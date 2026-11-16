import os
import re
import shutil
import socket
import offense.executor
import offense.catalog_author
from typing import TypedDict, List, Dict, Any, Literal
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from scope import load_scope, set_active_scope, ScopeError
from state.world_model import WorldModel, Credential, Session, inputs_fingerprint
from state import mission_io
from catalog import load_catalog, techniques_for, technique_by_id

load_dotenv()

# --- Mode verbose (diagnostic) --------------------------------------------- #
# Activable par la variable d'environnement PIRATECREW_VERBOSE (1/true/on/oui),
# ou à chaud via la commande « verbose » de l'invite interactive. Imprime des
# lignes de diagnostic sur la console uniquement (jamais dans audit.log) :
# hôtes énumérés, ports sondés, ports ouverts/services, tâches planifiées —
# de quoi comprendre un cycle qui ne planifie « 0 tâche ».
_VERBOSE = os.getenv("PIRATECREW_VERBOSE", "").strip().lower() in ("1", "true", "yes", "on", "oui")


def set_verbose(on: bool) -> None:
    """Active/désactive le mode verbose (diagnostic) du processus."""
    global _VERBOSE
    _VERBOSE = bool(on)


def is_verbose() -> bool:
    """État courant du mode verbose."""
    return _VERBOSE


# --- Mode propose-only ------------------------------------------------------ #
# Activable par PIRATECREW_PROPOSE_ONLY (1/true/on/oui) : les techniques
# rédigées par le LLM sont proposées/persistées mais JAMAIS exécutées.
_PROPOSE_ONLY = os.getenv("PIRATECREW_PROPOSE_ONLY", "").strip().lower() in ("1", "true", "yes", "on", "oui")


def set_propose_only(on: bool) -> None:
    """Active/désactive le mode propose-only du processus."""
    global _PROPOSE_ONLY
    _PROPOSE_ONLY = bool(on)


def is_propose_only() -> bool:
    """État courant du mode propose-only."""
    return _PROPOSE_ONLY


def _vprint(msg: str) -> None:
    """Imprime une ligne de diagnostic UNIQUEMENT si le mode verbose est actif."""
    if _VERBOSE:
        print(f"[VERBOSE] {msg}")


# Catalogue chargé une fois (lecture YAML légère, builtin + operator).
_CATALOG = load_catalog()

# --- REGISTRE DE MISSION ---------------------------------------------------- #
# Le WorldModel est tenu PAR RÉFÉRENCE ici, indexé par thread_id, et PAS
# sérialisé dans l'état LangGraph : un agent exécutant invoqué dans un nœud ne
# peut pas muter proprement l'état parent, donc on partage l'objet de mission
# via ce registre (cf. design §6.2). L'état LangGraph ne transporte qu'un handle.
_MISSIONS: Dict[str, WorldModel] = {}


def start_mission(thread_id: str, scope) -> WorldModel:
    """Crée le modèle du terrain d'une mission, ou renvoie celui déjà associé au
    thread_id dans ce processus (registre en mémoire). Projet 1 : une mission par
    exécution (mission_id unique) — il n'y a PAS de reprise automatique entre
    exécutions. Le périmètre fraîchement chargé est ré-appliqué dans tous les cas."""
    world = _MISSIONS.get(thread_id)
    if world is None:
        world = WorldModel(scope=scope)
        _MISSIONS[thread_id] = world
    else:
        world.scope = scope
    return world


def get_world(thread_id: str) -> WorldModel:
    """Récupère le modèle du terrain actif. Lève si aucune mission démarrée."""
    world = _MISSIONS.get(thread_id)
    if world is None:
        raise RuntimeError(
            f"Aucune mission active pour thread_id={thread_id!r} : appeler start_mission d'abord.")
    return world


def _pending_sessions(world: WorldModel) -> List[Session]:
    """Sessions vivantes obtenues mais pas encore autorisées par l'opérateur (gate)."""
    return [s for s in world.sessions if s.alive and not s.authorized]


def resume_with_authorization(prev_thread_id: str, host: str, target: str) -> str | None:
    """Autorise les sessions de `host` dans le monde de `prev_thread_id` et prépare la
    reprise : un nouveau thread_id pointe sur le MÊME objet WorldModel (registre, ledger
    et session autorisée conservés). Renvoie le nouveau thread_id, ou None s'il n'y a
    rien à autoriser. L'invoke LangGraph est fait par l'appelant (REPL)."""
    world = _MISSIONS.get(prev_thread_id)
    if world is None:
        return None
    if authorize_sessions(world, host) == 0:
        return None
    new_id = mission_io.new_mission_id(target)
    _MISSIONS[new_id] = world
    return new_id


# --- 1. ÉTAT GLOBAL DE LA MISSION & DES REQUÊTES ---------------------------- #
class MissionState(TypedDict, total=False):
    question: str
    target: str
    goal: str
    thread_id: str
    cycle: int
    max_cycles: int
    finished: bool
    recon_results: str
    discovered_services: List[str]
    rag_context: str
    planned: List[Dict[str, Any]]
    execution_reports: List[Dict[str, Any]]
    final_response: str
    mission_success: bool


llm = ChatAnthropic(model="claude-sonnet-4-6")

# Détection des services à partir de la sortie (texte libre) d'un agent de recon.
KNOWN_SERVICES = ["https", "http", "smb", "netbios", "ldap", "ftp", "ssh",
                  "rdp", "mysql", "smtp", "dns", "winrm"]
PORT_TO_SERVICE = {
    "21": "ftp", "22": "ssh", "25": "smtp", "53": "dns", "80": "http",
    "139": "netbios", "143": "smtp", "443": "https", "445": "smb",
    "3306": "mysql", "3389": "rdp", "5985": "winrm", "8080": "http",
}
# Ports sondés par défaut lors de la reconnaissance (source unique).
DEFAULT_RECON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                       1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8000,
                       8080, 8443, 8888, 9000, 9090]
_HOSTPORT_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:(\d{1,5})\b")
_PORTWORD_RE = re.compile(r"\bports?\s+(\d{1,5})\b", re.IGNORECASE)


def requested_ports(text: str) -> list[int]:
    """Ports explicitement nommés dans une requête (`ip:port`, `port N`).
    Bornés à 1..65535, dédoublonnés, triés."""
    found = set()
    for rx in (_HOSTPORT_RE, _PORTWORD_RE):
        for m in rx.finditer(text or ""):
            n = int(m.group(1))
            if 1 <= n <= 65535:
                found.add(n)
    return sorted(found)


# Intention de balayage de la PLAGE COMPLÈTE (1-65535).
_FULL_SCAN_RE = re.compile(
    r"(tous?\s+les?\s+ports|all\s+ports|full[-\s]?port|scan\s+complet|"
    r"balayage\s+complet|plage\s+compl[eè]te|-p-|1-65535)",
    re.IGNORECASE,
)


def wants_full_scan(text: str) -> bool:
    """Vrai si la requête demande un balayage de la plage COMPLÈTE 1-65535
    (« tous les ports », « scan complet », « all ports », « -p- »)."""
    return bool(_FULL_SCAN_RE.search(text or ""))


# Domaine d'outils à déployer selon le service découvert.
SERVICE_DOMAIN = {
    "http": "web", "https": "web",
    "smb": "ad", "netbios": "ad", "ldap": "ad",
}

# Outils Python toujours présents (pas de binaire externe). Toute technique dont
# le `tool` n'est PAS ici est considérée comme dépendante d'un binaire externe,
# vérifié via shutil.which (cf. technique_available / escalade « outil manquant »).
PYTHON_TOOLS = {
    "tcp_port_check", "http_fingerprint", "http_get", "http_get_listing", "smb_port_probe",
    "scope_check", "log_audit_event", "report_finding",
}


def technique_available(tech) -> bool:
    """Vrai si la technique peut s'exécuter ici : outil Python intégré, aucun
    outil requis, ou binaire externe présent dans le PATH. Déterministe (sans LLM)."""
    tool = (getattr(tech, "tool", "") or "").strip()
    if not tool or tool in PYTHON_TOOLS:
        return True
    return shutil.which(tool) is not None


def _split_principal(principal: str) -> tuple:
    """Découpe un principal en (domaine, utilisateur) : `CORP\\user`,
    `user@corp.local` ou `user` (domaine vide)."""
    if "\\" in principal:
        domain, _, user = principal.partition("\\")
        return domain, user
    if "@" in principal:
        user, _, domain = principal.partition("@")
        return domain, user
    return "", principal


def _render_template(template: str, host: str, port: int = 0,
                     creds: list | None = None, context: dict | None = None) -> str:
    """Rend un gabarit de commande avec {target}/{port} et, si `creds` est non
    vide, {user}/{domain}/{hash}/{password}/{secret} (depuis creds[0]) ;
    {share} vient de `context`. Un placeholder inconnu renvoie le gabarit brut,
    sans lever."""
    if not template:
        return ""
    subs: Dict[str, Any] = {"target": host, "port": port}
    if creds:
        domain, user = _split_principal(creds[0].principal)
        subs.update(user=user, domain=domain, hash=creds[0].secret,
                    password=creds[0].secret, secret=creds[0].secret)
    if context and "share" in context:
        subs["share"] = context["share"]
    try:
        return template.format(**subs)
    except (KeyError, IndexError, ValueError):
        return template


# Marqueurs qui DISQUALIFIENT une ligne « open » (port testé mais pas ouvert).
_NEG_MARKERS = ("closed", "filtered", "none open", "no open", "0 open",
                "not open", "aucun", "fermé", "ferme")
_PORT_TOKEN_RE = re.compile(r"\d+")


def _parse_services(text: str) -> List[str]:
    """Services OUVERTS extraits de la sortie libre d'un agent de recon.

    Repli best-effort (le canal primaire reste report_finding). Ne retient que
    les lignes signalant « open » sans marqueur de négation, et matche les ports
    par TOKEN et non en sous-chaîne : « built 2021 », « 255.255.255.0 » ou
    « … — none open » ne créent plus de service fantôme.
    """
    found = set()
    for raw_line in (text or "").splitlines():
        low = raw_line.lower()
        if "open" not in low or any(m in low for m in _NEG_MARKERS):
            continue
        tokens = set(_PORT_TOKEN_RE.findall(low))
        for port, svc in PORT_TO_SERVICE.items():
            if port in tokens:
                found.add(svc)
        for svc in KNOWN_SERVICES:
            if svc in low:
                found.add(svc)
    if "https" in found:
        found.add("http")
    return sorted(found)


# --- 2. SUPERVISEUR MAÎTRE (Le Routeur) ------------------------------------- #
def master_supervisor(state: MissionState) -> Literal["delegate_pirate", "delegate_analyst", "autonomous_mission", "general_response"]:
    print("\n[MASTER] Analyse de la requête par l'orchestrateur...")
    question = state.get("question", "")

    prompt = f"""Tu es l'orchestrateur maître de la plateforme de cybersécurité PirateCrew.
Analyse la demande de l'utilisateur et choisis la stratégie parmi ces quatre options exactes :
- "delegate_pirate" : si la requête concerne de la théorie, des cours, des protocoles Active Directory, des méthodologies ou de la documentation tactique (RAG).
- "delegate_analyst" : si la requête contient du code source, un script (Python, Bash, PowerShell), un PoC d'exploit ou demande une analyse de code.
- "autonomous_mission" : si la requête demande de lancer un scan complet, de trouver des vulnérabilités, d'auditer ou d'exploiter une cible/IP spécifique sur le réseau.
- "general_response" : si c'est une question générale, une salutation ou de l'administration sans lien technique direct.

Réponds uniquement par l'un de ces quatre mots exacts : "delegate_pirate", "delegate_analyst", "autonomous_mission" ou "general_response".

Requête : {question}
Choix :"""

    response = llm.invoke(prompt)
    decision = response.content.strip()

    if "autonomous_mission" in decision:
        print("[MASTER] Décision : Lancement d'une mission autonome (Recon / Decide / Execute / Integrate)")
        return "autonomous_mission"
    elif "delegate_analyst" in decision:
        print("[MASTER] Décision : Délégation au sous-agent d'analyse de code (AnalystAgent)")
        return "delegate_analyst"
    elif "delegate_pirate" in decision:
        print("[MASTER] Décision : Délégation au sous-agent RAG (PirateAgent)")
        return "delegate_pirate"
    else:
        print("[MASTER] Décision : Traitement direct par l'orchestrateur")
        return "general_response"


# --- 3. NŒUDS DE DÉLÉGATION CLASSIQUE --------------------------------------- #
def node_delegate_to_pirate(state: MissionState):
    # Import paresseux : charge le RAG (modèle d'embedding) seulement si utilisé.
    from agents.pirate_agent import pirate_graph_direct
    result = pirate_graph_direct.invoke({"question": state["question"]})
    return {"final_response": result.get("generation", "Erreur RAG.")}


def node_delegate_to_analyst(state: MissionState):
    from agents.analyst_agent import analyst_graph
    result = analyst_graph.invoke({"question": state["question"]})
    return {"final_response": result.get("analysis", "Erreur d'analyse de code.")}


def node_general_response(state: MissionState):
    prompt = f"Tu es PirateCrew, un assistant de cybersécurité. Réponds de façon concise : {state['question']}"
    resp = llm.invoke(prompt)
    return {"final_response": resp.content}


# --- Porte d'entrée de mission (scope fail-closed) -------------------------- #
def enter_autonomous_mission(state: MissionState, config):
    """Charge le périmètre (scope.txt), démarre la mission, affiche le périmètre.
    Fail-closed : scope.txt absent/vide ⇒ refus net, aucune recon lancée."""
    thread_id = ((config or {}).get("configurable", {}).get("thread_id")
                 or state.get("thread_id") or "session_pirate_master")
    try:
        scope = load_scope("scope.txt")
    except ScopeError as exc:
        set_active_scope(None)  # fail-closed : aucun périmètre périmé ne reste actif après un refus
        print(f"[SCOPE] Mission refusée : {exc}")
        return {"finished": True,
                "final_response": "Mission refusée : périmètre d'autorisation (scope.txt) absent ou vide."}
    set_active_scope(scope)
    start_mission(thread_id, scope)
    print(f"[SCOPE] Périmètre chargé : {len(scope.networks)} entrée(s). Mission {thread_id!r} démarrée.")
    return {"thread_id": thread_id, "cycle": 0, "max_cycles": state.get("max_cycles", 6),
            "finished": False}


def route_after_enter(state: MissionState) -> Literal["recon", "finish"]:
    return "finish" if state.get("finished") else "recon"


# --- 4. HELPERS DE MISSION (purs, testables sans LLM) ----------------------- #
def _requires_satisfied(world: WorldModel, host: str, service: str, requires: set) -> bool:
    """Vrai si le modèle du terrain satisfait les prérequis d'une technique."""
    for req in requires:
        if req == "credential" and not world.creds_applicable(service):
            return False
        if req == "session" and not any(
                s.host == host and s.alive and s.authorized for s in world.sessions):
            return False
    return True


def authorize_sessions(world: WorldModel, host: str) -> int:
    """Autorise les sessions vivantes de `host` pas encore autorisées ;
    renvoie le nombre de sessions modifiées."""
    n = 0
    for s in world.sessions:
        if s.host == host and s.alive and not s.authorized:
            s.authorized = True
            n += 1
    return n


def _task_inputs_fp(world: WorldModel, service: str, requires: set) -> str:
    """Empreinte des entrées retenues pour une technique (ex. le cred choisi).
    Permet au ledger de distinguer une tentative sans cred d'une tentative avec."""
    if "credential" in requires:
        creds = world.creds_applicable(service)
        if creds:
            # Empreinte sur TOUS les creds applicables (triés) : un nouveau cred
            # change l'empreinte et ré-ouvre la technique (R2), là où creds[0]
            # seul la figeait sur le premier cred à jamais.
            ids = sorted(f"{c.principal}:{c.secret}" for c in creds)
            return inputs_fingerprint({"cred": ",".join(ids)})
    return ""


def plan_tasks(world: WorldModel, catalog: list) -> List[Dict[str, Any]]:
    """Pour chaque (hôte in-scope, service), les techniques dont les prérequis
    sont satisfaits et qui ne sont pas déjà tentées avec les mêmes entrées."""
    tasks: List[Dict[str, Any]] = []
    for host in world.in_scope_hosts():
        for svc in host.services:
            service = svc.name
            if not service:
                continue
            for tech in techniques_for(catalog, service):
                if not _requires_satisfied(world, host.ip, service, tech.requires):
                    continue
                fp = _task_inputs_fp(world, service, tech.requires)
                if world.is_tried(host.ip, service, tech.id, fp, port=svc.port):
                    continue
                tasks.append({
                    "host": host.ip,
                    "service": service,
                    "technique_id": tech.id,
                    "domain": tech.domain,
                    "inputs_fp": fp,
                    "port": svc.port,
                })
    return tasks


# Motifs best-effort pour le rattrapage de trouvailles dans du texte brut (R1).
_CRED_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9._\\-]{1,63}):([^\s:/]{3,64})(?:\b|(?<=\W)(?=\s|$))")
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# Indice explicite de credential : un 'mot:valeur' n'est retenu que sur une ligne
# qui en porte un, sinon « Server:nginx » / « Host:10.0.0.1 » fabriquent de faux
# secrets qui débloqueraient à tort des techniques requires={credential}.
_CRED_CUE_RE = re.compile(
    r"\b(cred|creds|credential|credentials|password|passwd|pwd|login|logon|secret|hash|ntlm|kerb)\b",
    re.IGNORECASE,
)
# Noms d'en-têtes/étiquettes à ne JAMAIS prendre pour un principal de credential.
# La fenêtre d'indice (cue + 2 lignes) peut survoler un « Server:nginx » /
# « Host:10.0.0.1 » compact : ce sont de la prose structurée, pas des identifiants.
_NON_CRED_PRINCIPALS = {
    "server", "host", "date", "connection", "content", "content-type",
    "content-length", "content-encoding", "transfer-encoding", "location",
    "etag", "vary", "cache-control", "set-cookie", "cookie", "x-powered-by",
    "x-frame-options", "last-modified", "accept-ranges", "keep-alive",
    "www-authenticate", "user-agent", "referer", "via", "upgrade", "allow",
    "pragma", "expires", "strict-transport-security",
}


def reconcile_evidence(world: WorldModel, raw_text: str) -> int:
    """Back-stop (R1) : repère des credentials (principal:secret) et des hôtes
    (IPv4) évidents dans une sortie brute et les ajoute au modèle s'ils sont
    nouveaux. Renvoie le nombre d'éléments ajoutés. Jamais levant."""
    text = raw_text or ""
    added = 0
    # Credentials : uniquement depuis une LIGNE portant un indice explicite de
    # credential (anti-fabrication depuis de la prose « mot:valeur » anodine).
    # Fenêtre ancrée sur l'indice : la ligne du cue + les 2 suivantes (les
    # fichiers réels séparent souvent « Cred for DC : » de la valeur).
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not _CRED_CUE_RE.search(line):
            continue
        for window_line in lines[i:i + 3]:
            for m in _CRED_RE.finditer(window_line):
                principal, secret = m.group(1), m.group(2)
                if principal.lower() in _NON_CRED_PRINCIPALS:
                    continue
                before = len(world.credentials)
                world.add_credential(Credential(kind="password", principal=principal,
                                                secret=secret, source="evidence-reconcile"))
                if len(world.credentials) > before:
                    added += 1
    for m in _IPV4_RE.finditer(text):
        ip = m.group(1)
        if ip not in world.hosts:
            world.add_host(ip)
            added += 1
    return added


def discover_services(world, hosts, ports, probe, fingerprint=None, log=None, workers=1) -> int:
    """probe(host,port)->bool teste l'ouverture d'un port. Pour chaque port ouvert,
    enregistre un service via world.add_service. Nom du service: PORT_TO_SERVICE.get(str(port))
    si connu; sinon fingerprint(host,port)->str|None s'il est fourni (ex. 'http' pour un
    service web sur un port inhabituel); sinon ''. Renvoie le nombre de ports ouverts enregistrés.

    `log` (optionnel) : callable(str) appelé pour CHAQUE port ouvert (diagnostic verbose).
    `workers`>1 : sonde les (hôte,port) EN PARALLÈLE (threads, I/O-bound) ; l'enregistrement
    des services reste SÉQUENTIEL et déterministe (WorldModel non thread-safe)."""
    targets = [(host, port) for host in hosts for port in ports]
    if workers and workers > 1 and len(targets) > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=workers) as pool:
            flags = list(pool.map(lambda t: probe(t[0], t[1]), targets))  # map préserve l'ordre
        open_targets = [t for t, ok in zip(targets, flags) if ok]
    else:
        open_targets = [(host, port) for (host, port) in targets if probe(host, port)]
    count = 0
    for host, port in open_targets:
        name = PORT_TO_SERVICE.get(str(port))
        if not name and fingerprint is not None:
            name = fingerprint(host, port)
        world.add_service(host, port, name=name or "")
        if log:
            log(f"{host}:{port} ouvert → service '{name or '?'}'")
        count += 1
    return count


def autonomous_discovery(world, hosts, default_ports, probe, fingerprint=None, log=None,
                         default_workers=64, full_workers=256) -> int:
    """Découverte auto-escaladante : balayage des `default_ports`, puis, pour chaque hôte
    resté SANS service, balayage de la plage complète 1-65535 (plus lourd, plus de workers).
    Pas d'escalade si `default_ports` couvre déjà toute la plage (rien de plus à sonder).
    Renvoie le total de ports ouverts enregistrés."""
    n1 = discover_services(world, hosts, default_ports, probe, fingerprint, log,
                           workers=default_workers)
    empty = [h for h in hosts if h not in world.hosts or not world.hosts[h].services]
    if empty and len(default_ports) < 65535:
        n2 = discover_services(world, empty, list(range(1, 65536)), probe, fingerprint, log,
                               workers=full_workers)
    else:
        n2 = 0
    return n1 + n2


def _port_open(host: str, port: int, timeout: float = 3) -> bool:
    """Sonde TCP réelle : vrai si la connexion aboutit."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _http_name(host: str, port: int) -> str | None:
    """'http' si le port répond en HTTP (via l'outil http_fingerprint), sinon None."""
    from tools.registry import http_fingerprint
    out = http_fingerprint.invoke({"url": f"http://{host}:{port}/"})
    return "http" if "HTTP" in str(out) else None


# --- 5. NŒUDS DE LA MISSION AUTONOME (boucle à état) ------------------------ #
def node_recon(state: MissionState, config):
    from agents.dynamic_agent import build_task_agent
    thread_id = config["configurable"]["thread_id"]
    world = get_world(thread_id)
    target = state.get("target") or "127.0.0.1"
    print(f"\n[MISSION] Reconnaissance de {target} (cycle {state.get('cycle', 0)})...")
    # Découverte déterministe multi-hôtes / multi-ports (sans LLM), bornée au périmètre.
    hosts = world.scope.hosts(max_hosts=256)
    full = (wants_full_scan(state.get("question", "") or "")
            or wants_full_scan(state.get("target", "") or ""))
    if full:
        # Plage complète : sondage parallèle + timeout court (sinon des milliers de
        # ports filtrés feraient traîner le cycle jusqu'au bout des timeouts).
        ports = list(range(1, 65536))
        workers = 256
        ports_desc = "PLAGE COMPLÈTE 1-65535"
    else:
        ports = sorted(set(DEFAULT_RECON_PORTS)
                       | set(requested_ports(state.get("question", "") or ""))
                       | set(requested_ports(state.get("target", "") or "")))
        workers = 64
        ports_desc = ",".join(map(str, ports))
    _vprint(f"Périmètre : {len(hosts)} hôte(s) à sonder → {hosts[:10]}{' …' if len(hosts) > 10 else ''}")
    _vprint(f"Ports sondés ({len(ports)}, {workers} workers) : {ports_desc}")
    # Découverte auto-escaladante (plage complète si les ports par défaut sont vides).
    probe = lambda h, p: _port_open(h, p, timeout=1.0)  # noqa: E731
    autonomous_discovery(world, hosts, ports, probe, _http_name, log=_vprint,
                         default_workers=workers)
    _found = [f"{s.host}:{s.port}/{s.name or '?'}" for h in world.in_scope_hosts() for s in h.services]
    _vprint(f"Services in-scope après découverte ({len(_found)}) : {_found or 'AUCUN'}")
    ctx = (f"OBJECTIF: reconnaître {target}. Pour CHAQUE service ouvert, appelle "
           f"report_finding(kind='service', host='{target}', service=<nom>, port=<port>).")
    agent = build_task_agent("network", world, ctx)
    _ports_for_agent = ("la plage complète 1-65535" if full
                        else f"les ports courants ({','.join(map(str, ports))})")
    query = (f"Scanne la cible {target}. Utilise nmap_scan si disponible, sinon tcp_port_check "
             f"sur {_ports_for_agent}. "
             f"Remonte chaque service ouvert via report_finding.")
    try:
        result = agent.invoke({"messages": [("user", query)]})
        raw = result["messages"][-1].content
    except Exception as exc:  # noqa: BLE001
        raw = f"(erreur recon: {type(exc).__name__}: {exc})"
    world.add_evidence({"phase": "recon", "target": target, "raw": raw})
    # Repli : déduire des services du texte brut si l'agent n'a pas tout remonté.
    for svc in _parse_services(raw):
        port = next((int(p) for p, s in PORT_TO_SERVICE.items() if s == svc), 0)
        world.add_service(target, port, name=svc)
    services = sorted({s.name for h in world.in_scope_hosts() for s in h.services if s.name})
    return {"recon_results": raw, "discovered_services": services,
            "max_cycles": state.get("max_cycles", 6)}


def _dry_services(world: WorldModel, catalog, planned) -> List[str]:
    """Services in-scope « à sec » à confier à l'auteur LLM : nom non vide, absents
    des tâches planifiées, et sans technique OU dont toutes les techniques sont
    déjà tentées (vrai trou de catalogue, pas une attente de prérequis)."""
    planned_services = {t.get("service") for t in planned}
    out: List[str] = []
    for h in world.in_scope_hosts():
        for svc in h.services:
            name = svc.name
            if not name or name in planned_services or name in out:
                continue
            techs = techniques_for(catalog, name)
            if all(any(k[0] == h.ip and k[1] == name and k[2] == t.id and k[4] == svc.port
                       for k in world.technique_ledger) for t in techs):
                out.append(name)
    return out


def _already_authored(world: WorldModel, service: str) -> bool:
    """Vrai si l'auteur LLM a déjà rédigé une technique pour ce service (une fois par mission)."""
    return any(e.get("kind") == "llm_technique" and e.get("service") == service
               for e in world.evidence)


def node_decide(state: MissionState, config):
    thread_id = config["configurable"]["thread_id"]
    world = get_world(thread_id)
    tasks = plan_tasks(world, _CATALOG)
    if not tasks:
        authored = False
        for svc in _dry_services(world, _CATALOG, tasks):
            if _already_authored(world, svc):
                continue
            tech = offense.catalog_author.author_technique(
                svc, f"Service {svc} découvert, aucune technique applicable au catalogue.",
                lambda p: llm.invoke(p).content)
            if tech:
                _CATALOG.append(tech)
                try:
                    offense.catalog_author.persist_llm_technique(tech, thread_id)
                except Exception as exc:  # noqa: BLE001 - best-effort
                    _vprint(f"Persistance technique LLM échouée : {type(exc).__name__}")
                world.add_evidence({"kind": "llm_technique", "service": svc, "id": tech.id})
                authored = True
        if authored:
            tasks = plan_tasks(world, _CATALOG)
    _vprint("Tâches planifiées : " + str(
        [f"{t['host']}:{t['port']}/{t['service']}→{t['technique_id']}" for t in tasks] or "aucune"))
    services = state.get("discovered_services", [])
    rag = ""
    if services:
        try:
            from agents.pirate_agent import vectorstore
            docs = vectorstore.similarity_search(
                "Techniques d'attaque et d'énumération autorisée pour : " + ", ".join(services), k=3)
            rag = "\n\n---\n\n".join(d.page_content for d in docs)
        except Exception as exc:  # noqa: BLE001
            rag = f"(RAG indisponible : {type(exc).__name__})"
    print(f"[MISSION] Décision : {len(tasks)} tâche(s) planifiée(s) pour ce cycle.")
    return {"planned": tasks, "rag_context": rag}


def node_execute(state: MissionState, config):
    thread_id = config["configurable"]["thread_id"]
    world = get_world(thread_id)
    reports: List[Dict[str, Any]] = []
    for task in state.get("planned", []):
        tech = technique_by_id(_CATALOG, task["technique_id"])
        port = int(task.get("port", 0) or 0)
        inputs_fp = task.get("inputs_fp", "")
        # Escalade « outil manquant » (Option Y) : outil requis absent ⇒ on
        # n'exécute pas, on signale, et on NE marque PAS la technique (elle reste
        # replanifiable après installation de l'outil + relance de la mission).
        if not technique_available(tech):
            msg = f"Outil requis absent : {tech.tool}"
            world.add_evidence({"kind": "tool_request", "tool": tech.tool,
                                "technique": tech.id, "host": task["host"]})
            reports.append({"technique": tech.id, "host": task["host"],
                            "service": task["service"], "port": port, "inputs_fp": inputs_fp,
                            "status": "blocked_missing_tool", "tool": tech.tool, "detail": msg})
            continue
        # Chemin offensif DÉTERMINISTE (operator/llm) : rendu + exécuteur gardé,
        # jamais via l'agent LLM. Les techniques builtin gardent le chemin agent.
        if tech.provided_by in ("operator", "llm"):
            if is_propose_only() and tech.provided_by == "llm":
                reports.append({"technique": tech.id, "host": task["host"],
                                "service": task["service"], "port": port, "inputs_fp": inputs_fp,
                                "status": "proposed_awaiting_operator",
                                "detail": "Technique LLM proposée, en attente de validation opérateur."})
                continue
            creds = world.creds_applicable(task["service"])
            rendered = _render_template(tech.command_template, task["host"], port, creds=creds)
            status, raw = offense.executor.execute_command(rendered, timeout=120)
            world.add_evidence({"phase": "execute", "technique": tech.id, "host": task["host"],
                                "raw": raw, "rendered": rendered})
            if status == "done":
                reconcile_evidence(world, raw)
                if tech.opens_session and tech.success_signal and tech.success_signal in raw:
                    world.add_session(Session(host=task["host"], channel=(tech.tool or tech.id),
                                              via_cred=(creds[0].principal if creds else None),
                                              authorized=False))
            reports.append({"technique": tech.id, "host": task["host"], "service": task["service"],
                            "port": port, "inputs_fp": inputs_fp, "status": status, "detail": raw})
            continue
        from agents.dynamic_agent import build_task_agent
        domain = SERVICE_DOMAIN.get(task["service"], tech.domain or "network")
        creds = world.creds_applicable(task["service"])
        rendered = _render_template(tech.command_template, task["host"], port)
        ctx = (f"OBJECTIF: exécuter la technique '{tech.id}' ({tech.name}) sur "
               f"{task['host']}:{port} / service {task['service']}, DANS le périmètre. "
               f"Outil attendu: {tech.tool or '(outils fournis)'}. "
               f"Commande: {rendered or '(aucun gabarit — utilise les outils fournis)'}. "
               f"Signal de succès: {tech.success_signal or '(aucun)'}. "
               f"CREDS applicables: {[c.principal for c in creds] or 'aucun'}. "
               f"RAG: {(state.get('rag_context') or '')[:800]}. "
               f"Remonte toute trouvaille via report_finding.")
        agent = build_task_agent(domain, world, ctx)
        query = (f"Exécute la technique {tech.id} sur {task['host']}:{port} ({task['service']}). "
                 + (f"Commande: {rendered}" if rendered else ""))
        try:
            result = agent.invoke({"messages": [("user", query)]})
            raw = result["messages"][-1].content
            status = "done"
        except Exception as exc:  # noqa: BLE001
            raw = f"{type(exc).__name__}: {exc}"
            status = "error"
        world.add_evidence({"phase": "execute", "technique": tech.id, "host": task["host"], "raw": raw})
        reports.append({"technique": tech.id, "host": task["host"], "service": task["service"],
                        "port": port, "inputs_fp": inputs_fp, "status": status, "detail": raw})
    return {"execution_reports": reports}


def node_integrate(state: MissionState, config):
    thread_id = config["configurable"]["thread_id"]
    world = get_world(thread_id)
    reports = state.get("execution_reports", [])
    # Ne marque « tentée » que ce qui a tourné (done/error) ou été bloqué par un garde-fou
    # (évite le re-spin). Une
    # technique bloquée par un outil manquant n'est pas grillée : elle reste
    # replanifiable après installation + relance (Option Y). Clé par (entrées, port).
    for report in reports:
        if report.get("status") in ("done", "error", "blocked_destructive",
                                    "blocked_out_of_scope", "blocked_shell_meta"):
            world.mark_technique(report["host"], report["service"], report["technique"],
                                 report.get("inputs_fp", ""), status="tried",
                                 port=int(report.get("port", 0) or 0))
    # Back-stop R1 : récupère creds/hosts dans les sorties brutes.
    added = 0
    for report in reports:
        added += reconcile_evidence(world, report.get("detail", ""))
    cycle = state.get("cycle", 0) + 1
    summary = (f"Mission (cycle {cycle}) : {len(world.in_scope_hosts())} hôte(s) in-scope, "
               f"{len(world.credentials)} credential(s), {len(world.sessions)} session(s), "
               f"{len(world.loot)} butin(s). +{added} trouvaille(s) récupérée(s) du texte brut ce cycle.")
    # Escalade « outil manquant » (Option Y) : liste les binaires à installer.
    missing = sorted({r.get("tool", "") for r in reports
                      if r.get("status") == "blocked_missing_tool" and r.get("tool")})
    if missing:
        hints = " ; ".join(f"{t} (`sudo apt install -y {t}`)" for t in missing)
        summary += ("\n⚠ Techniques en attente d'un outil absent : " + hints +
                    ". Installe-le(s) dans l'environnement (Kali) puis relance la même mission pour les débloquer.")
    print(f"[MISSION] Intégration : {summary}")
    # Persistance à chaque cycle : les trouvailles survivent à un crash/interruption.
    try:
        mission_io.save_world(world, thread_id)
    except Exception as e:  # persistance au mieux : ne jamais interrompre la mission
        print(f"[MISSION] avertissement: persistance échouée ({type(e).__name__})")
    return {"cycle": cycle, "final_response": summary}


def route_after_integrate(state: MissionState) -> Literal["continue", "finish"]:
    """Continue tant qu'il reste des tâches planifiables sur un hôte in-scope et
    que le cap de cycles n'est pas atteint ; sinon termine (épuisement/cap)."""
    if state.get("cycle", 0) >= state.get("max_cycles", 6):
        print("\n[MISSION] Cap de cycles atteint — fin.")
        return "finish"
    if state.get("finished"):
        return "finish"
    thread_id = state.get("thread_id")
    world = _MISSIONS.get(thread_id) if thread_id else None
    if world is not None:
        # On ne continue QUE s'il reste une tâche réellement EXÉCUTABLE. Les tâches
        # bloquées par un outil absent sont signalées mais ne font pas tourner la
        # boucle à vide jusqu'au cap de cycles (cf. escalade Option Y).
        runnable = [t for t in plan_tasks(world, _CATALOG)
                    if technique_available(technique_by_id(_CATALOG, t["technique_id"]))]
        if not runnable:
            print("\n[MISSION] Épuisement : plus aucune tâche exécutable in-scope — fin.")
            return "finish"
    return "continue"


# --- 6. CONSTRUCTION DU GRAPHE MAÎTRE --------------------------------------- #
master_workflow = StateGraph(MissionState)

master_workflow.add_node("delegate_pirate", node_delegate_to_pirate)
master_workflow.add_node("delegate_analyst", node_delegate_to_analyst)
master_workflow.add_node("general_response", node_general_response)

master_workflow.add_node("recon", node_recon)
master_workflow.add_node("decide", node_decide)
master_workflow.add_node("execute", node_execute)
master_workflow.add_node("integrate", node_integrate)
master_workflow.add_node("enter", enter_autonomous_mission)

master_workflow.add_conditional_edges(
    START,
    master_supervisor,
    {
        "delegate_pirate": "delegate_pirate",
        "delegate_analyst": "delegate_analyst",
        "autonomous_mission": "enter",
        "general_response": "general_response",
    },
)

# Porte de mission : enter → recon (périmètre OK) ou END (refus fail-closed).
master_workflow.add_conditional_edges(
    "enter",
    route_after_enter,
    {"recon": "recon", "finish": END},
)

# Boucle de la mission autonome : recon (une fois) → decide → execute → integrate → route.
master_workflow.add_edge("recon", "decide")
master_workflow.add_edge("decide", "execute")
master_workflow.add_edge("execute", "integrate")
master_workflow.add_conditional_edges(
    "integrate",
    route_after_integrate,
    {"continue": "decide", "finish": END},
)

master_workflow.add_edge("delegate_pirate", END)
master_workflow.add_edge("delegate_analyst", END)
master_workflow.add_edge("general_response", END)

memory = MemorySaver()
master_orchestrator = master_workflow.compile(checkpointer=memory)


# --- 7. INTERFACE CLI INTERACTIVE ------------------------------------------- #
if __name__ == "__main__":
    print("==================================================")
    print(" 🏴‍☠️  PirateCrew - Orchestrateur à état 🏴‍☠️ ")
    print("==================================================")
    print("Tapez 'exit' ou 'quit' pour quitter.\n")

    # Périmètre d'autorisation : fail-closed (scope.txt obligatoire pour une mission).
    # Le chargement + la porte de mission détaillée sont finalisés en Task 7.
    # Affichage informatif du périmètre au démarrage. La porte de mission
    # (enter_autonomous_mission) le (re)charge et l'applique, fail-closed.
    try:
        _scope0 = load_scope("scope.txt")
        print(f"[SCOPE] scope.txt : {len(_scope0.networks)} entrée(s). Missions autonomes autorisées dans ce périmètre.")
    except ScopeError as exc:
        print(f"[SCOPE] scope.txt absent/vide ({exc}). Les missions autonomes seront refusées.")

    if is_verbose():
        print("[VERBOSE] mode activé (PIRATECREW_VERBOSE). Tapez « verbose » pour basculer.")
    else:
        print("Astuce : tapez « verbose » pour activer les diagnostics détaillés (ports/services/tâches).")

    _last_mission_id, _last_target = None, None

    while True:
        try:
            user_input = input("\nVous > ")
            if user_input.lower() in ["exit", "quit"]:
                print("Fermeture de PirateCrew.")
                break
            if not user_input.strip():
                continue

            # Bascule du mode verbose (diagnostic) : « verbose », « verbose on/off ».
            _parts = user_input.strip().lower().split()
            if _parts[0] == "verbose":
                if len(_parts) == 1:
                    set_verbose(not is_verbose())
                else:
                    set_verbose(_parts[1] in ("on", "1", "true", "yes", "oui"))
                print(f"[VERBOSE] mode {'activé' if is_verbose() else 'désactivé'}.")
                continue

            # Propose-only (auteur LLM : propose sans exécuter) : « propose-only [on|off] ».
            if _parts[0] == "propose-only":
                if len(_parts) == 1:
                    set_propose_only(not is_propose_only())
                else:
                    set_propose_only(_parts[1] in ("on", "1", "true", "yes", "oui"))
                print(f"[PROPOSE-ONLY] mode {'activé' if is_propose_only() else 'désactivé'}.")
                continue

            # Liste des sessions de la dernière mission.
            if _parts[0] == "sessions":
                _w = _MISSIONS.get(_last_mission_id) if _last_mission_id else None
                if _w is None or not _w.sessions:
                    print("[SESSIONS] aucune session.")
                else:
                    for _s in _w.sessions:
                        _etat = "autorisée" if _s.authorized else "en attente"
                        print(f"[SESSIONS] {_s.host} / {_s.channel} — {_etat}")
                continue

            # Cible = première IP mentionnée dans la requête, sinon 127.0.0.1.
            _ipm = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", user_input)

            if _parts[0] == "authorize":
                if not _ipm:
                    print("[AUTHORIZE] usage : authorize <hôte (IPv4)>")
                    continue
                _host = _ipm.group(0)
                new_id = (resume_with_authorization(_last_mission_id, _host, _last_target)
                          if _last_mission_id else None)
                if not new_id:
                    print(f"[AUTHORIZE] aucune session en attente à autoriser pour {_host}.")
                    continue
                print(f"[AUTHORIZE] session(s) de {_host} autorisée(s) — reprise de la mission.")
                _question = f"Lance la reprise post-exploitation de {_host} (audit/exploitation de la cible)"
                mission_id, target = new_id, _last_target
                user_input = _question
            else:
                target = _ipm.group(0) if _ipm else "127.0.0.1"
                # Identité de mission : un mission_id par exécution = thread_id.
                mission_id = mission_io.new_mission_id(target)
            _last_mission_id, _last_target = mission_id, target
            config = {"configurable": {"thread_id": mission_id}}

            initial_state = {
                "question": user_input,
                "target": target,
                "goal": user_input,
                "thread_id": mission_id,
                "cycle": 0,
                "max_cycles": 6,
                "discovered_services": [],
                "rag_context": "",
                "planned": [],
                "execution_reports": [],
                "final_response": "",
            }

            result = {}
            try:
                result = master_orchestrator.invoke(initial_state, config=config)
            finally:
                # Garantit world.json + rapport même sur Ctrl-C / exception.
                w = _MISSIONS.get(mission_id)
                if w is not None:
                    # Persistance au mieux : un échec ne masque jamais l'exception d'origine.
                    try:
                        mission_io.save_world(w, mission_id)
                    except Exception as exc:
                        print(f"[MISSION] avertissement: persistance échouée ({type(exc).__name__})")
                    try:
                        report_path = mission_io.save_report(w, mission_id)
                        print(f"\n[MISSION] Rapport : {report_path}")
                    except Exception as exc:
                        print(f"[MISSION] avertissement: persistance échouée ({type(exc).__name__})")
            print(f"\nPirateCrew >\n{result.get('final_response', 'Aucune réponse générée.')}")
            # Gate session : remonte les sessions obtenues mais non autorisées.
            _w = _MISSIONS.get(mission_id)
            _pend = _pending_sessions(_w) if _w is not None else []
            if _pend:
                _liste = ", ".join(f"{s.host}/{s.channel}" for s in _pend)
                print(f"⏸ Session(s) en attente d'autorisation : {_liste} — "
                      f"tapez « authorize <hôte> » pour lancer la post-exploitation.")
        except KeyboardInterrupt:
            print("\nInterruption. Sortie.")
            break
