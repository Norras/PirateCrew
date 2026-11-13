import os
import re
from typing import TypedDict, List, Dict, Any, Literal
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from scope import load_scope, set_active_scope, ScopeError
from state.world_model import WorldModel, Credential, inputs_fingerprint
from catalog import load_catalog, techniques_for, technique_by_id

load_dotenv()

# Catalogue chargé une fois (lecture YAML légère, builtin + operator).
_CATALOG = load_catalog()

# --- REGISTRE DE MISSION ---------------------------------------------------- #
# Le WorldModel est tenu PAR RÉFÉRENCE ici, indexé par thread_id, et PAS
# sérialisé dans l'état LangGraph : un agent exécutant invoqué dans un nœud ne
# peut pas muter proprement l'état parent, donc on partage l'objet de mission
# via ce registre (cf. design §6.2). L'état LangGraph ne transporte qu'un handle.
_MISSIONS: Dict[str, WorldModel] = {}


def start_mission(thread_id: str, scope) -> WorldModel:
    """Crée (ou recrée) le modèle du terrain d'une mission et l'enregistre."""
    world = WorldModel(scope=scope)
    _MISSIONS[thread_id] = world
    return world


def get_world(thread_id: str) -> WorldModel:
    """Récupère le modèle du terrain actif. Lève si aucune mission démarrée."""
    world = _MISSIONS.get(thread_id)
    if world is None:
        raise RuntimeError(
            f"Aucune mission active pour thread_id={thread_id!r} : appeler start_mission d'abord.")
    return world


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
# Domaine d'outils à déployer selon le service découvert.
SERVICE_DOMAIN = {
    "http": "web", "https": "web",
    "smb": "ad", "netbios": "ad", "ldap": "ad",
}


def _parse_services(text: str) -> List[str]:
    """Extrait les services détectés depuis la sortie libre d'un agent de recon."""
    low = (text or "").lower()
    found = set()
    for svc in KNOWN_SERVICES:
        if svc in low:
            found.add(svc)
    for port, svc in PORT_TO_SERVICE.items():
        if port in low:
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
        if req == "session" and not any(s.host == host and s.alive for s in world.sessions):
            return False
    return True


def _task_inputs_fp(world: WorldModel, service: str, requires: set) -> str:
    """Empreinte des entrées retenues pour une technique (ex. le cred choisi).
    Permet au ledger de distinguer une tentative sans cred d'une tentative avec."""
    if "credential" in requires:
        creds = world.creds_applicable(service)
        if creds:
            c = creds[0]
            return inputs_fingerprint({"cred": f"{c.principal}:{c.secret}"})
    return ""


def plan_tasks(world: WorldModel, catalog: list) -> List[Dict[str, Any]]:
    """Pour chaque (hôte in-scope, service), les techniques dont les prérequis
    sont satisfaits et qui ne sont pas déjà tentées avec les mêmes entrées."""
    tasks: List[Dict[str, Any]] = []
    for host in world.in_scope_hosts():
        services = sorted({svc.name for svc in host.services if svc.name})
        for service in services:
            for tech in techniques_for(catalog, service):
                if not _requires_satisfied(world, host.ip, service, tech.requires):
                    continue
                fp = _task_inputs_fp(world, service, tech.requires)
                if world.is_tried(host.ip, service, tech.id, fp):
                    continue
                tasks.append({
                    "host": host.ip,
                    "service": service,
                    "technique_id": tech.id,
                    "domain": tech.domain,
                    "inputs_fp": fp,
                })
    return tasks


# Motifs best-effort pour le rattrapage de trouvailles dans du texte brut (R1).
_CRED_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9._\\-]{1,63}):([^\s:/]{3,64})\b")
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def reconcile_evidence(world: WorldModel, raw_text: str) -> int:
    """Back-stop (R1) : repère des credentials (principal:secret) et des hôtes
    (IPv4) évidents dans une sortie brute et les ajoute au modèle s'ils sont
    nouveaux. Renvoie le nombre d'éléments ajoutés. Jamais levant."""
    text = raw_text or ""
    added = 0
    for m in _CRED_RE.finditer(text):
        principal, secret = m.group(1), m.group(2)
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


# --- 5. NŒUDS DE LA MISSION AUTONOME (boucle à état) ------------------------ #
def node_recon(state: MissionState, config):
    from agents.dynamic_agent import build_task_agent
    thread_id = config["configurable"]["thread_id"]
    world = get_world(thread_id)
    target = state.get("target") or "127.0.0.1"
    print(f"\n[MISSION] Reconnaissance de {target} (cycle {state.get('cycle', 0)})...")
    ctx = (f"OBJECTIF: reconnaître {target}. Pour CHAQUE service ouvert, appelle "
           f"report_finding(kind='service', host='{target}', service=<nom>, port=<port>).")
    agent = build_task_agent("network", world, ctx)
    query = (f"Scanne la cible {target}. Utilise nmap_scan si disponible, sinon tcp_port_check "
             f"sur les ports courants (21,22,80,443,139,445,3389,8080). "
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


def node_decide(state: MissionState, config):
    thread_id = config["configurable"]["thread_id"]
    world = get_world(thread_id)
    tasks = plan_tasks(world, _CATALOG)
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
    from agents.dynamic_agent import build_task_agent
    thread_id = config["configurable"]["thread_id"]
    world = get_world(thread_id)
    reports: List[Dict[str, Any]] = []
    for task in state.get("planned", []):
        tech = technique_by_id(_CATALOG, task["technique_id"])
        domain = SERVICE_DOMAIN.get(task["service"], tech.domain or "network")
        creds = world.creds_applicable(task["service"])
        ctx = (f"OBJECTIF: exécuter la technique '{tech.id}' ({tech.name}) sur "
               f"{task['host']} / service {task['service']}, DANS le périmètre. "
               f"Outil attendu: {tech.tool or '(outils fournis)'}. "
               f"Gabarit: {tech.command_template or '(aucun gabarit — utilise les outils fournis)'}. "
               f"Signal de succès: {tech.success_signal or '(aucun)'}. "
               f"CREDS applicables: {[c.principal for c in creds] or 'aucun'}. "
               f"RAG: {(state.get('rag_context') or '')[:800]}. "
               f"Remonte toute trouvaille via report_finding.")
        agent = build_task_agent(domain, world, ctx)
        query = (f"Exécute la technique {tech.id} sur {task['host']} ({task['service']}). "
                 + (f"Gabarit de commande: {tech.command_template}" if tech.command_template else ""))
        try:
            result = agent.invoke({"messages": [("user", query)]})
            raw = result["messages"][-1].content
            status = "done"
        except Exception as exc:  # noqa: BLE001
            raw = f"{type(exc).__name__}: {exc}"
            status = "error"
        world.add_evidence({"phase": "execute", "technique": tech.id, "host": task["host"], "raw": raw})
        reports.append({"technique": tech.id, "host": task["host"], "service": task["service"],
                        "status": status, "detail": raw})
    return {"execution_reports": reports}


def node_integrate(state: MissionState, config):
    thread_id = config["configurable"]["thread_id"]
    world = get_world(thread_id)
    # Marque les techniques tentées ce cycle (clé par entrées, cf. R2).
    for task in state.get("planned", []):
        world.mark_technique(task["host"], task["service"], task["technique_id"],
                             task.get("inputs_fp", ""), status="tried")
    # Back-stop R1 : récupère creds/hosts dans les sorties brutes.
    added = 0
    for report in state.get("execution_reports", []):
        added += reconcile_evidence(world, report.get("detail", ""))
    cycle = state.get("cycle", 0) + 1
    summary = (f"Mission (cycle {cycle}) : {len(world.in_scope_hosts())} hôte(s) in-scope, "
               f"{len(world.credentials)} credential(s), {len(world.sessions)} session(s), "
               f"{len(world.loot)} butin(s). +{added} trouvaille(s) récupérée(s) du texte brut ce cycle.")
    print(f"[MISSION] Intégration : {summary}")
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
    if world is not None and not plan_tasks(world, _CATALOG):
        print("\n[MISSION] Épuisement : plus aucune tâche planifiable in-scope — fin.")
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

    config = {"configurable": {"thread_id": "session_pirate_master"}}

    while True:
        try:
            user_input = input("\nVous > ")
            if user_input.lower() in ["exit", "quit"]:
                print("Fermeture de PirateCrew.")
                break
            if not user_input.strip():
                continue

            # Cible = première IP mentionnée dans la requête, sinon 127.0.0.1.
            _ipm = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", user_input)
            target = _ipm.group(0) if _ipm else "127.0.0.1"

            initial_state = {
                "question": user_input,
                "target": target,
                "goal": user_input,
                "thread_id": "session_pirate_master",
                "cycle": 0,
                "max_cycles": 6,
                "discovered_services": [],
                "rag_context": "",
                "planned": [],
                "execution_reports": [],
                "final_response": "",
            }

            result = master_orchestrator.invoke(initial_state, config=config)
            print(f"\nPirateCrew >\n{result.get('final_response', 'Aucune réponse générée.')}")
        except KeyboardInterrupt:
            print("\nInterruption. Sortie.")
            break
