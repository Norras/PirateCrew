import os
import re
import shutil
import socket
import offense.executor
import offense.netns
import offense.catalog_author
from typing import TypedDict, List, Dict, Any, Literal
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from scope import load_scope, set_active_scope, ScopeError, _audit as _audit_event
from state.world_model import WorldModel, Credential, Session, inputs_fingerprint
from state import mission_io
from catalog import load_catalog, techniques_for, technique_by_id

load_dotenv()

# --- Verbose mode (diagnostics) --------------------------------------------- #
# Enabled through the PIRATECREW_VERBOSE environment variable (1/true/on/oui),
# or on the fly with the "verbose" command of the interactive prompt. Prints
# diagnostic lines to the console only (never to audit.log):
# enumerated hosts, probed ports, open ports/services, planned tasks —
# enough to understand a cycle that plans "0 tasks".
_VERBOSE = os.getenv("PIRATECREW_VERBOSE", "").strip().lower() in ("1", "true", "yes", "on", "oui")


def set_verbose(on: bool) -> None:
    """Enable/disable the process-wide verbose (diagnostic) mode."""
    global _VERBOSE
    _VERBOSE = bool(on)


def is_verbose() -> bool:
    """Current state of verbose mode."""
    return _VERBOSE


# --- Propose-only mode ------------------------------------------------------ #
# Enabled through PIRATECREW_PROPOSE_ONLY (1/true/on/oui): techniques
# authored by the LLM are proposed/persisted but NEVER executed.
_PROPOSE_ONLY = os.getenv("PIRATECREW_PROPOSE_ONLY", "").strip().lower() in ("1", "true", "yes", "on", "oui")


def set_propose_only(on: bool) -> None:
    """Enable/disable the process-wide propose-only mode."""
    global _PROPOSE_ONLY
    _PROPOSE_ONLY = bool(on)


def is_propose_only() -> bool:
    """Current state of propose-only mode."""
    return _PROPOSE_ONLY


def _vprint(msg: str) -> None:
    """Print a diagnostic line ONLY if verbose mode is on."""
    if _VERBOSE:
        print(f"[VERBOSE] {msg}")


# Catalog loaded once (lightweight YAML read, builtin + operator).
_CATALOG = load_catalog()
# Per-mission overlay (keyed by thread_id): techniques authored by the LLM, isolated
# between missions of the same process (the REPL chains several of them).
_MISSION_CATALOG: Dict[str, list] = {}


def _effective_catalog(thread_id: str) -> list:
    """Base catalog + the LLM techniques specific to this mission."""
    return _CATALOG + _MISSION_CATALOG.get(thread_id, [])

# --- MISSION REGISTRY ------------------------------------------------------- #
# The WorldModel is held BY REFERENCE here, indexed by thread_id, and NOT
# serialized in the LangGraph state: an executing agent invoked inside a node
# cannot cleanly mutate the parent state, so the mission object is shared
# through this registry (see design §6.2). The LangGraph state only carries a handle.
_MISSIONS: Dict[str, WorldModel] = {}


def start_mission(thread_id: str, scope) -> WorldModel:
    """Create a mission's world model, or return the one already associated with
    thread_id in this process (in-memory registry). Project 1: one mission per
    run (unique mission_id) — there is NO automatic resume between
    runs. The freshly loaded scope is re-applied in every case."""
    world = _MISSIONS.get(thread_id)
    if world is None:
        world = WorldModel(scope=scope)
        _MISSIONS[thread_id] = world
    else:
        world.scope = scope
    return world


def get_world(thread_id: str) -> WorldModel:
    """Return the active world model. Raises if no mission has been started."""
    world = _MISSIONS.get(thread_id)
    if world is None:
        raise RuntimeError(
            f"No active mission for thread_id={thread_id!r}: call start_mission first.")
    return world


def _pending_sessions(world: WorldModel) -> List[Session]:
    """Live sessions obtained but not yet authorized by the operator (gate)."""
    return [s for s in world.sessions if s.alive and not s.authorized]


def resume_with_authorization(prev_thread_id: str, host: str, target: str) -> str | None:
    """Authorize the sessions of `host` in the world of `prev_thread_id` and prepare
    the resume: a new thread_id points to the SAME WorldModel object (registry, ledger
    and authorized session kept). Returns the new thread_id, or None if there is
    nothing to authorize. The LangGraph invoke is done by the caller (REPL)."""
    world = _MISSIONS.get(prev_thread_id)
    if world is None:
        return None
    if authorize_sessions(world, host) == 0:
        return None
    new_id = mission_io.new_mission_id(target)
    _MISSIONS[new_id] = world
    # The LLM technique overlay follows the world: without it, the technique the
    # operator just authorized would no longer be plannable (the author does not
    # rewrite it, it is already in the mission evidence).
    if prev_thread_id in _MISSION_CATALOG:
        _MISSION_CATALOG[new_id] = _MISSION_CATALOG[prev_thread_id]
    return new_id


def _last_mission_after(prev: tuple, mission_id: str, target: str) -> tuple:
    """(id, target) of the last MISSION after a REPL turn. A turn with no mission
    world (question, RAG, code analysis) does not replace the previous one:
    "authorize" and "sessions" must keep targeting its pending sessions."""
    return (mission_id, target) if mission_id in _MISSIONS else prev


# Pending RAG promotion: candidate texts from the last mission, written to
# the shared RAG ONLY on the operator's order ("promote" command).
_PENDING_PROMOTION: List[dict] = []


def queue_promotion(thread_id: str) -> List[str]:
    """Prepare the RAG promotion of the mission's LLM techniques WITHOUT writing anything.

    Returns the texts that would be stored, for operator review;
    `promote_pending` then writes them. The automatic filter (secrets, principals,
    host names known to the WorldModel, IPs, high-entropy tokens) is only a
    pre-screen: it does not recognize every piece of target data, hence the explicit approval."""
    world = _MISSIONS.get(thread_id)
    forbidden: List[str] = []
    if world is not None:
        for c in world.credentials:
            forbidden += [v for v in (c.secret, c.principal) if v]
        for h in world.hosts.values():
            if h.hostname:
                name = h.hostname.rstrip(".")
                forbidden += [name, name.split(".", 1)[0], name.split(".", 1)[-1]]
    _PENDING_PROMOTION[:] = offense.catalog_author.rag_candidates(
        _MISSION_CATALOG.get(thread_id, []), forbidden)
    return [c["text"] for c in _PENDING_PROMOTION]


def promote_pending(store=None) -> int:
    """Write the pending candidates to the RAG (operator's order) and empty the
    queue. Returns the number written; if the store fails, the queue is kept."""
    written = offense.catalog_author.store_candidates(list(_PENDING_PROMOTION), store=store)
    _PENDING_PROMOTION.clear()
    return written


# --- 1. GLOBAL MISSION & REQUEST STATE -------------------------------------- #
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
    netns_missing: bool  # network perimeter absent this cycle: operator/llm path not executable
    resume: bool         # resume after "authorize": direct mission, no LLM routing


llm = ChatAnthropic(model="claude-sonnet-4-6")


def _author_model_name() -> str:
    """Model of the LLM technique author, configurable through the
    `PIRATECREW_AUTHOR_MODEL` env var (default: the orchestrator's shared model).

    Lets the author be driven independently from the router/decider (`llm`
    above) — e.g. a more capable model to write techniques —
    without touching the rest of the orchestrator.
    """
    return os.getenv("PIRATECREW_AUTHOR_MODEL", "claude-sonnet-4-6")


# Instance dedicated to the author: reads the env at import time (the REPL/CLI sets
# the env before launch). By default, same model as `llm`.
author_llm = ChatAnthropic(model=_author_model_name())

# Service detection from the (free-text) output of a recon agent.
KNOWN_SERVICES = ["https", "http", "smb", "netbios", "ldap", "ftp", "ssh",
                  "rdp", "mysql", "smtp", "dns", "winrm"]
PORT_TO_SERVICE = {
    "21": "ftp", "22": "ssh", "25": "smtp", "53": "dns", "80": "http",
    "139": "netbios", "143": "smtp", "443": "https", "445": "smb",
    "3306": "mysql", "3389": "rdp", "5985": "winrm", "8080": "http",
}
# Ports probed by default during reconnaissance (single source).
DEFAULT_RECON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                       1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8000,
                       8080, 8443, 8888, 9000, 9090]
_HOSTPORT_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:(\d{1,5})\b")
_PORTWORD_RE = re.compile(r"\bports?\s+(\d{1,5})\b", re.IGNORECASE)


def requested_ports(text: str) -> list[int]:
    """Ports explicitly named in a request (`ip:port`, `port N`).
    Bounded to 1..65535, deduplicated, sorted."""
    found = set()
    for rx in (_HOSTPORT_RE, _PORTWORD_RE):
        for m in rx.finditer(text or ""):
            n = int(m.group(1))
            if 1 <= n <= 65535:
                found.add(n)
    return sorted(found)


# Intent to sweep the FULL RANGE (1-65535). Includes French phrasings on purpose
# (user requests may be written in French).
_FULL_SCAN_RE = re.compile(
    r"(tous?\s+les?\s+ports|all\s+ports|full[-\s]?port|scan\s+complet|"
    r"balayage\s+complet|plage\s+compl[eè]te|-p-|1-65535)",
    re.IGNORECASE,
)


def wants_full_scan(text: str) -> bool:
    """True if the request asks for a sweep of the FULL range 1-65535
    ("tous les ports", "scan complet", "all ports", "-p-")."""
    return bool(_FULL_SCAN_RE.search(text or ""))


# Tool domain to deploy depending on the discovered service.
SERVICE_DOMAIN = {
    "http": "web", "https": "web",
    "smb": "ad", "netbios": "ad", "ldap": "ad",
}

# Python tools that are always present (no external binary). Any technique whose
# `tool` is NOT here is considered to depend on an external binary,
# checked through shutil.which (see technique_available / "missing tool" escalation).
PYTHON_TOOLS = {
    "tcp_port_check", "http_fingerprint", "http_get", "http_get_listing", "smb_port_probe",
    "scope_check", "log_audit_event", "report_finding",
}


def technique_available(tech) -> bool:
    """True if the technique can run here: built-in Python tool, no tool
    required, or external binary present in the PATH. Deterministic (no LLM)."""
    tool = (getattr(tech, "tool", "") or "").strip()
    if not tool or tool in PYTHON_TOOLS:
        return True
    return shutil.which(tool) is not None


def _split_principal(principal: str) -> tuple:
    """Split a principal into (domain, user): `CORP\\user`,
    `user@corp.local` or `user` (empty domain)."""
    if "\\" in principal:
        domain, _, user = principal.partition("\\")
        return domain, user
    if "@" in principal:
        user, _, domain = principal.partition("@")
        return domain, user
    return "", principal


def _render_subs(host: str, port: int = 0, creds: list | None = None,
                 context: dict | None = None) -> Dict[str, Any]:
    """Substitutions AVAILABLE for a template: {target}/{port}, then
    {user}/{domain}/{hash}/{password}/{secret} if `creds`, and {share} if `context`.
    A template with a field that is not listed here cannot be filled."""
    subs: Dict[str, Any] = {"target": host, "port": port}
    if creds:
        domain, user = _split_principal(creds[0].principal)
        subs.update(user=user, domain=domain, hash=creds[0].secret,
                    password=creds[0].secret, secret=creds[0].secret)
    if context and "share" in context:
        subs["share"] = context["share"]
    return subs


def _template_fields(template: str) -> list[str]:
    """Named fields referenced by a template (`{user}`, `{share}`, …)."""
    import string
    return [fn for _, fn, _, _ in string.Formatter().parse(template or "") if fn]


def _render_template(template: str, host: str, port: int = 0,
                     creds: list | None = None, context: dict | None = None) -> str:
    """Render a template with the available substitutions (_render_subs). An
    unknown placeholder returns the raw template without raising (Project 1
    contract kept; the execution path, for its part, refuses an unfillable
    field upstream instead of running the raw template, see node_execute)."""
    if not template:
        return ""
    try:
        return template.format(**_render_subs(host, port, creds, context))
    except (KeyError, IndexError, ValueError):
        return template


# Markers that DISQUALIFY an "open" line (port tested but not open). The French
# entries ("aucun", "fermé", "ferme") match French-language tool output: keep them.
_NEG_MARKERS = ("closed", "filtered", "none open", "no open", "0 open",
                "not open", "aucun", "fermé", "ferme")
_PORT_TOKEN_RE = re.compile(r"\d+")


def _parse_services(text: str) -> List[str]:
    """OPEN services extracted from the free-form output of a recon agent.

    Best-effort fallback (the primary channel remains report_finding). Only keeps
    lines reporting "open" with no negation marker, and matches ports
    by TOKEN rather than substring: "built 2021", "255.255.255.0" or
    "… — none open" no longer create a phantom service.
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


# --- 2. MASTER SUPERVISOR (the Router) -------------------------------------- #
def master_supervisor(state: MissionState) -> Literal["delegate_pirate", "delegate_analyst", "autonomous_mission", "general_response"]:
    if state.get("resume"):
        # Resume after "authorize": the authorization is already consumed, the mission
        # restarts without depending on an LLM classification that could send it elsewhere.
        print("\n[MASTER] Resuming after authorization: autonomous mission.")
        return "autonomous_mission"
    print("\n[MASTER] The orchestrator is analyzing the request...")
    question = state.get("question", "")

    prompt = f"""You are the master orchestrator of the PirateCrew cybersecurity platform.
Analyze the user's request and pick the strategy among these four exact options:
- "delegate_pirate": if the request concerns theory, courses, Active Directory protocols, methodologies or tactical documentation (RAG).
- "delegate_analyst": if the request contains source code, a script (Python, Bash, PowerShell), an exploit PoC or asks for a code analysis.
- "autonomous_mission": if the request asks to run a full scan, find vulnerabilities, audit or exploit a specific target/IP on the network.
- "general_response": if it is a general question, a greeting or administration with no direct technical link.

Answer with only one of these four exact words: "delegate_pirate", "delegate_analyst", "autonomous_mission" or "general_response".

Request: {question}
Choice:"""

    response = llm.invoke(prompt)
    decision = response.content.strip()

    if "autonomous_mission" in decision:
        print("[MASTER] Decision: launching an autonomous mission (Recon / Decide / Execute / Integrate)")
        return "autonomous_mission"
    elif "delegate_analyst" in decision:
        print("[MASTER] Decision: delegating to the code analysis sub-agent (AnalystAgent)")
        return "delegate_analyst"
    elif "delegate_pirate" in decision:
        print("[MASTER] Decision: delegating to the RAG sub-agent (PirateAgent)")
        return "delegate_pirate"
    else:
        print("[MASTER] Decision: handled directly by the orchestrator")
        return "general_response"


# --- 3. CLASSIC DELEGATION NODES -------------------------------------------- #
def node_delegate_to_pirate(state: MissionState):
    # Lazy import: loads the RAG (embedding model) only if used.
    from agents.pirate_agent import pirate_graph_direct
    result = pirate_graph_direct.invoke({"question": state["question"]})
    return {"final_response": result.get("generation", "RAG error.")}


def node_delegate_to_analyst(state: MissionState):
    from agents.analyst_agent import analyst_graph
    result = analyst_graph.invoke({"question": state["question"]})
    return {"final_response": result.get("analysis", "Code analysis error.")}


def node_general_response(state: MissionState):
    prompt = f"You are PirateCrew, a cybersecurity assistant. Answer concisely: {state['question']}"
    resp = llm.invoke(prompt)
    return {"final_response": resp.content}


# --- Mission entry gate (fail-closed scope) --------------------------------- #
def enter_autonomous_mission(state: MissionState, config):
    """Load the scope (scope.txt), start the mission, display the scope.
    Fail-closed: scope.txt missing/empty ⇒ flat refusal, no recon launched."""
    thread_id = ((config or {}).get("configurable", {}).get("thread_id")
                 or state.get("thread_id") or "session_pirate_master")
    try:
        scope = load_scope("scope.txt")
    except ScopeError as exc:
        set_active_scope(None)  # fail-closed: no stale scope stays active after a refusal
        print(f"[SCOPE] Mission refused: {exc}")
        return {"finished": True,
                "final_response": "Mission refused: authorization scope (scope.txt) missing or empty."}
    set_active_scope(scope)
    start_mission(thread_id, scope)
    print(f"[SCOPE] Scope loaded: {len(scope.networks)} entry(ies). Mission {thread_id!r} started.")
    # Network perimeter (namespace + nftables): required by the deterministic
    # offensive path only. Its absence does not refuse the mission — reconnaissance
    # and the builtin tools remain usable — but we say so upfront.
    try:
        offense.netns.verify(scope)
        print(f"[NETNS] Network perimeter active ({offense.netns.NS_NAME}).")
        warning = offense.netns.loopback_warning(scope)
        if warning:
            print(warning)
    except offense.netns.NetnsError as exc:
        print(f"[NETNS] Offensive path disabled: {exc}")
    return {"thread_id": thread_id, "cycle": 0, "max_cycles": state.get("max_cycles", 6),
            "finished": False}


def route_after_enter(state: MissionState) -> Literal["recon", "finish"]:
    return "finish" if state.get("finished") else "recon"


# --- 4. MISSION HELPERS (pure, testable without an LLM) --------------------- #
def _requires_satisfied(world: WorldModel, host: str, service: str, requires: set) -> bool:
    """True if the world model satisfies a technique's prerequisites."""
    for req in requires:
        if req == "credential" and not world.creds_applicable(service):
            return False
        if req == "session" and not any(
                s.host == host and s.alive and s.authorized for s in world.sessions):
            return False
    return True


def authorize_sessions(world: WorldModel, host: str) -> int:
    """Authorize the live sessions of `host` that are not yet authorized;
    returns the number of sessions changed."""
    n = 0
    for s in world.sessions:
        if s.host == host and s.alive and not s.authorized:
            s.authorized = True
            n += 1
    return n


def _task_inputs_fp(world: WorldModel, service: str, requires: set) -> str:
    """Fingerprint of the inputs used for a technique (e.g. the chosen cred).
    Lets the ledger tell an attempt without a cred from an attempt with one."""
    if "credential" in requires:
        creds = world.creds_applicable(service)
        if creds:
            # Fingerprint over ALL applicable creds (sorted): a new cred
            # changes the fingerprint and re-opens the technique (R2), whereas creds[0]
            # alone froze it on the first cred forever.
            ids = sorted(f"{c.principal}:{c.secret}" for c in creds)
            return inputs_fingerprint({"cred": ",".join(ids)})
    return ""


def plan_tasks(world: WorldModel, catalog: list) -> List[Dict[str, Any]]:
    """For each (in-scope host, service), the techniques whose prerequisites
    are satisfied and that have not already been tried with the same inputs."""
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


# Best-effort patterns for catching findings in raw text (R1).
_CRED_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9._\\-]{1,63}):([^\s:/]{3,64})(?:\b|(?<=\W)(?=\s|$))")
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# Explicit credential cue: a 'word:value' is only kept on a line that carries
# one, otherwise "Server:nginx" / "Host:10.0.0.1" fabricate false secrets that
# would wrongly unlock techniques with requires={credential}. The French cues
# (mot de passe, mdp, identifiant...) match French-language target data: keep them.
_CRED_CUE_RE = re.compile(
    r"\b(cred|creds|credential|credentials|password|passwd|pwd|login|logon|secret|hash|ntlm|kerb"
    r"|mot de passe|mot_de_passe|mdp|identifiant|identifiants)\b",
    re.IGNORECASE,
)
# "key = value" / "key: value" form (ini, .env, YAML, JSON): a password is only
# kept if it has a user identifier within _KV_WINDOW lines at most. The French key
# names (utilisateur, mot_de_passe...) match French-language target data: keep them.
_KV_RE = re.compile(r"""^\s*["']?([A-Za-z][\w.\-]{0,63})["']?\s*[=:]\s*(.*?)\s*$""")
_KV_WINDOW = 3
_KV_USER_KEYS = {"user", "username", "user_name", "login", "utilisateur", "identifiant",
                 "account", "compte"}
_KV_USER_SUFFIXES = ("_user", "_username", "_login", "_utilisateur")
_KV_PASS_KEYS = {"password", "passwd", "pass", "pwd", "mot_de_passe", "motdepasse", "mdp",
                 "secret"}
_KV_PASS_SUFFIXES = ("_password", "_passwd", "_pass", "_pwd", "_mdp", "_mot_de_passe")
_KV_USER_VALUE = re.compile(r"[A-Za-z0-9][\w.@\\\-]{0,63}")
# Header/label names to NEVER mistake for a credential principal.
# The cue window (cue + 2 lines) can sweep over a compact "Server:nginx" /
# "Host:10.0.0.1": that is structured prose, not identifiers.
_NON_CRED_PRINCIPALS = {
    "server", "host", "date", "connection", "content", "content-type",
    "content-length", "content-encoding", "transfer-encoding", "location",
    "etag", "vary", "cache-control", "set-cookie", "cookie", "x-powered-by",
    "x-frame-options", "last-modified", "accept-ranges", "keep-alive",
    "www-authenticate", "user-agent", "referer", "via", "upgrade", "allow",
    "pragma", "expires", "strict-transport-security",
    # Key names: "password:hunter2" does not have "password" as its identifier.
    "password", "passwd", "pass", "pwd", "secret", "mot_de_passe", "mdp",
    "user", "username", "login", "utilisateur", "identifiant",
}


def _kv_clean(value: str) -> str:
    """Raw value of a "key = value" line: trailing comma and quotes removed."""
    v = value.rstrip(",;").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v


def _kv_is_secret(value: str) -> bool:
    """True if `value` looks like a real secret, not a template/mask/empty value."""
    if not 3 <= len(value) <= 128 or any(c.isspace() for c in value):
        return False
    if value.startswith(("$", "{", "<", "%")) or set(value) <= {"*", "x", "X"}:
        return False
    return value.lower() not in {"none", "null", "nil", "undefined", "true", "false"}


def _kv_credentials(lines: List[str]) -> List[tuple]:
    """(identifier, secret) pairs from "key = value" lines: each password
    is paired with the closest identifier within _KV_WINDOW lines at most. Pure."""
    users, secrets = [], []
    for i, line in enumerate(lines):
        m = _KV_RE.match(line)
        if not m:
            continue
        key = m.group(1).lower().replace("-", "_").replace(".", "_")
        value = _kv_clean(m.group(2))
        if key in _KV_PASS_KEYS or key.endswith(_KV_PASS_SUFFIXES):
            if _kv_is_secret(value):
                secrets.append((i, value))
        elif key in _KV_USER_KEYS or key.endswith(_KV_USER_SUFFIXES):
            if _KV_USER_VALUE.fullmatch(value):
                users.append((i, value))
    out = []
    for i, secret in secrets:
        near = [(abs(j - i), user) for j, user in users if abs(j - i) <= _KV_WINDOW]
        if near:
            out.append((min(near)[1], secret))
    return out


def reconcile_evidence(world: WorldModel, raw_text: str) -> int:
    """Back-stop (R1): spot obvious credentials (principal:secret) and hosts
    (IPv4) in raw output and add them to the model if they are
    new. Returns the number of items added. Never raises."""
    text = raw_text or ""
    added = 0
    # Credentials: only from a LINE carrying an explicit credential cue
    # (anti-fabrication from harmless "word:value" prose).
    # Window anchored on the cue: the cue line + the next 2 (real files
    # often separate "Cred for DC :" from the value).
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
    for principal, secret in _kv_credentials(lines):
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
    """probe(host,port)->bool tests whether a port is open. For each open port,
    registers a service through world.add_service. Service name: PORT_TO_SERVICE.get(str(port))
    if known; otherwise fingerprint(host,port)->str|None if provided (e.g. 'http' for a
    web service on an unusual port); otherwise ''. Returns the number of open ports registered.

    `log` (optional): callable(str) called for EACH open port (verbose diagnostics).
    `workers`>1: probes the (host,port) pairs IN PARALLEL (threads, I/O-bound); service
    registration stays SEQUENTIAL and deterministic (WorldModel is not thread-safe)."""
    targets = [(host, port) for host in hosts for port in ports]
    if workers and workers > 1 and len(targets) > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=workers) as pool:
            flags = list(pool.map(lambda t: probe(t[0], t[1]), targets))  # map preserves order
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
            log(f"{host}:{port} open → service '{name or '?'}'")
        count += 1
    return count


def autonomous_discovery(world, hosts, default_ports, probe, fingerprint=None, log=None,
                         default_workers=64, full_workers=256) -> int:
    """Self-escalating discovery: sweep of `default_ports`, then, for each host left
    WITHOUT a service, sweep of the full range 1-65535 (heavier, more workers).
    No escalation if `default_ports` already covers the whole range (nothing more to probe).
    Returns the total number of open ports registered."""
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
    """Real TCP probe: true if the connection succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _http_name(host: str, port: int) -> str | None:
    """'http' if the port answers over HTTP (via the http_fingerprint tool), otherwise None."""
    from tools.registry import http_fingerprint
    out = http_fingerprint.invoke({"url": f"http://{host}:{port}/"})
    return "http" if "HTTP" in str(out) else None


# --- 5. AUTONOMOUS MISSION NODES (stateful loop) ---------------------------- #
def node_recon(state: MissionState, config):
    from agents.dynamic_agent import build_task_agent
    thread_id = config["configurable"]["thread_id"]
    world = get_world(thread_id)
    target = state.get("target") or "127.0.0.1"
    print(f"\n[MISSION] Reconnaissance of {target} (cycle {state.get('cycle', 0)})...")
    # Deterministic multi-host / multi-port discovery (no LLM), bounded to the scope.
    hosts = world.scope.hosts(max_hosts=256)
    full = (wants_full_scan(state.get("question", "") or "")
            or wants_full_scan(state.get("target", "") or ""))
    if full:
        # Full range: parallel probing + short timeout (otherwise thousands of
        # filtered ports would drag the cycle out to the end of the timeouts).
        ports = list(range(1, 65536))
        workers = 256
        ports_desc = "FULL RANGE 1-65535"
    else:
        ports = sorted(set(DEFAULT_RECON_PORTS)
                       | set(requested_ports(state.get("question", "") or ""))
                       | set(requested_ports(state.get("target", "") or "")))
        workers = 64
        ports_desc = ",".join(map(str, ports))
    _vprint(f"Scope: {len(hosts)} host(s) to probe → {hosts[:10]}{' …' if len(hosts) > 10 else ''}")
    _vprint(f"Ports probed ({len(ports)}, {workers} workers): {ports_desc}")
    # Self-escalating discovery (full range if the default ports come back empty).
    probe = lambda h, p: _port_open(h, p, timeout=1.0)  # noqa: E731
    autonomous_discovery(world, hosts, ports, probe, _http_name, log=_vprint,
                         default_workers=workers)
    _found = [f"{s.host}:{s.port}/{s.name or '?'}" for h in world.in_scope_hosts() for s in h.services]
    _vprint(f"In-scope services after discovery ({len(_found)}): {_found or 'NONE'}")
    _audit_event("RECON", f"{target} cycle {state.get('cycle', 0)}: {len(ports)} port(s) probed, "
                 f"{len(_found)} in-scope service(s): " + (", ".join(_found) if _found else "none"))
    ctx = (f"OBJECTIVE: scout {target}. For EACH open service, call "
           f"report_finding(kind='service', host='{target}', service=<name>, port=<port>).")
    agent = build_task_agent("network", world, ctx)
    _ports_for_agent = ("the full range 1-65535" if full
                        else f"the common ports ({','.join(map(str, ports))})")
    query = (f"Scan the target {target}. Use nmap_scan if available, otherwise tcp_port_check "
             f"on {_ports_for_agent}. "
             f"Report each open service through report_finding.")
    try:
        result = agent.invoke({"messages": [("user", query)]})
        raw = result["messages"][-1].content
    except Exception as exc:  # noqa: BLE001
        raw = f"(recon error: {type(exc).__name__}: {exc})"
    world.add_evidence({"phase": "recon", "target": target, "raw": raw})
    # Fallback: infer services from the raw text if the agent did not report everything.
    for svc in _parse_services(raw):
        port = next((int(p) for p, s in PORT_TO_SERVICE.items() if s == svc), 0)
        world.add_service(target, port, name=svc)
    services = sorted({s.name for h in world.in_scope_hosts() for s in h.services if s.name})
    return {"recon_results": raw, "discovered_services": services,
            "max_cycles": state.get("max_cycles", 6)}


def _dry_services(world: WorldModel, catalog, planned) -> List[str]:
    """"Dry" in-scope services to hand to the LLM author: non-empty name, absent
    from the planned tasks, and with no technique OR with all techniques
    already tried (a real catalog gap, not a wait on prerequisites)."""
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
    """True if the LLM author has already been called for this service, whether or not
    it produced a technique (one attempt per service and per mission)."""
    return any(e.get("kind") in ("llm_technique", "llm_author_attempt")
               and e.get("service") == service for e in world.evidence)


def _authorable_services(world: WorldModel, catalog) -> List[str]:
    """Exhausted services that the LLM author has not yet handled in this mission."""
    return [s for s in _dry_services(world, catalog, []) if not _already_authored(world, s)]


def _redact(text: str, secrets) -> str:
    """Mask (***) the known secrets AND high-entropy tokens (hash/key/
    token, even unknown ones) before the text goes to the LLM."""
    for s in secrets:
        if s and len(s) >= 3:
            text = text.replace(s, "***")
    return offense.catalog_author._HIGH_ENTROPY.sub("***", text)


def _execute_excerpt(world: WorldModel, tech_id: str, host: str,
                     secrets=(), limit: int = 200) -> str:
    """Excerpt of the last execution output for (tech_id, host), redacted
    of known secrets THEN truncated (the order avoids any secret cut in half)."""
    raw = ""
    for e in world.evidence:
        if (e.get("phase") == "execute" and e.get("technique") == tech_id
                and e.get("host") == host):
            raw = e.get("raw", "") or ""
    if not raw:
        return "(no output captured)"
    cleaned = _redact(str(raw).replace("\n", " ").replace("\r", " "), secrets)
    return cleaned[:limit]


_RAG_AUTHOR_K = 4
_RAG_AUTHOR_EXCERPT = 500


def _rag_for_author(service: str, search=None) -> str:
    """RAG excerpts (operator notes + promoted techniques) useful to the LLM
    author for `service`. Each excerpt is bounded; the source is flagged. Never
    raises: RAG unavailable or empty → empty string (the author works without)."""
    try:
        if search is None:
            from agents.pirate_agent import vectorstore
            search = lambda q, k: vectorstore.similarity_search(q, k=k)  # noqa: E731
        docs = search(f"Authorized enumeration and attack techniques for the {service} service",
                      _RAG_AUTHOR_K) or []
        parts = []
        for d in docs:
            text = " ".join(str(getattr(d, "page_content", "") or "").split())
            if not text:
                continue
            meta = getattr(d, "metadata", None) or {}
            label = "promoted technique" if meta.get("source") == "llm_authored" else "note"
            parts.append(f"- ({label}) {text[:_RAG_AUTHOR_EXCERPT]}")
        return "\n".join(parts)
    except Exception as exc:  # noqa: BLE001 - best-effort, never blocking
        _vprint(f"RAG unavailable for the author: {type(exc).__name__}")
        return ""


def _author_context(world: WorldModel, service: str, extra: str = "") -> str:
    """Real mission context for the LLM author of a technique on `service`.

    Assembled from the WorldModel: version(s)/port(s) of the targeted service on
    in-scope hosts, neighboring services, principals of the applicable credentials, and
    the techniques already tried for this service with a truncated excerpt of their
    result. Output excerpts are REDACTED of known secrets (masked
    with ***); only credential principals are cited — this text goes
    to the LLM, like the context of the existing agent path.
    """
    secrets = [c.secret for c in world.credentials if c.secret]
    lines: List[str] = []
    targets: List[str] = []
    neighbors = set()
    for h in world.in_scope_hosts():
        for s in h.services:
            if s.name == service:
                targets.append(f"{h.ip}:{s.port} ({s.version or 'unknown version'})")
            elif s.name:
                neighbors.add(s.name)
    lines.append("Targeted service: " + ("; ".join(targets) if targets else service))
    if neighbors:
        lines.append("Other services on the host(s): " + ", ".join(sorted(neighbors)))
    principals = [c.principal for c in world.creds_applicable(service)]
    lines.append("Available credentials (principals): "
                 + (", ".join(principals) if principals else "none"))
    tried: List[str] = []
    for (h_ip, svc, tech_id, _fp, port), status in world.technique_ledger.items():
        if svc != service:
            continue
        tried.append(f"{tech_id} on {h_ip}:{port} -> {status}; result: "
                     + _execute_excerpt(world, tech_id, h_ip, secrets))
    if tried:
        lines.append("Already tried (DO NOT propose again):\n- " + "\n- ".join(tried))
    else:
        lines.append("No technique tried yet for this service.")
    if extra:
        lines.append("Knowledge (RAG: operator notes and already-promoted techniques, "
                     "to adapt — do not copy any literal value):\n" + extra)
    return "\n".join(lines)


def node_decide(state: MissionState, config):
    thread_id = config["configurable"]["thread_id"]
    world = get_world(thread_id)
    tasks = plan_tasks(world, _effective_catalog(thread_id))
    if not tasks:
        authored = False
        for svc in _dry_services(world, _effective_catalog(thread_id), tasks):
            if _already_authored(world, svc):
                continue
            world.add_evidence({"kind": "llm_author_attempt", "service": svc})
            tech = offense.catalog_author.author_technique(
                svc, _author_context(world, svc, extra=_rag_for_author(svc)),
                lambda p: author_llm.invoke(p).content)
            if tech:
                _MISSION_CATALOG.setdefault(thread_id, []).append(tech)
                try:
                    offense.catalog_author.persist_llm_technique(tech, thread_id)
                except Exception as exc:  # noqa: BLE001 - best-effort
                    _vprint(f"LLM technique persistence failed: {type(exc).__name__}")
                world.add_evidence({"kind": "llm_technique", "service": svc, "id": tech.id})
                _audit_event("AUTHORED", f"{svc}: {tech.id} (tool={tech.tool or '-'})")
                authored = True
        if authored:
            tasks = plan_tasks(world, _effective_catalog(thread_id))
    _vprint("Planned tasks: " + str(
        [f"{t['host']}:{t['port']}/{t['service']}→{t['technique_id']}" for t in tasks] or "none"))
    services = state.get("discovered_services", [])
    rag = ""
    if services:
        try:
            from agents.pirate_agent import vectorstore
            docs = vectorstore.similarity_search(
                "Authorized attack and enumeration techniques for: " + ", ".join(services), k=3)
            rag = "\n\n---\n\n".join(d.page_content for d in docs)
        except Exception as exc:  # noqa: BLE001
            rag = f"(RAG unavailable: {type(exc).__name__})"
    _audit_event("DECIDE", f"cycle {state.get('cycle', 0)}: {len(tasks)} task(s): "
                 + (", ".join(f"{t['technique_id']}@{t['host']}:{t.get('port', 0)}" for t in tasks)
                    if tasks else "none"))
    print(f"[MISSION] Decision: {len(tasks)} task(s) planned for this cycle.")
    return {"planned": tasks, "rag_context": rag}


def node_execute(state: MissionState, config):
    thread_id = config["configurable"]["thread_id"]
    world = get_world(thread_id)
    reports: List[Dict[str, Any]] = []
    for task in state.get("planned", []):
        tech = technique_by_id(_effective_catalog(thread_id), task["technique_id"])
        port = int(task.get("port", 0) or 0)
        inputs_fp = task.get("inputs_fp", "")
        # "Missing tool" escalation (Option Y): required tool absent ⇒ we do not
        # execute, we flag it, and we do NOT mark the technique (it stays
        # replannable after the tool is installed + the mission is relaunched).
        if not technique_available(tech):
            msg = f"Required tool missing: {tech.tool}"
            world.add_evidence({"kind": "tool_request", "tool": tech.tool,
                                "technique": tech.id, "host": task["host"]})
            reports.append({"technique": tech.id, "host": task["host"],
                            "service": task["service"], "port": port, "inputs_fp": inputs_fp,
                            "status": "blocked_missing_tool", "tool": tech.tool, "detail": msg})
            continue
        # DETERMINISTIC offensive path (operator/llm): rendering + guarded executor,
        # never through the LLM agent. Builtin techniques keep the agent path.
        if tech.provided_by in ("operator", "llm"):
            if is_propose_only() and tech.provided_by == "llm":
                reports.append({"technique": tech.id, "host": task["host"],
                                "service": task["service"], "port": port, "inputs_fp": inputs_fp,
                                "status": "proposed_awaiting_operator",
                                "detail": "LLM technique proposed, awaiting operator validation."})
                continue
            creds = world.creds_applicable(task["service"])
            # Scope (reference check): every LITERAL host in the template must be
            # in-scope — names are resolved. {target} is in-scope by construction;
            # {domain}/{share} are identities, not hosts. Out of scope -> we do not
            # execute, we report to the operator (who can add it to the scope).
            from offense.guardrails import scope_literal_violations as _scope_literal_violations
            _bad_scope = _scope_literal_violations(tech.command_template)
            if _bad_scope:
                detail = (f"Host(s) out of scope: {', '.join(_bad_scope)} — "
                          f"add them to the scope (scope.txt) to authorize them.")
                world.add_evidence({"kind": "out_of_scope", "technique": tech.id,
                                    "host": task["host"], "literals": ", ".join(_bad_scope)})
                reports.append({"technique": tech.id, "host": task["host"], "service": task["service"],
                                "port": port, "inputs_fp": inputs_fp,
                                "status": "blocked_out_of_scope", "detail": detail})
                continue
            # Fail-visible refusal of a template with an unfillable placeholder (e.g. {share}
            # with no value): we do NOT execute a raw template (literal braces), we
            # report the missing input. The ledger marks it 'tried' (loop-safe).
            _subs = _render_subs(task["host"], port, creds=creds)
            _missing = sorted({f for f in _template_fields(tech.command_template) if f not in _subs})
            if _missing:
                detail = f"Required input(s) not available: {', '.join(_missing)}"
                world.add_evidence({"kind": "missing_input", "technique": tech.id,
                                    "host": task["host"], "fields": ", ".join(_missing)})
                reports.append({"technique": tech.id, "host": task["host"], "service": task["service"],
                                "port": port, "inputs_fp": inputs_fp,
                                "status": "blocked_missing_input", "detail": detail})
                continue
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
        ctx = (f"OBJECTIVE: run the technique '{tech.id}' ({tech.name}) on "
               f"{task['host']}:{port} / service {task['service']}, WITHIN the scope. "
               f"Expected tool: {tech.tool or '(provided tools)'}. "
               f"Command: {rendered or '(no template — use the provided tools)'}. "
               f"Success signal: {tech.success_signal or '(none)'}. "
               f"Applicable CREDS: {[c.principal for c in creds] or 'none'}. "
               f"RAG: {(state.get('rag_context') or '')[:800]}. "
               f"Report any finding through report_finding.")
        agent = build_task_agent(domain, world, ctx)
        query = (f"Run the technique {tech.id} on {task['host']}:{port} ({task['service']}). "
                 + (f"Command: {rendered}" if rendered else ""))
        try:
            result = agent.invoke({"messages": [("user", query)]})
            raw = result["messages"][-1].content
            # What the tools actually returned (the LLM summary may omit
            # the content read): feeds node_integrate's findings back-stop.
            tool_output = "\n".join(str(m.content) for m in result["messages"]
                                    if getattr(m, "type", "") == "tool")
            status = "done"
        except Exception as exc:  # noqa: BLE001
            raw = f"{type(exc).__name__}: {exc}"
            tool_output = ""
            status = "error"
        world.add_evidence({"phase": "execute", "technique": tech.id, "host": task["host"], "raw": raw})
        reports.append({"technique": tech.id, "host": task["host"], "service": task["service"],
                        "port": port, "inputs_fp": inputs_fp, "status": status, "detail": raw,
                        "tool_output": tool_output})
    # Audit trail of the execution (every technique that went through this node, whatever
    # its outcome). Structural fields ONLY — never the rendered command, which carries
    # the credential (it stays in world.json, see README § secrets at rest).
    for r in reports:
        _audit_event("EXEC", f"{r.get('technique', '?')} {r.get('host', '?')}:{r.get('port', 0)}"
                     f"/{r.get('service', '?')} -> {r.get('status', '?')}")
    return {"execution_reports": reports}


def node_integrate(state: MissionState, config):
    thread_id = config["configurable"]["thread_id"]
    world = get_world(thread_id)
    reports = state.get("execution_reports", [])
    # Only mark as "tried" what actually ran (done/error) or was blocked by a guardrail
    # (avoids re-spinning). A
    # technique blocked by a missing tool is not burned: it stays
    # replannable after installation + relaunch (Option Y). Keyed by (inputs, port).
    for report in reports:
        if report.get("status") in ("done", "error", "blocked_destructive",
                                    "blocked_out_of_scope", "blocked_shell_meta",
                                    "blocked_missing_input"):
            world.mark_technique(report["host"], report["service"], report["technique"],
                                 report.get("inputs_fp", ""), status="tried",
                                 port=int(report.get("port", 0) or 0))
    # R1 back-stop: recovers creds/hosts from raw outputs. A "network perimeter
    # absent" block is not tool output: its message (which cites scope
    # addresses) must not feed the world model.
    added = 0
    for report in reports:
        if report.get("status") == "blocked_no_netns":
            continue
        added += reconcile_evidence(world, report.get("detail", ""))
        if report.get("tool_output"):
            added += reconcile_evidence(world, report["tool_output"])
    cycle = state.get("cycle", 0) + 1
    summary = (f"Mission (cycle {cycle}): {len(world.in_scope_hosts())} in-scope host(s), "
               f"{len(world.credentials)} credential(s), {len(world.sessions)} session(s), "
               f"{len(world.loot)} loot item(s). +{added} finding(s) recovered from raw text this cycle.")
    # "Missing tool" escalation (Option Y): lists the binaries to install.
    missing = sorted({r.get("tool", "") for r in reports
                      if r.get("status") == "blocked_missing_tool" and r.get("tool")})
    if missing:
        hints = " ; ".join(f"{t} (`sudo apt install -y {t}`)" for t in missing)
        summary += ("\n⚠ Techniques waiting for a missing tool: " + hints +
                    ". Install it/them in the environment (Kali) then relaunch the same mission to unblock them.")
    # "Network perimeter absent" escalation: same contract as the missing tool —
    # operator/llm techniques are NOT marked (replannable once the namespace
    # is in place), the operator is warned once per cycle.
    netns_blocked = [r for r in reports if r.get("status") == "blocked_no_netns"]
    if netns_blocked:
        summary += (f"\n⚠ {len(netns_blocked)} technique(s) waiting for the network perimeter. "
                    "Network perimeter not in place: run 'sudo python -m offense.netns up' then relaunch.")
    print(f"[MISSION] Integration: {summary}")
    # Persistence every cycle: findings survive a crash/interruption.
    try:
        mission_io.save_world(world, thread_id)
    except Exception as e:  # best-effort persistence: never interrupt the mission
        print(f"[MISSION] warning: persistence failed ({type(e).__name__})")
    return {"cycle": cycle, "final_response": summary, "netns_missing": bool(netns_blocked)}


def route_after_integrate(state: MissionState) -> Literal["continue", "finish"]:
    """Continue as long as plannable tasks remain on an in-scope host and
    the cycle cap is not reached; otherwise finish (exhaustion/cap)."""
    if state.get("cycle", 0) >= state.get("max_cycles", 6):
        print("\n[MISSION] Cycle cap reached — done.")
        return "finish"
    if state.get("finished"):
        return "finish"
    thread_id = state.get("thread_id")
    world = _MISSIONS.get(thread_id) if thread_id else None
    if world is not None:
        # We continue ONLY if a truly RUNNABLE task remains. Tasks blocked by a
        # missing tool are flagged but do not spin the loop idle until the
        # cycle cap (see Option Y escalation).
        # Same without the network perimeter: operator/llm techniques are not runnable.
        cat = _effective_catalog(thread_id)
        netns_missing = bool(state.get("netns_missing"))
        runnable = []
        for t in plan_tasks(world, cat):
            tech = technique_by_id(cat, t["technique_id"])
            if not technique_available(tech):
                continue
            if netns_missing and tech.provided_by in ("operator", "llm"):
                continue
            if is_propose_only() and tech.provided_by == "llm":
                continue                      # proposed, never executed: does not make it loop
            runnable.append(t)
        if not runnable:
            # Catalog exhausted on a service: decide must still hand over to the
            # LLM author (once per service), unless nothing it would write
            # could run (network perimeter absent).
            if not netns_missing and _authorable_services(world, cat):
                return "continue"
            print("\n[MISSION] Exhausted: no runnable in-scope task left — done.")
            return "finish"
    return "continue"


# --- 6. MASTER GRAPH CONSTRUCTION ------------------------------------------- #
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

# Mission gate: enter → recon (scope OK) or END (fail-closed refusal).
master_workflow.add_conditional_edges(
    "enter",
    route_after_enter,
    {"recon": "recon", "finish": END},
)

# Autonomous mission loop: recon (once) → decide → execute → integrate → route.
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


# --- 7. INTERACTIVE CLI ----------------------------------------------------- #
if __name__ == "__main__":
    print("==================================================")
    print(" 🏴‍☠️  PirateCrew - Stateful orchestrator 🏴‍☠️ ")
    print("==================================================")
    print("Type 'exit' or 'quit' to leave.\n")

    # Authorization scope: fail-closed (scope.txt mandatory for a mission).
    # Loading + the detailed mission gate are finalized in Task 7.
    # Informational display of the scope at startup. The mission gate
    # (enter_autonomous_mission) (re)loads and enforces it, fail-closed.
    try:
        _scope0 = load_scope("scope.txt")
        print(f"[SCOPE] scope.txt: {len(_scope0.networks)} entry(ies). Autonomous missions allowed within this scope.")
    except ScopeError as exc:
        print(f"[SCOPE] scope.txt missing/empty ({exc}). Autonomous missions will be refused.")

    if is_verbose():
        print("[VERBOSE] mode enabled (PIRATECREW_VERBOSE). Type \"verbose\" to toggle.")
    else:
        print("Tip: type \"verbose\" to enable detailed diagnostics (ports/services/tasks).")

    _last_mission_id, _last_target = None, None

    while True:
        try:
            user_input = input("\nYou > ")
            if user_input.lower() in ["exit", "quit"]:
                print("Closing PirateCrew.")
                break
            if not user_input.strip():
                continue

            # Verbose (diagnostic) mode toggle: "verbose", "verbose on/off".
            _parts = user_input.strip().lower().split()
            if _parts[0] == "verbose":
                if len(_parts) == 1:
                    set_verbose(not is_verbose())
                else:
                    set_verbose(_parts[1] in ("on", "1", "true", "yes", "oui"))
                print(f"[VERBOSE] mode {'enabled' if is_verbose() else 'disabled'}.")
                continue

            # Propose-only (LLM author: propose without executing): "propose-only [on|off]".
            if _parts[0] == "propose-only":
                if len(_parts) == 1:
                    set_propose_only(not is_propose_only())
                else:
                    set_propose_only(_parts[1] in ("on", "1", "true", "yes", "oui"))
                print(f"[PROPOSE-ONLY] mode {'enabled' if is_propose_only() else 'disabled'}.")
                continue

            # List the sessions of the last mission.
            if _parts[0] == "sessions":
                _w = _MISSIONS.get(_last_mission_id) if _last_mission_id else None
                if _w is None or not _w.sessions:
                    print("[SESSIONS] no sessions.")
                else:
                    for _s in _w.sessions:
                        _state = "authorized" if _s.authorized else "pending"
                        print(f"[SESSIONS] {_s.host} / {_s.channel} — {_state}")
                continue

            # Writing the LLM techniques proposed at the end of a mission to the shared
            # RAG: only on this explicit operator order.
            if _parts[0] == "promote":
                try:
                    _n = promote_pending()
                    print(f"[PROMOTE] {_n} technique(s) added to the RAG." if _n
                          else "[PROMOTE] nothing to promote.")
                except Exception as exc:
                    print(f"[PROMOTE] failed ({type(exc).__name__}) — nothing was added.")
                continue

            # Target = first IP mentioned in the request, otherwise 127.0.0.1.
            _ipm = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", user_input)

            _resume = False
            if _parts[0] == "authorize":
                if not _ipm:
                    print("[AUTHORIZE] usage: authorize <host (IPv4)>")
                    continue
                _host = _ipm.group(0)
                new_id = (resume_with_authorization(_last_mission_id, _host, _last_target)
                          if _last_mission_id else None)
                if not new_id:
                    print(f"[AUTHORIZE] no pending session to authorize for {_host}.")
                    continue
                print(f"[AUTHORIZE] session(s) of {_host} authorized — resuming the mission.")
                _question = f"Start the post-exploitation resume of {_host} (audit/exploitation of the target)"
                mission_id, target = new_id, _last_target
                user_input = _question
                _resume = True
            else:
                target = _ipm.group(0) if _ipm else "127.0.0.1"
                # Mission identity: one mission_id per run = thread_id.
                mission_id = mission_io.new_mission_id(target)
            config = {"configurable": {"thread_id": mission_id}}

            initial_state = {
                "question": user_input,
                "resume": _resume,
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
                # Guarantees world.json + report even on Ctrl-C / exception.
                w = _MISSIONS.get(mission_id)
                if w is not None:
                    # Best-effort persistence: a failure never masks the original exception.
                    try:
                        mission_io.save_world(w, mission_id)
                    except Exception as exc:
                        print(f"[MISSION] warning: persistence failed ({type(exc).__name__})")
                    try:
                        report_path = mission_io.save_report(w, mission_id)
                        print(f"\n[MISSION] Report: {report_path}")
                    except Exception as exc:
                        print(f"[MISSION] warning: persistence failed ({type(exc).__name__})")
                    # Learning loop: techniques authored by the LLM are PROPOSED
                    # for the shared RAG, never written automatically — the operator
                    # reviews what would be stored, then types "promote".
                    try:
                        _cands = queue_promotion(mission_id)
                        if _cands:
                            print(f"[MISSION] {len(_cands)} LLM technique(s) proposed for the shared RAG. "
                                  "Review them, then type \"promote\" to add them:")
                            for _c in _cands:
                                print(f"  - {_c}")
                    except Exception as exc:
                        print(f"[MISSION] warning: RAG promotion preparation failed ({type(exc).__name__})")
            # Last known MISSION (a turn without a mission does not replace it).
            _last_mission_id, _last_target = _last_mission_after(
                (_last_mission_id, _last_target), mission_id, target)
            print(f"\nPirateCrew >\n{result.get('final_response', 'No response generated.')}")
            # Session gate: surfaces sessions obtained but not authorized.
            _w = _MISSIONS.get(mission_id)
            _pend = _pending_sessions(_w) if _w is not None else []
            if _pend:
                _liste = ", ".join(f"{s.host}/{s.channel}" for s in _pend)
                print(f"⏸ Session(s) awaiting authorization: {_liste} — "
                      f"type \"authorize <host>\" to start post-exploitation.")
        except KeyboardInterrupt:
            print("\nInterrupted. Exiting.")
            break
