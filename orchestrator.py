import os
from typing import TypedDict, List, Dict, Any, Literal
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

# Import de vos sous-agents et fabriques
from agents.pirate_agent import pirate_graph_direct, vectorstore
from agents.analyst_agent import analyst_graph
from agents.dynamic_agent import build_task_agent

load_dotenv()

# --- 1. ÉTAT GLOBAL DE LA MISSION & DES REQUÊTES ---
class MissionState(TypedDict):
    question: str
    target: str
    goal: str
    attempts: int
    max_attempts: int
    scan_depth: str
    recon_results: str
    discovered_services: List[str]
    rag_context: str
    execution_reports: List[Dict[str, Any]]
    final_response: str
    mission_success: bool

llm = ChatAnthropic(model="claude-sonnet-4-6")

# Détection des services à partir de la sortie (texte libre) de l'agent de recon.
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
    """Extrait les services détectés depuis la sortie libre de l'agent de recon."""
    low = (text or "").lower()
    found = set()
    for svc in KNOWN_SERVICES:
        if svc in low:
            found.add(svc)
    for port, svc in PORT_TO_SERVICE.items():
        if port in low:
            found.add(svc)
    # https implique une surface web http pour le routage.
    if "https" in found:
        found.add("http")
    return sorted(found)


# --- 2. SUPERVISEUR MAÎTRE (Le Routeur) ---
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
        print("[MASTER] Décision : Lancement d'une mission autonome (Recon / Exploit / Pivot)")
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

# --- 3. NŒUDS DE DÉLÉGATION CLASSIQUE ---
def node_delegate_to_pirate(state: MissionState):
    # Graphe direct (sans routeur) : le master_supervisor a déjà tranché "théorique".
    result = pirate_graph_direct.invoke({"question": state["question"]})
    return {"final_response": result.get("generation", "Erreur RAG.")}

def node_delegate_to_analyst(state: MissionState):
    result = analyst_graph.invoke({"question": state["question"]})
    return {"final_response": result.get("analysis", "Erreur d'analyse de code.")}

def node_general_response(state: MissionState):
    prompt = f"Tu es PirateCrew, un assistant de cybersécurité. Réponds de façon concise : {state['question']}"
    resp = llm.invoke(prompt)
    return {"final_response": resp.content}

# --- 4. NŒUDS DE LA MISSION AUTONOME (Boucle & Pivot) ---
def node_reconnaissance(state: MissionState):
    attempts = state.get("attempts", 0) + 1
    depth = state.get("scan_depth", "quick")
    target = state.get("target", "127.0.0.1")
    print(f"\n[MISSION] --- Essai n°{attempts} (Mode scan: {depth}) ---")

    # Agent dynamique réseau : nmap si dispo, sinon repli socket (tcp_port_check).
    scanner_agent = build_task_agent("network")
    query = (
        f"Scanne la cible {target} en mode {depth}. "
        f"Utilise nmap_scan si disponible ; sinon teste avec tcp_port_check les ports courants "
        f"(21, 22, 80, 443, 139, 445, 3389, 8080). "
        f"Liste explicitement les ports et services ouverts détectés."
    )

    result = scanner_agent.invoke({"messages": [("user", query)]})
    recon_output = result["messages"][-1].content

    # Services réellement déduits de la sortie de l'agent (plus de liste codée en dur).
    services = _parse_services(recon_output)
    print(f"[MISSION] Services détectés : {services or 'aucun'}")

    return {
        "attempts": attempts,
        "max_attempts": state.get("max_attempts", 3),
        "recon_results": recon_output,
        "discovered_services": services,
    }

def node_rag_and_strategy(state: MissionState):
    services = state.get("discovered_services", [])
    print(f"[MISSION] Interrogation croisée du RAG pour les services : {services}")
    if not services:
        return {"rag_context": "Aucun service découvert : pas de requête RAG pertinente."}

    # Vrai RAG : recherche vectorielle dans ChromaDB (réutilise le vectorstore du pirate_agent).
    query = "Techniques d'attaque et d'énumération autorisée pour : " + ", ".join(services)
    try:
        docs = vectorstore.similarity_search(query, k=3)
        rag_data = "\n\n---\n\n".join(doc.page_content for doc in docs) or "(aucun document pertinent)"
    except Exception as exc:  # noqa: BLE001
        rag_data = f"RAG indisponible ({type(exc).__name__}: {exc})"
    return {"rag_context": rag_data}

def node_execution_workers(state: MissionState):
    print("[MISSION] Déploiement des agents d'intervention spécialisés...")
    target = state.get("target", "127.0.0.1")
    reports = []

    # On énumère chaque service unique via l'agent du domaine correspondant.
    for service in set(state.get("discovered_services", [])):
        domain = SERVICE_DOMAIN.get(service)
        if not domain:
            reports.append({"service": service, "status": "skipped",
                            "detail": f"Pas d'agent d'énumération dédié pour {service}."})
            continue

        agent = build_task_agent(domain)
        if domain == "web":
            query = (f"Fais un fingerprint HTTP de http://{target} et rapporte les findings "
                     f"(code de statut, techno/serveur révélés par les en-têtes).")
        else:  # ad
            query = (f"Sonde la surface SMB/AD sur {target} (smb_port_probe) et rapporte les "
                     f"findings d'énumération autorisée. Pas d'exploitation.")
        try:
            result = agent.invoke({"messages": [("user", query)]})
            detail = result["messages"][-1].content
            reports.append({"service": service, "status": "done", "detail": detail})
        except Exception as exc:  # noqa: BLE001
            reports.append({"service": service, "status": "error",
                            "detail": f"{type(exc).__name__}: {exc}"})

    if not reports:
        reports.append({"service": "none", "status": "skipped",
                        "detail": "Aucun service exploitable détecté lors de la reconnaissance."})

    return {"execution_reports": reports}

def node_evaluation(state: MissionState):
    print("[MISSION] Évaluation des résultats par l'orchestrateur...")
    reports = state.get("execution_reports", [])
    findings = "\n\n".join(
        f"[service={r['service']} | statut={r['status']}]\n{r['detail']}" for r in reports
    ) or "(aucun finding)"

    prompt = f"""Tu es l'évaluateur de PirateCrew. À partir des findings de reconnaissance / énumération
ci-dessous et du contexte documentaire, détermine s'il existe un VECTEUR D'ATTAQUE VIABLE identifié
(surface exposée, service à version vulnérable connue, mauvaise configuration exploitable).

Format de réponse STRICT :
- Première ligne EXACTEMENT « VERDICT: SUCCESS » si un vecteur viable est identifié, sinon « VERDICT: FAIL ».
- Ensuite, une synthèse concise des findings et des prochaines étapes d'énumération AUTORISÉE.

=== CONTEXTE DOCUMENTAIRE (RAG) ===
{state.get('rag_context', '(vide)')}

=== FINDINGS ===
{findings}
"""
    resp = llm.invoke(prompt)
    text = resp.content
    success = text.strip().upper().startswith("VERDICT: SUCCESS")
    return {"mission_success": success, "final_response": text}

def route_after_evaluation(state: MissionState) -> Literal["pivot", "finish"]:
    if state.get("mission_success", False):
        return "finish"
    if state["attempts"] < state["max_attempts"]:
        print("\n[🔄 PIVOT STRATÉGIQUE] Échec détecté. L'orchestrateur change de stratégie (passage en mode agressif)...")
        return "pivot"
    print("\n[❌ ÉCHEC MISSION] Nombre maximum de tentatives atteint.")
    return "finish"

def node_pivot(state: MissionState):
    return {"scan_depth": "aggressive"}

# --- 5. CONSTRUCTION DU GRAPHE MAÎTRE ---
master_workflow = StateGraph(MissionState)

# Enregistrement de tous les nœuds
master_workflow.add_node("delegate_pirate", node_delegate_to_pirate)
master_workflow.add_node("delegate_analyst", node_delegate_to_analyst)
master_workflow.add_node("general_response", node_general_response)

master_workflow.add_node("recon", node_reconnaissance)
master_workflow.add_node("rag_strategy", node_rag_and_strategy)
master_workflow.add_node("workers", node_execution_workers)
master_workflow.add_node("evaluator", node_evaluation)
master_workflow.add_node("pivot", node_pivot)

# Aiguillage initial depuis le Superviseur
master_workflow.add_conditional_edges(
    START,
    master_supervisor,
    {
        "delegate_pirate": "delegate_pirate",
        "delegate_analyst": "delegate_analyst",
        "autonomous_mission": "recon",
        "general_response": "general_response"
    }
)

# Pipeline de la mission autonome (Boucle cyclique)
master_workflow.add_edge("recon", "rag_strategy")
master_workflow.add_edge("rag_strategy", "workers")
master_workflow.add_edge("workers", "evaluator")

master_workflow.add_conditional_edges(
    "evaluator",
    route_after_evaluation,
    {
        "pivot": "pivot",
        "finish": END
    }
)
master_workflow.add_edge("pivot", "recon")

# Fins des branches simples
master_workflow.add_edge("delegate_pirate", END)
master_workflow.add_edge("delegate_analyst", END)
master_workflow.add_edge("general_response", END)

memory = MemorySaver()
master_orchestrator = master_workflow.compile(checkpointer=memory)

# --- 6. INTERFACE CLI INTERACTIVE ---
if __name__ == "__main__":
    print("==================================================")
    print(" 🏴‍☠️  PirateCrew - Orchestrateur Multi-Agents 🏴‍☠️ ")
    print("==================================================")
    print("Tapez 'exit' ou 'quit' pour quitter.\n")

    config = {"configurable": {"thread_id": "session_pirate_master"}}

    while True:
        try:
            user_input = input("\nVous > ")
            if user_input.lower() in ["exit", "quit"]:
                print("Fermeture de PirateCrew.")
                break
            
            if not user_input.strip():
                continue

            # Initialisation de l'état de base pour chaque requête
            initial_state = {
                "question": user_input,
                "target": "127.0.0.1", # Extrayible dynamiquement si besoin
                "goal": user_input,
                "attempts": 0,
                "max_attempts": 2,
                "scan_depth": "quick",
                "discovered_services": [],
                "rag_context": "",
                "execution_reports": [],
                "final_response": "",
                "mission_success": False
            }

            result = master_orchestrator.invoke(initial_state, config=config)
            print(f"\nPirateCrew >\n{result.get('final_response', 'Aucune réponse générée.')}")
            
        except KeyboardInterrupt:
            print("\nInterruption. Sortie.")
            break