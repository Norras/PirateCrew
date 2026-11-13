import os
from typing import List, TypedDict, Literal
from dotenv import load_dotenv
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from langchain_anthropic import ChatAnthropic
from langgraph.graph import StateGraph, START, END

load_dotenv()

class PirateAgentState(TypedDict):
    question: str
    documents: List[str]
    generation: str

DB_DIR = "./chroma_db"
embeddings = HuggingFaceEmbeddings(model_name="BAAI/bge-m3")
vectorstore = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)

# Retrait de la temperature
llm = ChatAnthropic(model="claude-sonnet-4-6")

def node_router(state: PirateAgentState) -> Literal["retrieve", "direct_generate"]:
    print("[+] Exécution du nœud : Routeur LLM intelligent...")
    question = state["question"]
    
    prompt = f"""Analyse la question de l'utilisateur ci-dessous et détermine si elle nécessite de consulter la base de documentation technique interne (cours de cybersécurité/pentest Active Directory) ou si c'est une question générale, une salutation ou une discussion basique.

Réponds **uniquement** par un seul mot :
- "retrieve" si la question touche à la technique, aux attaques, aux protocoles, aux configurations ou aux cours HTB.
- "direct_generate" si c'est une salutation, une question générale ou hors technique.

Question : {question}
Décision (retrieve/direct_generate) :"""

    response = llm.invoke(prompt)
    decision = response.content.strip().lower()
    
    if "direct_generate" in decision:
        print(" -> Route choisie : Génération directe (hors RAG)")
        return "direct_generate"
    else:
        print(" -> Route choisie : Recherche RAG (ChromaDB)")
        return "retrieve"

def node_retrieve(state: PirateAgentState):
    print("[+] Exécution du nœud : Recherche vectorielle (ChromaDB)...")
    docs = vectorstore.similarity_search(state["question"], k=3)
    return {"documents": [doc.page_content for doc in docs]}

def node_generate(state: PirateAgentState):
    print("[+] Exécution du nœud : Génération de la réponse (Claude)...")
    docs = state.get("documents", [])
    contexte = "\n\n---\n\n".join(docs) if docs else "Aucun document contextuel fourni."

    prompt = f"""Tu es PirateCrew, un assistant expert en cybersécurité et pentest.
Réponds à la question de l'utilisateur en t'appuyant rigoureusement sur le contexte technique fourni si disponible.

=== DOCUMENTATION SOURCE (RAG) ===
{contexte}

=== QUESTION ===
{state['question']}
"""
    reponse = llm.invoke(prompt)
    return {"generation": reponse.content}

def _build_routed_graph():
    """Graphe autonome : le routeur LLM décide retrieve vs direct_generate.
    Utile quand le pirate_agent est appelé seul (sans orchestrateur en amont)."""
    wf = StateGraph(PirateAgentState)
    wf.add_node("retrieve", node_retrieve)
    wf.add_node("generate", node_generate)
    wf.add_conditional_edges(
        START,
        node_router,
        {"retrieve": "retrieve", "direct_generate": "generate"},
    )
    wf.add_edge("retrieve", "generate")
    wf.add_edge("generate", END)
    return wf.compile()


def _build_direct_graph():
    """Graphe pour la délégation depuis l'orchestrateur : RAG direct, SANS routeur.
    Le superviseur maître a déjà décidé que la question est technique → inutile de
    re-router ici. On économise un appel LLM (retrieve → generate directement)."""
    wf = StateGraph(PirateAgentState)
    wf.add_node("retrieve", node_retrieve)
    wf.add_node("generate", node_generate)
    wf.add_edge(START, "retrieve")
    wf.add_edge("retrieve", "generate")
    wf.add_edge("generate", END)
    return wf.compile()


# Deux graphes, mêmes nœuds, entrées différentes.
pirate_graph = _build_routed_graph()         # usage autonome (avec routeur)
pirate_graph_direct = _build_direct_graph()  # usage via orchestrateur (sans routeur)