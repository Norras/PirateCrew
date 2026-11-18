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

# Temperature removed
llm = ChatAnthropic(model="claude-sonnet-4-6")

def node_router(state: PirateAgentState) -> Literal["retrieve", "direct_generate"]:
    print("[+] Running node: smart LLM router...")
    question = state["question"]

    prompt = f"""Analyze the user's question below and decide whether it requires consulting the internal technical documentation base (cybersecurity / Active Directory pentest courses) or whether it is a general question, a greeting or basic chit-chat.

Answer with **only** a single word:
- "retrieve" if the question concerns technique, attacks, protocols, configurations or HTB courses.
- "direct_generate" if it is a greeting, a general question or off-topic (non-technical).

Question: {question}
Decision (retrieve/direct_generate):"""

    response = llm.invoke(prompt)
    decision = response.content.strip().lower()
    
    if "direct_generate" in decision:
        print(" -> Route chosen: direct generation (no RAG)")
        return "direct_generate"
    else:
        print(" -> Route chosen: RAG search (ChromaDB)")
        return "retrieve"

def node_retrieve(state: PirateAgentState):
    print("[+] Running node: vector search (ChromaDB)...")
    docs = vectorstore.similarity_search(state["question"], k=3)
    return {"documents": [doc.page_content for doc in docs]}

def node_generate(state: PirateAgentState):
    print("[+] Running node: answer generation (Claude)...")
    docs = state.get("documents", [])
    contexte = "\n\n---\n\n".join(docs) if docs else "No contextual document provided."

    prompt = f"""You are PirateCrew, an expert assistant in cybersecurity and pentesting.
Answer the user's question, relying strictly on the technical context provided if available.

=== SOURCE DOCUMENTATION (RAG) ===
{contexte}

=== QUESTION ===
{state['question']}
"""
    reponse = llm.invoke(prompt)
    return {"generation": reponse.content}

def _build_routed_graph():
    """Standalone graph: the LLM router decides retrieve vs direct_generate.
    Useful when pirate_agent is called on its own (no orchestrator upstream)."""
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
    """Graph for delegation from the orchestrator: direct RAG, NO router.
    The master supervisor has already decided the question is technical, so there is
    no need to re-route here. This saves an LLM call (retrieve → generate directly)."""
    wf = StateGraph(PirateAgentState)
    wf.add_node("retrieve", node_retrieve)
    wf.add_node("generate", node_generate)
    wf.add_edge(START, "retrieve")
    wf.add_edge("retrieve", "generate")
    wf.add_edge("generate", END)
    return wf.compile()


# Two graphs, same nodes, different entry points.
pirate_graph = _build_routed_graph()         # standalone use (with router)
pirate_graph_direct = _build_direct_graph()  # use via orchestrator (no router)