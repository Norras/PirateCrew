import os
from typing import TypedDict
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langgraph.graph import StateGraph, START, END

load_dotenv()

class AnalystAgentState(TypedDict):
    question: str
    analysis: str

llm = ChatAnthropic(model="claude-sonnet-4-6")

def node_analyze(state: AnalystAgentState):
    print("[+] Exécution du sous-agent : Analyse de code / script...")
    question = state["question"]

    prompt = f"""Tu es un analyste de code et de scripts offensifs expert au sein de PirateCrew.
Analyse la demande, le code ou le script fourni par l'utilisateur. Explique son fonctionnement, ses mécanismes de contournement, ses risques de sécurité et, si nécessaire, les pistes de remédiation ou d'adaptation.

=== DEMANDE / CODE À ANALYSER ===
{question}
"""
    reponse = llm.invoke(prompt)
    return {"analysis": reponse.content}

workflow = StateGraph(AnalystAgentState)
workflow.add_node("analyze", node_analyze)
workflow.add_edge(START, "analyze")
workflow.add_edge("analyze", END)

analyst_graph = workflow.compile()