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
    print("[+] Running sub-agent: code / script analysis...")
    question = state["question"]

    prompt = f"""You are an expert analyst of offensive code and scripts within PirateCrew.
Analyze the request, code or script provided by the user. Explain how it works, its evasion mechanisms, its security risks and, where needed, remediation or adaptation options.

=== REQUEST / CODE TO ANALYZE ===
{question}
"""
    reponse = llm.invoke(prompt)
    return {"analysis": reponse.content}

workflow = StateGraph(AnalystAgentState)
workflow.add_node("analyze", node_analyze)
workflow.add_edge(START, "analyze")
workflow.add_edge("analyze", END)

analyst_graph = workflow.compile()