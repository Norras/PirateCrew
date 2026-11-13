"""Fabrique d'agents d'intervention (pattern Factory).

build_task_agent(domain) assemble un agent React doté :
- des outils OBLIGATOIRES (audit), toujours présents ;
- des outils CONDITIONNELS du domaine demandé ('network', 'web', 'ad').

L'agent retourné s'invoque via :
    agent.invoke({"messages": [("user", "...")]})
et la réponse se lit dans result["messages"][-1].content
"""

from dotenv import load_dotenv
from langgraph.prebuilt import create_react_agent
from langchain_anthropic import ChatAnthropic

from tools.registry import MANDATORY_TOOLS, TOOL_CATALOG

load_dotenv()

_SYSTEM_PROMPT = (
    "Tu es un agent d'intervention de PirateCrew, dédié au pentest AUTORISÉ et à la sécurité "
    "défensive. Tu utilises exclusivement les outils fournis pour reconnaître et énumérer des "
    "cibles que l'utilisateur est autorisé à auditer (lab, VM, périmètre consenti). "
    "Journalise tes étapes via l'outil d'audit. Tu ne génères AUCUN payload d'exploitation : "
    "tu rapportes des faits (ports ouverts, services, en-têtes, surface exposée) et des pistes "
    "d'énumération autorisée. Réponds de façon concise et factuelle."
)


def build_task_agent(domain: str):
    """Construit un agent React pour le domaine donné.

    domain : 'network', 'web' ou 'ad'. Un domaine inconnu ne reçoit que les outils obligatoires.
    """
    tools = MANDATORY_TOOLS + TOOL_CATALOG.get(domain, [])
    llm = ChatAnthropic(model="claude-sonnet-4-6")  # pas de temperature (refusée par le modèle)
    return create_react_agent(llm, tools, prompt=_SYSTEM_PROMPT)
