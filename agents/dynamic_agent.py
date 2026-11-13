"""Fabrique d'agents d'intervention (pattern Factory).

`build_task_agent(domain, world, mission_context)` assemble un agent React doté :
- des outils OBLIGATOIRES (audit + vérification de périmètre), toujours présents ;
- des outils CONDITIONNELS du domaine demandé ('network', 'web', 'ad') ;
- de l'outil `report_finding` lié au modèle du terrain, si un `world` est fourni.

L'agent retourné s'invoque via :
    agent.invoke({"messages": [("user", "...")]})
et la réponse se lit dans result["messages"][-1].content
"""
from __future__ import annotations

from dotenv import load_dotenv
from langgraph.prebuilt import create_react_agent
from langchain_anthropic import ChatAnthropic

from tools.registry import MANDATORY_TOOLS, TOOL_CATALOG, make_report_finding_tool

load_dotenv()

_BASE_PROMPT = (
    "Tu es un agent d'intervention de PirateCrew, dédié au pentest AUTORISÉ. Tu utilises "
    "exclusivement les outils fournis pour reconnaître, énumérer et attaquer des cibles que "
    "l'utilisateur est autorisé à auditer (lab, VM, périmètre consenti), et UNIQUEMENT à "
    "l'intérieur du périmètre d'autorisation — en cas de doute sur une cible, utilise "
    "scope_check. Journalise tes étapes via l'outil d'audit. Remonte CHAQUE trouvaille "
    "(service, credential, session, butin) via l'outil report_finding, de façon structurée. "
    "Réponds de façon concise et factuelle."
)


def _build_prompt(mission_context: str = "") -> str:
    """Prompt système de l'agent, enrichi du contexte de mission s'il est fourni
    (objectif, credentials applicables, techniques non tentées, extraits RAG)."""
    if not mission_context:
        return _BASE_PROMPT
    return f"{_BASE_PROMPT}\n\n=== CONTEXTE DE MISSION ===\n{mission_context}"


def _assemble_tools(domain: str, world=None) -> list:
    """Compose la liste d'outils : obligatoires + domaine (+ report_finding
    lié au modèle du terrain si `world` est fourni). Fonction pure, testable
    sans LLM."""
    tools = list(MANDATORY_TOOLS) + list(TOOL_CATALOG.get(domain, []))
    if world is not None:
        tools.append(make_report_finding_tool(world))
    return tools


def build_task_agent(domain: str, world=None, mission_context: str = ""):
    """Construit un agent React pour le domaine donné.

    domain : 'network', 'web' ou 'ad'. Un domaine inconnu ne reçoit que les
    outils obligatoires. `world` : modèle du terrain à alimenter via
    `report_finding` (None = pas de remontée structurée). `mission_context` :
    texte injecté dans le prompt système. Rétro-compatible :
    `build_task_agent("network")` fonctionne toujours.
    """
    llm = ChatAnthropic(model="claude-sonnet-4-6")  # pas de temperature (refusée par le modèle)
    return create_react_agent(
        llm,
        _assemble_tools(domain, world),
        prompt=_build_prompt(mission_context),
    )
