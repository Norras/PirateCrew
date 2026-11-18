"""Task agent factory (Factory pattern).

`build_task_agent(domain, world, mission_context)` assembles a React agent with:
- the MANDATORY tools (audit + scope check), always present;
- the CONDITIONAL tools of the requested domain ('network', 'web', 'ad');
- the `report_finding` tool bound to the world model, if a `world` is provided.

The returned agent is invoked with:
    agent.invoke({"messages": [("user", "...")]})
and the answer is read from result["messages"][-1].content
"""
from __future__ import annotations

from dotenv import load_dotenv
from langgraph.prebuilt import create_react_agent
from langchain_anthropic import ChatAnthropic

from tools.registry import MANDATORY_TOOLS, TOOL_CATALOG, make_report_finding_tool

load_dotenv()

_BASE_PROMPT = (
    "You are a PirateCrew task agent, dedicated to AUTHORIZED pentesting. You use "
    "only the tools provided to scout, enumerate and attack targets that "
    "the user is authorized to audit (lab, VM, consented scope), and ONLY "
    "within the authorization scope — if in doubt about a target, use "
    "scope_check. Log your steps through the audit tool. Report EVERY finding "
    "(service, credential, session, loot) through the report_finding tool, in a structured way. "
    "Answer concisely and factually."
)


def _build_prompt(mission_context: str = "") -> str:
    """Agent system prompt, enriched with the mission context when provided
    (objective, applicable credentials, untried techniques, RAG excerpts)."""
    if not mission_context:
        return _BASE_PROMPT
    return f"{_BASE_PROMPT}\n\n=== MISSION CONTEXT ===\n{mission_context}"


def _assemble_tools(domain: str, world=None) -> list:
    """Build the tool list: mandatory + domain (+ report_finding
    bound to the world model if `world` is provided). Pure function, testable
    without an LLM."""
    tools = list(MANDATORY_TOOLS) + list(TOOL_CATALOG.get(domain, []))
    if world is not None:
        tools.append(make_report_finding_tool(world))
    return tools


def build_task_agent(domain: str, world=None, mission_context: str = ""):
    """Build a React agent for the given domain.

    domain: 'network', 'web' or 'ad'. An unknown domain gets only the
    mandatory tools. `world`: world model to feed through
    `report_finding` (None = no structured reporting). `mission_context`:
    text injected into the system prompt. Backward compatible:
    `build_task_agent("network")` still works.
    """
    llm = ChatAnthropic(model="claude-sonnet-4-6")  # no temperature (rejected by the model)
    return create_react_agent(
        llm,
        _assemble_tools(domain, world),
        prompt=_build_prompt(mission_context),
    )
