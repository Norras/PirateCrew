from scope import Scope
from state.world_model import WorldModel
from agents.dynamic_agent import _assemble_tools, _build_prompt


def test_tools_include_report_finding_when_world_given():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    names = [getattr(t, "name", "") for t in _assemble_tools("ad", wm)]
    assert "report_finding" in names and "log_audit_event" in names


def test_tools_without_world_have_no_report_finding():
    names = [getattr(t, "name", "") for t in _assemble_tools("ad", None)]
    assert "report_finding" not in names


def test_prompt_embeds_mission_context():
    p = _build_prompt("OBJECTIF: enum SMB; CREDS: svc:P@ss")
    assert "OBJECTIF: enum SMB" in p
