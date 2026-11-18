import orchestrator as orch
from catalog.loader import _technique_from_dict


def test_effective_catalog_isolated_per_mission(monkeypatch):
    fake = _technique_from_dict({"id": "llm.fake", "service": "smb"})
    monkeypatch.setattr(orch, "_MISSION_CATALOG", {"A": [fake]})
    assert fake in orch._effective_catalog("A")
    assert fake not in orch._effective_catalog("B")


def test_requires_string_not_char_split():
    assert _technique_from_dict({"id": "x", "requires": "credential"}).requires == {"credential"}
