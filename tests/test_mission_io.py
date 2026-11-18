import json
from pathlib import Path
from scope import Scope
from state.world_model import WorldModel, Credential, Session
from state import mission_io


def test_new_mission_id_sanitises_target():
    mid = mission_io.new_mission_id("127.0.0.1")
    assert mid.startswith("127.0.0.1-") and ":" not in mid and "/" not in mid
    assert ":" not in mission_io.new_mission_id("fe80::1")  # IPv6 sanitized


def test_save_world_writes_json(tmp_path):
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    wm.add_credential(Credential(kind="password", principal="admin", secret="pw123"))
    p = mission_io.save_world(wm, "m1", root=tmp_path)
    assert p == tmp_path / "m1" / "world.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["credentials"][0]["secret"] == "pw123"


def test_gitignore_excludes_missions():
    gi = (Path(__file__).resolve().parent.parent / ".gitignore").read_text(encoding="utf-8")
    assert "missions/" in gi


def test_render_report_lists_findings():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    wm.add_service("10.10.10.5", 445, name="smb")
    wm.add_credential(Credential(kind="password", principal="admin", secret="pw123"))
    wm.add_session(Session(host="10.10.10.5", channel="evil-winrm"))  # authorized=False
    md = mission_io.render_report(wm)
    for token in ("10.10.10.5", "445", "smb", "admin", "pw123"):
        assert token in md
    assert "pending" in md.lower()  # unauthorized session


def test_save_report_writes_markdown(tmp_path):
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    p = mission_io.save_report(wm, "m1", root=tmp_path)
    assert p == tmp_path / "m1" / "report.md"
    assert p.read_text(encoding="utf-8") == mission_io.render_report(wm)
