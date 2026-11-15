import json
from pathlib import Path
from scope import Scope
from state.world_model import WorldModel, Credential
from state import mission_io


def test_new_mission_id_sanitises_target():
    mid = mission_io.new_mission_id("127.0.0.1")
    assert mid.startswith("127.0.0.1-") and ":" not in mid and "/" not in mid
    assert ":" not in mission_io.new_mission_id("fe80::1")  # IPv6 assaini


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
