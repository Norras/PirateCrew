from orchestrator import enter_autonomous_mission


def test_mission_refuses_without_scope(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # pas de scope.txt ici
    out = enter_autonomous_mission({"thread_id": "t1", "target": "10.10.10.5"},
                                   {"configurable": {"thread_id": "t1"}})
    assert out.get("finished") is True and "périmètre" in out.get("final_response", "").lower()


def test_mission_starts_with_scope(tmp_path, monkeypatch):
    (tmp_path / "scope.txt").write_text("10.10.10.0/24\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    out = enter_autonomous_mission({"thread_id": "t2", "target": "10.10.10.5"},
                                   {"configurable": {"thread_id": "t2"}})
    assert out.get("finished") is not True
