from orchestrator import enter_autonomous_mission
from scope import Scope
from state.world_model import WorldModel, Session


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


def test_mission_refusal_clears_stale_active_scope(tmp_path, monkeypatch):
    import scope as scope_mod
    # Un périmètre d'une mission précédente est encore actif dans le processus...
    scope_mod.set_active_scope(scope_mod.Scope.from_lines(["10.10.20.0/24"]))
    monkeypatch.chdir(tmp_path)  # ...mais plus aucun scope.txt ici => refus
    out = enter_autonomous_mission({"thread_id": "t3"},
                                   {"configurable": {"thread_id": "t3"}})
    assert out.get("finished") is True
    assert scope_mod.get_active_scope() is None  # fail-closed : le périmètre périmé est effacé


def test_pending_sessions_lists_unauthorized_alive():
    import orchestrator as orch
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_session(Session(host="127.0.0.1", channel="evil-winrm", authorized=False))
    wm.add_session(Session(host="127.0.0.1", channel="ssh", authorized=True))
    pend = orch._pending_sessions(wm)
    assert len(pend) == 1 and pend[0].channel == "evil-winrm"


def test_resume_reuses_world_and_authorizes(monkeypatch):
    import orchestrator as orch
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_session(Session(host="127.0.0.1", channel="evil-winrm", authorized=False))
    orch._MISSIONS["prev"] = wm
    new_id = orch.resume_with_authorization("prev", "127.0.0.1", "127.0.0.1")
    assert new_id and orch._MISSIONS[new_id] is wm          # même objet monde
    assert all(s.authorized for s in wm.sessions)           # session autorisée
    assert orch.resume_with_authorization("prev", "10.0.0.9", "x") is None  # rien à autoriser
