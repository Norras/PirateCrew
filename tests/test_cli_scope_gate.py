from orchestrator import enter_autonomous_mission
from scope import Scope
from state.world_model import WorldModel, Session


def test_mission_refuses_without_scope(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no scope.txt here
    out = enter_autonomous_mission({"thread_id": "t1", "target": "10.10.10.5"},
                                   {"configurable": {"thread_id": "t1"}})
    assert out.get("finished") is True and "scope" in out.get("final_response", "").lower()


def test_mission_starts_with_scope(tmp_path, monkeypatch):
    (tmp_path / "scope.txt").write_text("10.10.10.0/24\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    out = enter_autonomous_mission({"thread_id": "t2", "target": "10.10.10.5"},
                                   {"configurable": {"thread_id": "t2"}})
    assert out.get("finished") is not True


def test_mission_start_reports_network_perimeter_state(tmp_path, monkeypatch, capsys):
    # The mission gate says upfront whether the offensive path is usable; a missing
    # network perimeter does NOT refuse the mission (reconnaissance remains possible).
    import offense.netns as netns
    (tmp_path / "scope.txt").write_text("10.10.10.0/24\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def absent(scope, run=None):
        raise netns.NetnsError("table missing")
    monkeypatch.setattr(netns, "verify", absent)
    out = enter_autonomous_mission({"thread_id": "t_n1"}, {"configurable": {"thread_id": "t_n1"}})
    assert out.get("finished") is not True
    assert "[NETNS] Offensive path disabled: table missing" in capsys.readouterr().out

    monkeypatch.setattr(netns, "verify", lambda scope, run=None: None)
    enter_autonomous_mission({"thread_id": "t_n2"}, {"configurable": {"thread_id": "t_n2"}})
    assert "[NETNS] Network perimeter active (pc-offense)." in capsys.readouterr().out


def test_mission_refusal_clears_stale_active_scope(tmp_path, monkeypatch):
    import scope as scope_mod
    # A scope from a previous mission is still active in the process...
    scope_mod.set_active_scope(scope_mod.Scope.from_lines(["10.10.20.0/24"]))
    monkeypatch.chdir(tmp_path)  # ...but there is no scope.txt here anymore => refusal
    out = enter_autonomous_mission({"thread_id": "t3"},
                                   {"configurable": {"thread_id": "t3"}})
    assert out.get("finished") is True
    assert scope_mod.get_active_scope() is None  # fail-closed: the stale scope is cleared


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
    assert new_id and orch._MISSIONS[new_id] is wm          # same world object
    assert all(s.authorized for s in wm.sessions)           # session authorized
    assert orch.resume_with_authorization("prev", "10.0.0.9", "x") is None  # nothing to authorize


def _llm_tech(**over):
    from catalog.loader import Technique
    base = dict(id="llm.post", name="post", domain="post", service="ssh", requires={"session"},
                tool="echo", command_template="echo {target}", success_signal="ok", provided_by="llm")
    return Technique(**{**base, **over})


def test_resume_carries_the_llm_overlay(monkeypatch):
    # The resume changes thread_id: the LLM technique overlay of the original
    # mission must follow, otherwise the technique the operator just authorized
    # is no longer plannable (and the author does not rewrite it: already written).
    import orchestrator as orch
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_session(Session(host="127.0.0.1", channel="ssh", authorized=False))
    tech = _llm_tech()
    monkeypatch.setitem(orch._MISSIONS, "prev_o", wm)
    monkeypatch.setitem(orch._MISSION_CATALOG, "prev_o", [tech])
    new_id = orch.resume_with_authorization("prev_o", "127.0.0.1", "127.0.0.1")
    assert tech in orch._effective_catalog(new_id)


def test_resume_skips_the_llm_router(monkeypatch):
    # The authorization is consumed BEFORE the resume: the resume must not depend on
    # an LLM classification that could send it somewhere other than a mission.
    import orchestrator as orch

    class Boom:
        def invoke(self, *_a, **_k):
            raise AssertionError("the LLM router must not be consulted for a resume")
    monkeypatch.setattr(orch, "llm", Boom())
    assert orch.master_supervisor({"question": "whatever", "resume": True}) == "autonomous_mission"
    assert "resume" in orch.MissionState.__annotations__     # state channel declared


def test_non_mission_turn_does_not_forget_the_last_mission(monkeypatch):
    # "authorize" and "sessions" target the last MISSION: a question asked in
    # between (turn without a mission world) must not make it forgotten.
    import orchestrator as orch
    monkeypatch.setitem(orch._MISSIONS, "m_last", WorldModel(scope=Scope.from_lines(["127.0.0.1/32"])))
    last = ("m_last", "127.0.0.1")
    assert orch._last_mission_after(last, "chat-turn", "127.0.0.1") == last
    assert orch._last_mission_after((None, None), "m_last", "127.0.0.1") == last


def test_mission_start_warns_when_scope_is_loopback(tmp_path, monkeypatch, capsys):
    # 127.0.0.1 in the scope: from inside the namespace it is ITS OWN loopback,
    # empty. The offensive path will reach nothing — we say so instead of failing silently.
    import offense.netns as netns
    monkeypatch.setattr(netns, "verify", lambda scope, run=None: None)
    (tmp_path / "scope.txt").write_text("127.0.0.1\n10.10.10.0/24\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    enter_autonomous_mission({"thread_id": "t_lo1"}, {"configurable": {"thread_id": "t_lo1"}})
    out = capsys.readouterr().out
    assert "[NETNS] Warning: 127.0.0.1/32" in out and "loopback" in out

    (tmp_path / "scope.txt").write_text("10.10.10.0/24\n", encoding="utf-8")
    enter_autonomous_mission({"thread_id": "t_lo2"}, {"configurable": {"thread_id": "t_lo2"}})
    assert "Attention" not in capsys.readouterr().out


class _Store:
    def __init__(self):
        self.calls = []

    def add_texts(self, texts, metadatas=None, ids=None):
        self.calls.append((list(texts), metadatas, ids))


def test_end_of_mission_queues_rag_promotion_for_the_operator(monkeypatch):
    # Nothing enters the shared RAG without the "promote" command: the automatic
    # filter is only a pre-screen, it cannot recognize every piece of target data.
    import orchestrator as orch
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_host("127.0.0.1", hostname="dc01.corp.local")
    generic = _llm_tech(id="llm.g", service="smb", requires=set(), tool="nmap",
                        command_template="nmap -sV -p 445 {target}")
    specific = _llm_tech(id="llm.s", service="smb", requires=set(), tool="nmap",
                         command_template="nmap -sC -p 445 {target}",
                         success_signal="DC01 banner visible")
    monkeypatch.setitem(orch._MISSIONS, "m_rag", wm)
    monkeypatch.setitem(orch._MISSION_CATALOG, "m_rag", [generic, specific])
    store = _Store()
    texts = orch.queue_promotion("m_rag")
    assert len(texts) == 1 and "nmap -sV -p 445 {target}" in texts[0]   # the target name rules out the other
    assert store.calls == []                                           # nothing written without the operator
    assert orch.promote_pending(store=store) == 1 and len(store.calls) == 1
    assert orch.promote_pending(store=store) == 0 and len(store.calls) == 1   # queue emptied
