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


def test_mission_start_reports_network_perimeter_state(tmp_path, monkeypatch, capsys):
    # La porte de mission dit d'emblée si le chemin offensif est utilisable ; un
    # périmètre réseau absent ne refuse PAS la mission (la reconnaissance reste possible).
    import offense.netns as netns
    (tmp_path / "scope.txt").write_text("10.10.10.0/24\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def absent(scope, run=None):
        raise netns.NetnsError("table absente")
    monkeypatch.setattr(netns, "verify", absent)
    out = enter_autonomous_mission({"thread_id": "t_n1"}, {"configurable": {"thread_id": "t_n1"}})
    assert out.get("finished") is not True
    assert "[NETNS] Chemin offensif désactivé : table absente" in capsys.readouterr().out

    monkeypatch.setattr(netns, "verify", lambda scope, run=None: None)
    enter_autonomous_mission({"thread_id": "t_n2"}, {"configurable": {"thread_id": "t_n2"}})
    assert "[NETNS] Périmètre réseau actif (pc-offense)." in capsys.readouterr().out


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


def _llm_tech(**over):
    from catalog.loader import Technique
    base = dict(id="llm.post", name="post", domain="post", service="ssh", requires={"session"},
                tool="echo", command_template="echo {target}", success_signal="ok", provided_by="llm")
    return Technique(**{**base, **over})


def test_resume_carries_the_llm_overlay(monkeypatch):
    # La reprise change de thread_id : la surcouche de techniques LLM de la mission
    # d'origine doit suivre, sinon la technique que l'opérateur vient d'autoriser
    # n'est plus planifiable (et l'auteur ne la réécrit pas : déjà rédigée).
    import orchestrator as orch
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_session(Session(host="127.0.0.1", channel="ssh", authorized=False))
    tech = _llm_tech()
    monkeypatch.setitem(orch._MISSIONS, "prev_o", wm)
    monkeypatch.setitem(orch._MISSION_CATALOG, "prev_o", [tech])
    new_id = orch.resume_with_authorization("prev_o", "127.0.0.1", "127.0.0.1")
    assert tech in orch._effective_catalog(new_id)


def test_resume_skips_the_llm_router(monkeypatch):
    # L'autorisation est consommée AVANT la reprise : celle-ci ne doit pas dépendre
    # d'un classement LLM qui pourrait l'envoyer ailleurs qu'en mission.
    import orchestrator as orch

    class Boom:
        def invoke(self, *_a, **_k):
            raise AssertionError("le routeur LLM ne doit pas être consulté pour une reprise")
    monkeypatch.setattr(orch, "llm", Boom())
    assert orch.master_supervisor({"question": "peu importe", "resume": True}) == "autonomous_mission"
    assert "resume" in orch.MissionState.__annotations__     # canal d'état déclaré


def test_non_mission_turn_does_not_forget_the_last_mission(monkeypatch):
    # « authorize » et « sessions » visent la dernière MISSION : une question posée
    # entre-temps (tour sans monde de mission) ne doit pas la faire oublier.
    import orchestrator as orch
    monkeypatch.setitem(orch._MISSIONS, "m_last", WorldModel(scope=Scope.from_lines(["127.0.0.1/32"])))
    last = ("m_last", "127.0.0.1")
    assert orch._last_mission_after(last, "tour-de-discussion", "127.0.0.1") == last
    assert orch._last_mission_after((None, None), "m_last", "127.0.0.1") == last


def test_mission_start_warns_when_scope_is_loopback(tmp_path, monkeypatch, capsys):
    # 127.0.0.1 dans le périmètre : depuis le namespace c'est SA boucle locale,
    # vide. Le chemin offensif n'atteindra rien — on le dit au lieu d'échouer en silence.
    import offense.netns as netns
    monkeypatch.setattr(netns, "verify", lambda scope, run=None: None)
    (tmp_path / "scope.txt").write_text("127.0.0.1\n10.10.10.0/24\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    enter_autonomous_mission({"thread_id": "t_lo1"}, {"configurable": {"thread_id": "t_lo1"}})
    out = capsys.readouterr().out
    assert "[NETNS] Attention : 127.0.0.1/32" in out and "boucle locale" in out

    (tmp_path / "scope.txt").write_text("10.10.10.0/24\n", encoding="utf-8")
    enter_autonomous_mission({"thread_id": "t_lo2"}, {"configurable": {"thread_id": "t_lo2"}})
    assert "Attention" not in capsys.readouterr().out


class _Store:
    def __init__(self):
        self.calls = []

    def add_texts(self, texts, metadatas=None, ids=None):
        self.calls.append((list(texts), metadatas, ids))


def test_end_of_mission_queues_rag_promotion_for_the_operator(monkeypatch):
    # Rien n'entre dans le RAG partagé sans la commande « promote » : le filtre
    # automatique n'est qu'un pré-tri, il ne sait pas reconnaître toute donnée de cible.
    import orchestrator as orch
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_host("127.0.0.1", hostname="dc01.corp.local")
    generic = _llm_tech(id="llm.g", service="smb", requires=set(), tool="nmap",
                        command_template="nmap -sV -p 445 {target}")
    specific = _llm_tech(id="llm.s", service="smb", requires=set(), tool="nmap",
                         command_template="nmap -sC -p 445 {target}",
                         success_signal="bannière de DC01 visible")
    monkeypatch.setitem(orch._MISSIONS, "m_rag", wm)
    monkeypatch.setitem(orch._MISSION_CATALOG, "m_rag", [generic, specific])
    store = _Store()
    texts = orch.queue_promotion("m_rag")
    assert len(texts) == 1 and "nmap -sV -p 445 {target}" in texts[0]   # le nom de la cible écarte l'autre
    assert store.calls == []                                           # rien d'écrit sans l'opérateur
    assert orch.promote_pending(store=store) == 1 and len(store.calls) == 1
    assert orch.promote_pending(store=store) == 0 and len(store.calls) == 1   # file vidée
