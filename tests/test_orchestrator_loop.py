from scope import Scope
from state.world_model import WorldModel
from catalog import load_catalog, technique_by_id
from orchestrator import (plan_tasks, route_after_integrate, reconcile_evidence,
                          _parse_services, _task_inputs_fp)
from state.world_model import Credential


def test_plan_tasks_filters_by_requires_and_ledger():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    wm.add_host("10.10.10.5")
    wm.add_service("10.10.10.5", 445, name="smb")
    cat = load_catalog()
    tasks = plan_tasks(wm, cat)
    assert any(t["service"] == "smb" for t in tasks)          # technique sans requires proposée
    # une technique exigeant un cred n'apparaît pas tant qu'aucun cred applicable
    assert all("credential" not in technique_by_id(cat, t["technique_id"]).requires
               for t in tasks)


def test_route_finishes_on_cycle_cap():
    assert route_after_integrate({"cycle": 6, "max_cycles": 6}) == "finish"


def test_integrate_captures_raw_evidence():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    n = reconcile_evidence(wm, "Found creds admin:Password1 on 10.10.10.5")
    assert n >= 1 and any(c.principal == "admin" for c in wm.credentials)


def test_out_of_scope_discovery_not_tasked():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    wm.add_host("8.8.8.8")  # découverte hors périmètre
    assert "8.8.8.8" not in [t["host"] for t in plan_tasks(wm, load_catalog())]


def test_parse_services_ignores_substrings_and_closed_ports():
    # Un numéro de version/netmask ne doit pas créer de service par sous-chaîne,
    # et une énumération de ports fermés non plus.
    assert _parse_services("Apache/2.2.15 built 2021") == []        # "2021" != port 21
    assert _parse_services("Netmask 255.255.255.0") == []
    assert _parse_services("Host down. Checked 21,22,80,445 - none open.") == []


def test_parse_services_detects_open_services():
    txt = "PORT   STATE SERVICE\n445/tcp open  microsoft-ds\n80/tcp open http"
    svc = _parse_services(txt)
    assert "smb" in svc and "http" in svc


def test_reconcile_requires_credential_cue():
    # Prose ordinaire 'mot:valeur' SANS indice de credential => aucun faux secret.
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    reconcile_evidence(wm, "Server:nginx\nHost:10.10.10.9\nDomain:WORKGROUP")
    assert wm.credentials == []


def test_task_inputs_fp_changes_when_new_cred_discovered():
    # R2 : un nouveau credential applicable change l'empreinte => technique ré-ouverte.
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    wm.add_credential(Credential(kind="password", principal="svcA", secret="a", source="t"))
    fp1 = _task_inputs_fp(wm, "smb", {"credential"})
    wm.add_credential(Credential(kind="password", principal="svcB", secret="b", source="t"))
    fp2 = _task_inputs_fp(wm, "smb", {"credential"})
    assert fp1 and fp2 and fp1 != fp2


def test_task_inputs_fp_empty_without_credential_requirement():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    assert _task_inputs_fp(wm, "smb", set()) == ""


# --- Milestone 1 : propagation de port + escalade « outil manquant » (Option Y) --- #
def test_plan_task_carries_service_port():
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 8080, name="http")
    http_tasks = [t for t in plan_tasks(wm, load_catalog()) if t["service"] == "http"]
    assert http_tasks and all(t.get("port") == 8080 for t in http_tasks)


def test_technique_available_python_vs_missing_binary(monkeypatch):
    import orchestrator as orch
    cat = load_catalog()
    assert orch.technique_available(technique_by_id(cat, "http.fingerprint")) is True
    monkeypatch.setattr(orch.shutil, "which", lambda b: None)
    assert orch.technique_available(technique_by_id(cat, "smb.enum_shares")) is False


def test_render_template_fills_target_and_port():
    import orchestrator as orch
    assert orch._render_template("x http://{target}:{port}/", "127.0.0.1", 8080) == "x http://127.0.0.1:8080/"
    assert orch._render_template("", "127.0.0.1", 80) == ""


def _patch_fake_agent(monkeypatch):
    class _Msg:
        content = "OK (fake)"

    class _FakeAgent:
        def invoke(self, _):
            return {"messages": [_Msg()]}

    monkeypatch.setattr("agents.dynamic_agent.build_task_agent",
                        lambda domain, world=None, mission_context="": _FakeAgent())


def test_blocked_missing_tool_escalates_and_not_marked_tried(monkeypatch, tmp_path):
    import orchestrator as orch
    from state import mission_io
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    _patch_fake_agent(monkeypatch)
    monkeypatch.setattr(orch.shutil, "which", lambda b: None)  # smbclient absent
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_block"] = wm
    cfg = {"configurable": {"thread_id": "t_block"}}
    planned = plan_tasks(wm, orch._CATALOG)
    reports = orch.node_execute({"planned": planned}, cfg)["execution_reports"]
    assert any(r["status"] == "blocked_missing_tool" and r["tool"] == "smbclient" for r in reports)
    out = orch.node_integrate({"planned": planned, "execution_reports": reports, "cycle": 0}, cfg)
    assert "smbclient" in out["final_response"]
    # bloquée => NON marquée (replanifiable après install) ; exécutée => marquée
    assert wm.is_tried("127.0.0.1", "smb", "smb.enum_shares", inputs_fp="", port=445) is False
    assert wm.is_tried("127.0.0.1", "smb", "smb.port_probe", inputs_fp="", port=445) is True


def test_route_finishes_when_only_blocked_tasks_remain(monkeypatch):
    import orchestrator as orch
    monkeypatch.setattr(orch.shutil, "which", lambda b: None)  # smbclient absent
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    wm.mark_technique("127.0.0.1", "smb", "smb.port_probe", inputs_fp="", port=445)
    orch._MISSIONS["t_route_block"] = wm
    assert route_after_integrate({"cycle": 1, "max_cycles": 6, "thread_id": "t_route_block"}) == "finish"


def test_route_continues_when_runnable_task_remains():
    import orchestrator as orch
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 80, name="http")
    orch._MISSIONS["t_route_cont"] = wm
    assert route_after_integrate({"cycle": 1, "max_cycles": 6, "thread_id": "t_route_cont"}) == "continue"


def test_start_mission_reuses_worldmodel_on_same_thread():
    import orchestrator as orch
    sc = Scope.from_lines(["127.0.0.1/32"])
    w1 = orch.start_mission("t_reuse", sc)
    w1.mark_technique("127.0.0.1", "smb", "smb.port_probe", inputs_fp="", port=445)
    w2 = orch.start_mission("t_reuse", sc)
    assert w2 is w1 and w2.is_tried("127.0.0.1", "smb", "smb.port_probe", inputs_fp="", port=445) is True
    assert orch.start_mission("t_other_thread", sc) is not w1


def test_requested_ports_host_port():
    from orchestrator import requested_ports
    assert requested_ports("fais une analyse sur 127.0.0.1:8980") == [8980]


def test_requested_ports_word_port():
    from orchestrator import requested_ports
    assert requested_ports("vérifie le port 8980") == [8980]


def test_requested_ports_none():
    from orchestrator import requested_ports
    assert requested_ports("analyse tout le périmètre autorisé") == []


def test_requested_ports_out_of_range():
    from orchestrator import requested_ports
    assert requested_ports("port 99999") == []


def _services_named(wm, host, port):
    return [s.name for h in wm.in_scope_hosts() if h.ip == host
            for s in h.services if s.port == port]


def test_discover_services_fingerprint_names_unusual_port():
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    n = discover_services(wm, ["127.0.0.1"], [80, 8980],
                          probe=lambda h, p: p == 8980,
                          fingerprint=lambda h, p: "http")
    assert n == 1
    assert _services_named(wm, "127.0.0.1", 8980) == ["http"]


def test_discover_services_known_port_uses_mapping():
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    discover_services(wm, ["127.0.0.1"], [80, 8980], probe=lambda h, p: p == 80)
    assert _services_named(wm, "127.0.0.1", 80) == ["http"]


def test_discover_services_nothing_open():
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    n = discover_services(wm, ["127.0.0.1"], [80, 8980], probe=lambda h, p: False)
    assert n == 0
    assert [s for h in wm.in_scope_hosts() for s in h.services] == []


def test_reconcile_credential_on_line_after_cue():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    reconcile_evidence(wm, "Cred for DC :\nDamulsan:AAJJAQBenough1728!")
    assert any(c.principal == "Damulsan" and c.secret == "AAJJAQBenough1728!"
               for c in wm.credentials)


def test_reconcile_no_cue_word_adds_no_credential():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    reconcile_evidence(wm, "Server:nginx\nHost:10.0.0.1")
    assert len(wm.credentials) == 0


def test_reconcile_ignores_header_like_value_near_cue():
    # Un en-tête compact « Clé:valeur » dans la fenêtre d'un indice ne doit PAS
    # devenir un faux credential (garde anti-fabrication, cf. « Server:nginx »).
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    reconcile_evidence(wm, "Password policy:\nServer:nginx")
    assert len(wm.credentials) == 0


def test_discover_services_logs_each_open_port():
    # Mode verbose : un callback `log` reçoit une ligne par port ouvert (et aucune
    # pour les ports fermés), avec l'hôte, le port et le service détecté.
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    msgs = []
    discover_services(wm, ["127.0.0.1"], [80, 8980],
                      probe=lambda h, p: p == 8980,
                      fingerprint=lambda h, p: "http",
                      log=msgs.append)
    assert len(msgs) == 1
    assert "8980" in msgs[0] and "http" in msgs[0]


def test_vprint_respects_verbose_flag(capsys):
    # _vprint n'imprime que lorsque le mode verbose est actif ; set_verbose bascule.
    import orchestrator as orch
    orch.set_verbose(False)
    orch._vprint("caché")
    assert capsys.readouterr().out == ""
    orch.set_verbose(True)
    orch._vprint("visible")
    assert "visible" in capsys.readouterr().out
    orch.set_verbose(False)  # restaure l'état global


def test_wants_full_scan_detects_phrases():
    # Reconnaît une intention de balayage COMPLET ; ignore un port explicite ou le
    # simple mot « tout » (périmètre) sans « ports ».
    from orchestrator import wants_full_scan
    assert wants_full_scan("scanne tous les ports") is True
    assert wants_full_scan("fais un scan complet de 127.0.0.1") is True
    assert wants_full_scan("attaque 127.0.0.1:8980") is False
    assert wants_full_scan("analyse tout le périmètre autorisé") is False


def test_discover_services_parallel_finds_open_ports():
    # Sondage parallèle (workers>1) : trouve les mêmes ports ouverts, résultat
    # déterministe, enregistrement séquentiel dans le WorldModel.
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    opened = {22, 8980}
    n = discover_services(wm, ["127.0.0.1"], [22, 80, 8980],
                          probe=lambda h, p: p in opened,
                          workers=4)
    assert n == 2
    ports_found = sorted(s.port for h in wm.in_scope_hosts() for s in h.services)
    assert ports_found == [22, 8980]


def test_autonomous_discovery_escalates_on_empty_host():
    from orchestrator import autonomous_discovery
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    # rien sur les ports par défaut ; un service sur un port haut hors défaut
    probe = lambda h, p: p == 50000
    n = autonomous_discovery(wm, ["127.0.0.1"], [80, 443], probe=probe,
                             fingerprint=lambda h, p: "http")
    assert n == 1
    assert any(s.port == 50000 and s.name == "http"
               for h in wm.in_scope_hosts() for s in h.services)


def test_autonomous_discovery_no_escalation_when_service_found():
    from orchestrator import autonomous_discovery
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    probe = lambda h, p: p in (80, 50000)   # 80 est dans les défauts
    autonomous_discovery(wm, ["127.0.0.1"], [80], probe=probe)
    ports = sorted(s.port for h in wm.in_scope_hosts() for s in h.services)
    assert ports == [80]  # pas d'escalade → 50000 jamais sondé/enregistré


def test_node_integrate_persists_world_each_cycle(tmp_path, monkeypatch):
    import orchestrator as orch
    from state import mission_io
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    sc = Scope.from_lines(["127.0.0.1/32"])
    orch.start_mission("mX", sc)
    state = {"execution_reports": [], "cycle": 0, "thread_id": "mX"}
    orch.node_integrate(state, {"configurable": {"thread_id": "mX"}})
    assert (tmp_path / "mX" / "world.json").exists()
