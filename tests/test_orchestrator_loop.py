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


def test_blocked_missing_tool_escalates_and_not_marked_tried(monkeypatch):
    import orchestrator as orch
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
