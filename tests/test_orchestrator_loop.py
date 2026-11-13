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
