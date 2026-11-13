from scope import Scope
from state.world_model import WorldModel
from catalog import load_catalog, technique_by_id
from orchestrator import plan_tasks, route_after_integrate, reconcile_evidence


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
