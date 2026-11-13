from scope import Scope, set_active_scope
from state.world_model import WorldModel
from tools.registry import tcp_port_check, nmap_scan, make_report_finding_tool


def test_tcp_check_in_scope(local_scope):
    set_active_scope(local_scope)
    out = tcp_port_check.invoke({"target": "127.0.0.1", "port": 65000})
    assert "127.0.0.1:65000" in out  # ouvert ou fermé, mais pas refusé


def test_tcp_check_out_of_scope_refused():
    set_active_scope(Scope.from_lines(["10.10.10.0/24"]))
    out = tcp_port_check.invoke({"target": "127.0.0.1", "port": 80})
    assert "périmètre" in out.lower() or "scope" in out.lower()


def test_tool_absent_degrades(monkeypatch, local_scope):
    set_active_scope(local_scope)
    monkeypatch.setattr("tools.registry.shutil.which", lambda b: None)
    out = nmap_scan.invoke({"target": "127.0.0.1", "mode": "quick"})
    assert "install" in out.lower() or "absent" in out.lower()


def test_report_finding_writes_credential():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    tool = make_report_finding_tool(wm)
    tool.invoke({"kind": "credential", "host": "10.10.10.5",
                 "principal": "svc", "secret": "P@ss", "cred_kind": "password"})
    assert any(c.principal == "svc" for c in wm.credentials)
    assert wm.evidence  # trace brute conservée
