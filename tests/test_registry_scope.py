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


def test_audit_event_escapes_newline(tmp_path, monkeypatch):
    import tools.registry as reg
    monkeypatch.setattr(reg, "AUDIT_LOG", str(tmp_path / "audit.log"))
    from tools.registry import log_audit_event
    log_audit_event.invoke({"action": "note",
                            "detail": "banner\n2026-01-01T00:00:00 | OUT_OF_SCOPE | 10.0.0.1"})
    audit = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert audit.count("\n") == 1 and audit.endswith("\n")  # une fausse ligne ne peut être forgée
    assert "\\n" in audit


def test_http_fingerprint_connects_to_validated_ip(tmp_path, monkeypatch):
    import tools.registry as reg
    monkeypatch.setattr(reg, "AUDIT_LOG", str(tmp_path / "audit.log"))
    # La cible résout vers une IP in-scope ; on capture l'hôte RÉELLEMENT contacté.
    monkeypatch.setattr(reg, "_validate_target", lambda t: "127.0.0.1")
    captured = {}

    class FakeResp:
        status, reason = 200, "OK"
        def getheaders(self): return [("Server", "nginx")]

    class FakeConn:
        def __init__(self, host, port, timeout=None):
            captured["host"] = host
            captured["port"] = port
        def request(self, method, path, headers=None):
            captured["path"] = path
            captured["headers"] = headers or {}
        def getresponse(self): return FakeResp()
        def close(self): pass

    monkeypatch.setattr(reg.http.client, "HTTPConnection", FakeConn)
    from tools.registry import http_fingerprint
    out = http_fingerprint.invoke({"url": "http://box.htb/admin"})
    assert captured["host"] == "127.0.0.1"  # l'IP validée, jamais le hostname "box.htb"
    assert captured["headers"].get("Host") == "box.htb"  # vhost préservé dans l'en-tête
    assert "200" in out


def test_http_get_returns_body(tmp_path, monkeypatch):
    import tools.registry as reg
    monkeypatch.setattr(reg, "AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setattr(reg, "_validate_target", lambda t: "127.0.0.1")
    captured = {}

    class FakeResp:
        status, reason = 200, "OK"
        def read(self, n=-1): return b"<a href='creds.txt'>creds.txt</a>"

    class FakeConn:
        def __init__(self, host, port, timeout=None):
            captured["host"] = host
            captured["port"] = port
        def request(self, method, path, headers=None):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers or {}
        def getresponse(self): return FakeResp()
        def close(self): pass

    monkeypatch.setattr(reg.http.client, "HTTPConnection", FakeConn)
    from tools.registry import http_get
    out = http_get.invoke({"url": "http://box.htb:8080/"})
    assert captured["host"] == "127.0.0.1"   # l'IP validée, jamais le hostname
    assert captured["port"] == 8080          # le port de l'URL est respecté
    assert captured["method"] == "GET"
    assert "creds.txt" in out                # le CORPS est renvoyé, pas juste les en-têtes


def test_smb_list_shares_builds_argv(monkeypatch, local_scope):
    from scope import set_active_scope
    set_active_scope(local_scope)
    import tools.registry as reg
    captured = {}

    def fake_run(cmd, timeout=120):
        captured["cmd"] = cmd
        return "Sharename      Type\n---------\nIPC$           IPC"

    monkeypatch.setattr(reg, "_run", fake_run)
    from tools.registry import smb_list_shares
    out = smb_list_shares.invoke({"target": "127.0.0.1"})
    assert captured["cmd"][0] == "smbclient" and "-L" in captured["cmd"]
    assert "//127.0.0.1" in captured["cmd"]
    assert "IPC$" in out
