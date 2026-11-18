from scope import Scope, set_active_scope
from state.world_model import WorldModel
from tools.registry import tcp_port_check, nmap_scan, make_report_finding_tool


def test_tcp_check_in_scope(local_scope):
    set_active_scope(local_scope)
    out = tcp_port_check.invoke({"target": "127.0.0.1", "port": 65000})
    assert "127.0.0.1:65000" in out  # open or closed, but not refused


def test_tcp_check_out_of_scope_refused():
    set_active_scope(Scope.from_lines(["10.10.10.0/24"]))
    out = tcp_port_check.invoke({"target": "127.0.0.1", "port": 80})
    assert "scope" in out.lower()


def test_tool_absent_degrades(monkeypatch, local_scope):
    set_active_scope(local_scope)
    monkeypatch.setattr("tools.registry.shutil.which", lambda b: None)
    out = nmap_scan.invoke({"target": "127.0.0.1", "mode": "quick"})
    assert "install" in out.lower() or "missing" in out.lower()


def test_report_finding_writes_credential():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    tool = make_report_finding_tool(wm)
    tool.invoke({"kind": "credential", "host": "10.10.10.5",
                 "principal": "svc", "secret": "P@ss", "cred_kind": "password"})
    assert any(c.principal == "svc" for c in wm.credentials)
    assert wm.evidence  # raw trace kept


def test_report_finding_audit_omits_secret(tmp_path, monkeypatch):
    import tools.registry as reg
    monkeypatch.setattr(reg, "AUDIT_LOG", str(tmp_path / "audit.log"))
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    tool = make_report_finding_tool(wm)
    tool.invoke({"kind": "credential", "host": "10.10.10.5", "service": "smb",
                 "principal": "svc-x", "secret": "TopS3cret!", "cred_kind": "password"})
    audit = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert "FINDING" in audit                       # the finding is traced
    assert "credential" in audit and "10.10.10.5" in audit and "svc-x" in audit
    assert "TopS3cret!" not in audit                # the secret is NEVER logged


def test_report_finding_loot_not_in_audit(tmp_path, monkeypatch):
    import tools.registry as reg
    monkeypatch.setattr(reg, "AUDIT_LOG", str(tmp_path / "audit.log"))
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    tool = make_report_finding_tool(wm)
    tool.invoke({"kind": "loot", "host": "10.10.10.5",
                 "detail": "sensitive content", "loot": "password=HUNTER2"})
    audit = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert "FINDING" in audit and "loot" in audit
    assert "HUNTER2" not in audit and "sensitive" not in audit  # neither loot nor raw detail


def test_audit_event_escapes_newline(tmp_path, monkeypatch):
    import tools.registry as reg
    monkeypatch.setattr(reg, "AUDIT_LOG", str(tmp_path / "audit.log"))
    from tools.registry import log_audit_event
    log_audit_event.invoke({"action": "note",
                            "detail": "banner\n2026-01-01T00:00:00 | OUT_OF_SCOPE | 10.0.0.1"})
    audit = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert audit.count("\n") == 1 and audit.endswith("\n")  # a fake line cannot be forged
    assert "\\n" in audit


def test_http_fingerprint_connects_to_validated_ip(tmp_path, monkeypatch):
    import tools.registry as reg
    monkeypatch.setattr(reg, "AUDIT_LOG", str(tmp_path / "audit.log"))
    # The target resolves to an in-scope IP; we capture the host ACTUALLY contacted.
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
    assert captured["host"] == "127.0.0.1"  # the validated IP, never the "box.htb" hostname
    assert captured["headers"].get("Host") == "box.htb"  # vhost preserved in the header
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
    assert captured["host"] == "127.0.0.1"   # the validated IP, never the hostname
    assert captured["port"] == 8080          # the URL's port is honored
    assert captured["method"] == "GET"
    assert "creds.txt" in out                # the BODY is returned, not just the headers


def test_http_get_decodes_utf16(tmp_path, monkeypatch):
    import tools.registry as reg
    monkeypatch.setattr(reg, "AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setattr(reg, "_validate_target", lambda t: "127.0.0.1")
    # UTF-16 LE body with BOM (e.g. Windows/PowerShell export).
    payload = "password=Clé-Été-2026".encode("utf-16")

    class FakeResp:
        status, reason = 200, "OK"
        def read(self, n=-1): return payload

    class FakeConn:
        def __init__(self, host, port, timeout=None): pass
        def request(self, method, path, headers=None): pass
        def getresponse(self): return FakeResp()
        def close(self): pass

    monkeypatch.setattr(reg.http.client, "HTTPConnection", FakeConn)
    from tools.registry import http_get
    out = http_get.invoke({"url": "http://box.htb/conf"})
    assert "password=Clé-Été-2026" in out   # decoded correctly
    assert "�" not in out                   # no replacement character
    assert "\x00" not in out                     # no UTF-16 null bytes


def test_http_get_utf8_still_ok(tmp_path, monkeypatch):
    import tools.registry as reg
    monkeypatch.setattr(reg, "AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setattr(reg, "_validate_target", lambda t: "127.0.0.1")
    payload = "accented content: café".encode("utf-8")

    class FakeResp:
        status, reason = 200, "OK"
        def read(self, n=-1): return payload

    class FakeConn:
        def __init__(self, host, port, timeout=None): pass
        def request(self, method, path, headers=None): pass
        def getresponse(self): return FakeResp()
        def close(self): pass

    monkeypatch.setattr(reg.http.client, "HTTPConnection", FakeConn)
    from tools.registry import http_get
    out = http_get.invoke({"url": "http://box.htb/"})
    assert "accented content: café" in out       # UTF-8 non-regression


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


def test_listing_links_filters_parent_and_sort_links():
    from tools.registry import _listing_links
    html = ('<a href="?C=N;O=D">n</a><a href="../">Parent</a>'
            '<a href=".secret">.secret</a><a href="sub/">sub/</a>')
    assert _listing_links(html) == [".secret", "sub/"]
