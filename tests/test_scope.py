from pathlib import Path

import pytest

import scope
from scope import Scope, ScopeError, assert_in_scope, load_scope, set_active_scope


def test_load_scope_missing_file_raises(tmp_path):
    with pytest.raises(ScopeError):
        load_scope(str(tmp_path / "nope.txt"))


def test_load_scope_empty_raises(tmp_path):
    p = tmp_path / "scope.txt"; p.write_text("\n# comment\n", encoding="utf-8")
    with pytest.raises(ScopeError):
        load_scope(str(p))


def test_cidr_membership():
    s = Scope.from_lines(["10.10.10.0/24"])
    assert s.contains("10.10.10.5") is True
    assert s.contains("10.10.11.5") is False


def test_assert_in_scope_fail_closed_without_active_scope():
    set_active_scope(None)
    with pytest.raises(ScopeError):
        assert_in_scope("10.10.10.5")


def test_assert_in_scope_accepts_in_and_refuses_out():
    set_active_scope(Scope.from_lines(["10.10.10.0/24"]))
    assert assert_in_scope("10.10.10.5") == "10.10.10.5"
    with pytest.raises(ScopeError):
        assert_in_scope("1.1.1.1")


def test_hostname_resolved_then_checked(monkeypatch):
    monkeypatch.setattr("scope.socket.gethostbyname", lambda h: "10.10.10.9")
    set_active_scope(Scope.from_lines(["10.10.10.0/24"]))
    assert assert_in_scope("box.htb") == "10.10.10.9"


def test_unresolvable_target_refused(monkeypatch):
    def boom(h): raise OSError("no dns")
    monkeypatch.setattr("scope.socket.gethostbyname", boom)
    set_active_scope(Scope.from_lines(["10.10.10.0/24"]))
    with pytest.raises(ScopeError):
        assert_in_scope("ghost.invalid")


def test_out_of_scope_is_audited():
    set_active_scope(Scope.from_lines(["10.10.10.0/24"]))
    with pytest.raises(ScopeError):
        assert_in_scope("8.8.8.8")
    audit = Path(scope.AUDIT_LOG).read_text(encoding="utf-8")
    assert "| OUT_OF_SCOPE | 8.8.8.8\n" in audit


def test_from_lines_rejects_host_bits():
    with pytest.raises(ScopeError):
        Scope.from_lines(["10.10.10.5/24"])


def test_from_lines_rejects_garbage():
    with pytest.raises(ScopeError):
        Scope.from_lines(["garbage"])


def test_audit_line_escapes_newline(monkeypatch):
    def boom(h): raise OSError("no dns")
    monkeypatch.setattr("scope.socket.gethostbyname", boom)
    set_active_scope(Scope.from_lines(["10.10.10.0/24"]))
    with pytest.raises(ScopeError):
        assert_in_scope("1.1.1.1\nFAKE")
    audit = Path(scope.AUDIT_LOG).read_text(encoding="utf-8")
    assert audit.count("\n") == 1 and audit.endswith("\n")
    assert audit.rstrip("\n").endswith("| OUT_OF_SCOPE | 1.1.1.1\\nFAKE")


def test_hosts_single_address():
    assert Scope.from_lines(["127.0.0.1/32"]).hosts() == ["127.0.0.1"]


def test_hosts_excludes_network_and_broadcast():
    assert Scope.from_lines(["10.0.0.0/30"]).hosts() == ["10.0.0.1", "10.0.0.2"]


def test_hosts_respects_max_hosts():
    assert len(Scope.from_lines(["10.0.0.0/8"]).hosts(max_hosts=5)) == 5


def test_resolution_cache_avoids_second_dns(monkeypatch):
    # Resolution cached per mission: a given name is resolved only once.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    calls = []
    def fake(name):
        calls.append(name)
        return "10.0.0.5"
    monkeypatch.setattr(scope.socket, "gethostbyname", fake)
    assert assert_in_scope("host.lab") == "10.0.0.5"
    assert assert_in_scope("host.lab") == "10.0.0.5"
    assert calls == ["host.lab"]


def test_set_active_scope_clears_resolution_cache(monkeypatch):
    # A new mission (new scope) clears the cache: no stale resolution.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    monkeypatch.setattr(scope.socket, "gethostbyname", lambda n: "10.0.0.5")
    assert assert_in_scope("host.lab") == "10.0.0.5"
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    monkeypatch.setattr(scope.socket, "gethostbyname", lambda n: "10.0.0.9")
    assert assert_in_scope("host.lab") == "10.0.0.9"


def test_resolution_times_out_fail_closed(monkeypatch):
    # Slow/blocked resolver -> bounded by a timeout -> unresolved -> out of scope (fail-closed).
    import time
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    monkeypatch.setattr(scope, "_DNS_TIMEOUT", 0.2)
    def slow(name):
        time.sleep(3)
        return "10.0.0.5"
    monkeypatch.setattr(scope.socket, "gethostbyname", slow)
    start = time.monotonic()
    with pytest.raises(ScopeError):
        assert_in_scope("slow.lab")
    assert time.monotonic() - start < 2.0
