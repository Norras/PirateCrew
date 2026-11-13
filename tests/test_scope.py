import pytest

from scope import Scope, ScopeError, assert_in_scope, load_scope, set_active_scope


def test_load_scope_missing_file_raises(tmp_path):
    with pytest.raises(ScopeError):
        load_scope(str(tmp_path / "nope.txt"))


def test_load_scope_empty_raises(tmp_path):
    p = tmp_path / "scope.txt"; p.write_text("\n# commentaire\n", encoding="utf-8")
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
