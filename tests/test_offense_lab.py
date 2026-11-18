"""Local lab target (offense.lab) - unit tests.

None of these tests runs `ip`: pure functions, or an injected `run`. The
kernel-level proof is in test_lab_integration.py.
"""
import ipaddress

import pytest

from offense import lab, netns


class _Proc:
    def __init__(self, returncode=0, stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, "", stderr


class _FakeRun:
    """Stands in for subprocess.run: records the argv, runs nothing."""

    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on          # argv prefix that fails (returncode=1)

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if self.fail_on and list(argv)[:len(self.fail_on)] == self.fail_on:
            return _Proc(1, "boom")
        return _Proc()


def test_lab_address_is_never_routed_and_clear_of_the_offense_link():
    # Documentation range (RFC 5737): a stray packet would go nowhere.
    net = ipaddress.ip_network(lab.LAB_NET)
    assert net.subnet_of(ipaddress.ip_network("192.0.2.0/24"))
    assert not net.overlaps(ipaddress.ip_network(netns.LINK_NET))
    assert ipaddress.ip_address(lab.LAB_ADDR) in net and ipaddress.ip_address(lab.LAB_HOST_ADDR) in net
    assert lab.LAB_ADDR != lab.LAB_HOST_ADDR
    # The lab target is an acceptable scope for the offensive namespace.
    assert "@scope4 accept" in netns.nft_ruleset([ipaddress.ip_network(f"{lab.LAB_ADDR}/32")])


def test_setup_gives_the_lab_its_own_address():
    cmds = lab.setup_commands()
    assert cmds[0] == ["ip", "netns", "add", "pc-lab"]
    in_lab = ["ip", "netns", "exec", "pc-lab"]
    assert ["ip", "addr", "add", "192.0.2.1/30", "dev", "pc-lab-host"] in cmds
    assert [*in_lab, "ip", "addr", "add", "192.0.2.2/30", "dev", "pc-lab-ns"] in cmds
    assert [*in_lab, "ip", "link", "set", "lo", "up"] in cmds
    # No default route: the target answers on its link and goes nowhere else.
    assert not any("default" in c for c in cmds)


def test_teardown_removes_link_then_namespace():
    assert lab.teardown_commands() == [["ip", "link", "del", "pc-lab-host"],
                                       ["ip", "netns", "del", "pc-lab"]]


def test_up_starts_clean_and_runs_every_step():
    run = _FakeRun()
    lab.up(run=run)
    n = len(lab.teardown_commands())
    assert run.calls[:n] == lab.teardown_commands()          # idempotent: tears down first
    assert run.calls[n:] == lab.setup_commands()


def test_up_tears_down_when_a_step_fails():
    run = _FakeRun(fail_on=["ip", "link", "set", "pc-lab-host", "up"])
    with pytest.raises(netns.NetnsError):
        lab.up(run=run)
    assert run.calls[-len(lab.teardown_commands()):] == lab.teardown_commands()


def test_run_argv_drops_to_the_caller():
    argv = lab.run_argv(["python3", "-m", "http.server", "8000"], uid=1000, gid=1000)
    assert argv == ["ip", "netns", "exec", "pc-lab", "setpriv", "--reuid", "1000", "--regid", "1000",
                    "--init-groups", "--", "python3", "-m", "http.server", "8000"]


def test_main_requires_linux_root_and_a_command(monkeypatch, capsys):
    monkeypatch.setattr(lab.sys, "platform", "win32")
    assert lab.main(["up"]) == 2
    monkeypatch.setattr(lab.sys, "platform", "linux")
    monkeypatch.setattr(lab.os, "geteuid", lambda: 1000, raising=False)
    assert lab.main(["up"]) == 2
    monkeypatch.setattr(lab.os, "geteuid", lambda: 0, raising=False)
    assert lab.main(["run"]) == 2                              # nothing to run
    monkeypatch.setattr(lab, "is_up", lambda: False)
    assert lab.main(["run", "--", "true"]) == 1                # lab missing: it says so
    assert "offense.lab up" in capsys.readouterr().err


def test_main_up_tells_the_operator_what_to_scope(monkeypatch, capsys):
    monkeypatch.setattr(lab.sys, "platform", "linux")
    monkeypatch.setattr(lab.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(lab, "up", lambda run=None: None)
    assert lab.main(["up"]) == 0
    out = capsys.readouterr().out
    assert "192.0.2.2" in out and "scope.txt" in out
