"""Network scope (offense.netns) — unit tests.

None of these tests runs `ip`, `nft` or `sudo`: pure functions, or injected
`run` / `write`. The kernel-level proof is in test_netns_integration.py.
"""
import ipaddress

import pytest

from scope import Scope
from offense import netns


# --------------------------------------------------------------------------- #
# Task 1: pure generation
# --------------------------------------------------------------------------- #
def test_scope_v4_collapses_and_drops_v6():
    s = Scope.from_lines(["10.0.0.0/25", "10.0.0.128/25", "10.10.10.5", "fd00::/8"])
    assert [str(n) for n in netns.scope_v4(s)] == ["10.0.0.0/24", "10.10.10.5/32"]


def test_ruleset_is_atomic_and_scoped():
    r = netns.nft_ruleset([ipaddress.ip_network("10.0.0.0/24"), ipaddress.ip_network("10.10.10.5/32")])
    assert r.startswith("table inet piratecrew {}\ndelete table inet piratecrew\n")
    assert "elements = { 10.0.0.0/24, 10.10.10.5 }" in r
    assert 'iifname "pc-host" ip daddr @scope4 accept' in r
    assert 'iifname "pc-host" counter drop' in r
    assert r.index("@scope4 accept") < r.index('iifname "pc-host" counter drop')
    assert "hook input" in r and "hook forward" in r and "masquerade" in r


def test_ruleset_refuses_empty_and_overlap():
    with pytest.raises(netns.NetnsError):
        netns.nft_ruleset([])
    with pytest.raises(netns.NetnsError):
        netns.nft_ruleset([ipaddress.ip_network("100.127.0.0/16")])   # overlaps LINK_NET


@pytest.mark.parametrize("private", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
def test_link_stays_out_of_private_ranges(private):
    # The internal link lives in the carrier-grade shared range (100.64.0.0/10,
    # RFC 6598), not in a private range: a test scope covering all of
    # 10/8 (or a lab in 10.200.x.x) must remain acceptable.
    link = ipaddress.ip_network(netns.LINK_NET)
    assert link.subnet_of(ipaddress.ip_network("100.64.0.0/10"))
    assert not link.overlaps(ipaddress.ip_network(private))
    assert "@scope4 accept" in netns.nft_ruleset([ipaddress.ip_network(private)])
    assert ipaddress.ip_address(netns.HOST_ADDR) in link and ipaddress.ip_address(netns.NS_ADDR) in link


def test_loopback_entries_are_reported():
    # A 127.x scope entry is unreachable from the namespace (it has its own
    # loopback): we can single it out to warn the operator.
    s = Scope.from_lines(["127.0.0.1", "10.0.0.0/24", "127.8.0.0/16"])
    assert netns.loopback_entries(s) == ["127.0.0.1/32", "127.8.0.0/16"]
    assert "127.0.0.1/32" in netns.loopback_warning(s) and "loopback" in netns.loopback_warning(s)
    other = Scope.from_lines(["10.0.0.0/24"])
    assert netns.loopback_entries(other) == [] and netns.loopback_warning(other) is None


def test_setup_orders_and_disables_v6():
    cmds = netns.setup_commands()
    assert cmds[0] == ["ip", "netns", "add", "pc-offense"]
    assert ["ip", "netns", "exec", "pc-offense", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"] in cmds
    assert ["ip", "netns", "exec", "pc-offense", "ip", "route", "add", "default", "via", "100.127.77.1"] in cmds
    assert cmds[-1] == ["sysctl", "-w", "net.ipv4.ip_forward=1"]


def test_teardown_cuts_the_link_first():
    # The host veth is deleted FIRST: `ip netns del` does not destroy a
    # namespace that a process still occupies, and removing the nftables table
    # while that link exists would let it transit unfiltered.
    assert netns.teardown_commands() == [["ip", "link", "del", "pc-host"],
                                         ["ip", "netns", "del", "pc-offense"],
                                         ["nft", "delete", "table", "inet", "piratecrew"]]


def test_helper_script_is_hardened():
    lines = netns.HELPER_SCRIPT.splitlines()
    commands = [l for l in lines if l and not l.startswith("#")]
    # PATH fixed before any command: the script runs as root via sudo and must
    # not resolve nft/ip/setpriv in the caller's PATH.
    assert commands[:3] == ["set -eu", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "export PATH"]
    script = netns.HELPER_SCRIPT
    # Guard shared by both modes (--check and execution), before any `exec`.
    guard_end = script.index('if [ "${1:-}" = "--check" ]')
    assert "/run/netns/pc-offense" in script[:guard_end]
    assert "list chain inet piratecrew forward" in script[:guard_end]
    assert "list chain inet piratecrew input" in script[:guard_end]
    assert "exec " not in script[:guard_end]
    assert "export HOME USER LOGNAME" in script
    # WSL2: Windows interop (/run/WSL sockets) is masked BEFORE privileges
    # are dropped — otherwise `curl.exe` would run outside the namespace.
    assert "tmpfs /run/WSL" in script
    assert script.index("tmpfs /run/WSL") < script.index("setpriv --reuid")


# --------------------------------------------------------------------------- #
# Task 2: root setup (injected run / write)
# --------------------------------------------------------------------------- #
class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class _FakeRun:
    """Replaces subprocess.run: records (argv, input), runs nothing."""

    def __init__(self, fail_on=None, stdout="", returncode=0):
        self.calls = []
        self.fail_on = fail_on          # argv prefix that fails (returncode=1)
        self.stdout, self.returncode = stdout, returncode

    def __call__(self, argv, input=None, **kwargs):
        self.calls.append((list(argv), input))
        if self.fail_on and list(argv)[:len(self.fail_on)] == self.fail_on:
            return _Proc(1, "", "boom")
        return _Proc(self.returncode, self.stdout, "")


class _FakeWrite:
    def __init__(self):
        self.calls = []

    def __call__(self, path, content, mode):
        self.calls.append((path, content, mode))


@pytest.fixture
def fake_run():
    return _FakeRun()


@pytest.fixture
def fake_write():
    return _FakeWrite()


def test_up_loads_nft_before_creating_namespace(fake_run, fake_write):
    s = Scope.from_lines(["10.0.0.0/24"])
    netns.up(s, run=fake_run, write=fake_write)
    argvs = [c[0] for c in fake_run.calls]
    assert argvs.index(["nft", "-f", "-"]) < argvs.index(["ip", "netns", "add", "pc-offense"])
    assert fake_run.calls[argvs.index(["nft", "-f", "-"])][1] == netns.nft_ruleset(netns.scope_v4(s))


def test_up_is_idempotent_teardown_first(fake_run, fake_write):
    netns.up(Scope.from_lines(["10.0.0.0/24"]), run=fake_run, write=fake_write)
    teardown = netns.teardown_commands()
    assert [c[0] for c in fake_run.calls][:len(teardown)] == teardown


def test_up_survives_failing_initial_teardown(fake_write):
    # First `up`: there is nothing to tear down, `ip netns del` fails — that is not an error.
    run = _FakeRun(fail_on=["ip", "netns", "del"])
    netns.up(Scope.from_lines(["10.0.0.0/24"]), run=run, write=fake_write)
    assert ["ip", "netns", "add", "pc-offense"] in [c[0] for c in run.calls]


def test_up_writes_helper_resolv_and_sudoers(fake_run, fake_write):
    netns.up(Scope.from_lines(["10.0.0.0/24"]), dns="10.0.0.2", sudo_user="kali",
             run=fake_run, write=fake_write)
    files = {p: (c, m) for p, c, m in fake_write.calls}
    assert files["/usr/local/sbin/pc-netns-exec"] == (netns.HELPER_SCRIPT, 0o755)
    assert files["/etc/netns/pc-offense/resolv.conf"] == ("nameserver 10.0.0.2\n", 0o644)
    assert files["/etc/sudoers.d/piratecrew"] == (
        "kali ALL=(root) NOPASSWD: /usr/local/sbin/pc-netns-exec\n", 0o440)
    assert fake_run.calls[-1][0] == ["visudo", "-cf", "/etc/sudoers.d/piratecrew"]


def test_up_without_sudo_user_writes_no_sudoers(fake_run, fake_write):
    netns.up(Scope.from_lines(["10.0.0.0/24"]), run=fake_run, write=fake_write)
    assert "/etc/sudoers.d/piratecrew" not in [p for p, _c, _m in fake_write.calls]
    assert ["visudo", "-cf", "/etc/sudoers.d/piratecrew"] not in [c[0] for c in fake_run.calls]


def test_up_default_dns_is_empty_resolv(fake_run, fake_write):
    netns.up(Scope.from_lines(["10.0.0.0/24"]), run=fake_run, write=fake_write)
    assert ("/etc/netns/pc-offense/resolv.conf", "", 0o644) in fake_write.calls


def test_up_refuses_out_of_scope_dns_and_bad_sudo_user(fake_run, fake_write):
    s = Scope.from_lines(["10.0.0.0/24"])
    with pytest.raises(netns.NetnsError):
        netns.up(s, dns="8.8.8.8", run=fake_run, write=fake_write)
    with pytest.raises(netns.NetnsError):
        netns.up(s, dns="dc01.corp.local", run=fake_run, write=fake_write)   # literal IP required
    with pytest.raises(netns.NetnsError):
        netns.up(s, sudo_user="kali ALL=(ALL) ALL\nroot", run=fake_run, write=fake_write)
    assert fake_run.calls == [] and fake_write.calls == []


def test_up_refuses_scope_without_ipv4_before_any_command(fake_run, fake_write):
    with pytest.raises(netns.NetnsError):
        netns.up(Scope.from_lines(["fd00::/8"]), run=fake_run, write=fake_write)
    assert fake_run.calls == [] and fake_write.calls == []


def test_up_failure_tears_down(fake_write):
    run = _FakeRun(fail_on=["ip", "link", "add"])
    with pytest.raises(netns.NetnsError, match="ip link add"):
        netns.up(Scope.from_lines(["10.0.0.0/24"]), run=run, write=fake_write)
    teardown = netns.teardown_commands()
    assert [c[0] for c in run.calls][-len(teardown):] == teardown
    assert fake_write.calls == []


def test_up_nft_load_failure_creates_no_namespace(fake_write):
    run = _FakeRun(fail_on=["nft", "-f"])
    with pytest.raises(netns.NetnsError):
        netns.up(Scope.from_lines(["10.0.0.0/24"]), run=run, write=fake_write)
    assert ["ip", "netns", "add", "pc-offense"] not in [c[0] for c in run.calls]


def test_down_never_raises():
    def boom(argv, **kwargs):
        raise FileNotFoundError("ip")
    netns.down(run=boom)                       # missing binary: does not raise
    run = _FakeRun(fail_on=["ip"])
    netns.down(run=run)
    assert [c[0] for c in run.calls] == netns.teardown_commands()


def test_main_requires_root_and_linux(monkeypatch):
    monkeypatch.setattr(netns.sys, "platform", "win32")
    assert netns.main(["up"]) == 2
    monkeypatch.setattr(netns.sys, "platform", "linux")
    monkeypatch.setattr(netns.os, "geteuid", lambda: 1000, raising=False)
    assert netns.main(["up"]) == 2


# --------------------------------------------------------------------------- #
# Task 3: entering the namespace and verifying against the kernel
# --------------------------------------------------------------------------- #
# Real shape of `nft -j list set` (nftables 1.1.6): /32 as a string, CIDR as
# {"prefix"}, unaligned interval as {"range"}.
NFT_JSON = ('{"nftables":[{"metainfo":{"version":"1.1.6"}},{"set":{"family":"inet","name":"scope4",'
            '"table":"piratecrew","type":"ipv4_addr","flags":["interval"],"elem":['
            '"10.10.10.5",{"prefix":{"addr":"10.0.0.0","len":24}},{"range":["10.0.1.0","10.0.1.255"]}]}}]}')


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(netns.sys, "platform", "linux")


def _run_json(out, returncode=0):
    return _FakeRun(stdout=out, returncode=returncode)


def test_installed_networks_parses_three_element_forms(linux):
    run = _run_json(NFT_JSON)
    nets = netns.installed_networks(run=run)
    assert [str(n) for n in nets] == ["10.0.0.0/23", "10.10.10.5/32"]
    assert run.calls[0][0][-2:] == ["/usr/local/sbin/pc-netns-exec", "--check"]


def test_installed_networks_empty_set_is_empty_list(linux):
    out = '{"nftables":[{"set":{"name":"scope4","table":"piratecrew"}}]}'
    assert netns.installed_networks(run=_run_json(out)) == []


@pytest.mark.parametrize("out", [
    "", "not json", "{}", '{"nftables":[{"metainfo":{}}]}',
    '{"nftables":[{"set":{"elem":[{"weird":1}]}}]}',
    '{"nftables":[{"set":{"elem":["not-an-ip"]}}]}',
    '{"nftables":[{"set":{"elem":[{"prefix":{"addr":"10.0.0.0"}}]}}]}',
    '{"nftables":[{"set":"not-an-object"}]}',
    '{"nftables":[{"set":{"elem":"not-a-list"}}]}',
    '{"nftables":[{"set":{"elem":[{"range":["10.0.0.9","10.0.0.1"]}]}}]}',
])
def test_installed_networks_fail_closed_on_unexpected_output(linux, out):
    with pytest.raises(netns.NetnsError):
        netns.installed_networks(run=_run_json(out))


def test_installed_networks_fail_closed_on_helper_failure(linux):
    import subprocess
    with pytest.raises(netns.NetnsError):
        netns.installed_networks(run=_run_json(NFT_JSON, returncode=97))

    def missing(argv, **kwargs):
        raise FileNotFoundError("sudo")
    with pytest.raises(netns.NetnsError):
        netns.installed_networks(run=missing)

    def slow(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 10)
    with pytest.raises(netns.NetnsError):
        netns.installed_networks(run=slow)


def test_verify_exact_match_only(linux):
    run = _run_json(NFT_JSON)
    netns.verify(Scope.from_lines(["10.0.0.0/23", "10.10.10.5"]), run=run)       # does not raise
    for lines in (["10.0.0.0/23"], ["10.0.0.0/23", "10.10.10.5", "10.9.9.9"], ["10.0.0.0/22", "10.10.10.5"]):
        with pytest.raises(netns.NetnsError, match="offense.netns up"):
            netns.verify(Scope.from_lines(lines), run=run)


def test_verify_refuses_scope_without_ipv4(linux):
    empty_set = '{"nftables":[{"set":{"name":"scope4","table":"piratecrew"}}]}'
    with pytest.raises(netns.NetnsError):
        netns.verify(Scope.from_lines(["fd00::/8"]), run=_run_json(empty_set))


def test_verify_refuses_off_linux_without_spawning(monkeypatch):
    monkeypatch.setattr(netns.sys, "platform", "win32")
    run = _run_json(NFT_JSON)
    with pytest.raises(netns.NetnsError):
        netns.verify(Scope.from_lines(["10.0.0.0/23", "10.10.10.5"]), run=run)
    assert run.calls == []


def test_wrap_by_euid(monkeypatch):
    monkeypatch.setattr(netns.os, "geteuid", lambda: 1000, raising=False)
    # Absolute path: `sudo` must not be resolved in a PATH that starts with a
    # user-writable directory (venv/bin).
    assert netns.wrap(["nmap", "x"]) == ["/usr/bin/sudo", "-n", "/usr/local/sbin/pc-netns-exec", "nmap", "x"]
    monkeypatch.setattr(netns.os, "geteuid", lambda: 0, raising=False)
    assert netns.wrap(["nmap", "x"]) == ["/usr/local/sbin/pc-netns-exec", "nmap", "x"]


def test_run_isolated_requires_scope_and_verify(monkeypatch):
    from scope import set_active_scope
    with pytest.raises(netns.NetnsError):
        netns.run_isolated(["id"])                                   # no active scope
    seen = []
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    monkeypatch.setattr(netns, "verify", lambda scope, run=None: None)
    monkeypatch.setattr(netns, "wrap", lambda argv: ["W", *argv])
    monkeypatch.setattr("tools.registry._run", lambda argv, timeout=120: seen.append((argv, timeout)) or "ok")
    monkeypatch.setenv("PATH", "/opt/tools:/usr/bin")
    assert netns.run_isolated(["id"], timeout=7) == "ok"
    # - `env PATH=...`: sudo resets the environment; the tool must be found
    #   in the mission's PATH (venv/bin, ~/.local/bin), like technique_available.
    # - `timeout -k 5 7`: the deadline is applied AFTER privileges are dropped;
    #   a non-root process cannot kill `sudo` (EPERM), hence not the subprocess.
    # - outer timeout 7 + 15: a mere safety net, it must never fire first.
    assert seen == [(["W", "env", "PATH=/opt/tools:/usr/bin", "timeout", "-k", "5", "7", "id"], 22)]


def test_run_isolated_path_fallback_when_unset(monkeypatch):
    from scope import set_active_scope
    seen = []
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    monkeypatch.setattr(netns, "verify", lambda scope, run=None: None)
    monkeypatch.setattr(netns, "wrap", lambda argv: argv)
    monkeypatch.setattr("tools.registry._run", lambda argv, timeout=120: seen.append(argv) or "ok")
    monkeypatch.delenv("PATH", raising=False)
    netns.run_isolated(["id"])
    assert seen[0][1] == "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def test_run_isolated_helper_refusal_is_not_a_tool_result(monkeypatch):
    # The helper script refused (namespace or filter vanished between verification
    # and execution): this is a block, not tool output — otherwise the
    # technique would be marked "tried" although nothing ran.
    from scope import set_active_scope
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    monkeypatch.setattr(netns, "verify", lambda scope, run=None: None)
    monkeypatch.setattr("tools.registry._run",
                        lambda argv, timeout=120: "pc-netns-exec: namespace pc-offense missing")
    with pytest.raises(netns.NetnsError, match="namespace pc-offense missing.*offense.netns up"):
        netns.run_isolated(["id"])


def test_run_isolated_does_not_run_when_verify_fails(monkeypatch):
    from scope import set_active_scope
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    ran = []

    def refuse(scope, run=None):
        raise netns.NetnsError("different set")
    monkeypatch.setattr(netns, "verify", refuse)
    monkeypatch.setattr("tools.registry._run", lambda argv, timeout=120: ran.append(argv) or "ok")
    with pytest.raises(netns.NetnsError):
        netns.run_isolated(["id"])
    assert ran == []


def test_unit_tests_cannot_spawn_real_processes(linux):
    # Suite safeguard: outside integration tests (`netns` marker), the module's
    # default launcher is neutralized by conftest — even on a Linux machine,
    # `pytest` runs neither sudo, nor ip, nor nft.
    import subprocess
    assert netns._spawn is not subprocess.run
    with pytest.raises(netns.NetnsError):
        netns.installed_networks()            # default launcher: refused, no process
    netns.down()                              # same, and never raises


def test_main_status(monkeypatch, capsys, linux):
    monkeypatch.setattr(netns, "installed_networks",
                        lambda run=None: [ipaddress.ip_network("10.0.0.0/24")])
    assert netns.main(["status"]) == 0
    assert "10.0.0.0/24" in capsys.readouterr().out

    def absent(run=None):
        raise netns.NetnsError("table missing")
    monkeypatch.setattr(netns, "installed_networks", absent)
    assert netns.main(["status"]) == 1
    assert "absent" in capsys.readouterr().out
