"""Integration proof of the network scope — it is the KERNEL that is tested.

These tests call `netns.run_isolated` directly, WITHOUT going through
`offense.guardrails`: they prove the boundary holds even when the text check
lets everything through, and however the host is written.

Test bench: a second namespace (`pc-it-target`) plays the target, with one
in-scope address (198.51.100.10) and one out-of-scope address (203.0.113.9),
both served by the same HTTP server. Nothing leaves the machine.

Run (Linux, root):
    sudo PIRATECREW_NETNS_IT=1 venv/bin/pytest tests/test_netns_integration.py -v
"""
import os
import shutil
import subprocess
import tempfile
import time

try:
    import pwd
except ImportError:          # Windows: module absent, the tests are skipped there
    pwd = None

import pytest

from offense import netns
from scope import Scope, set_active_scope

from netns_bench import CURL, IN_SCOPE, MARKER, MARKS, OUT_OF_SCOPE
from netns_bench import _active_scope, bench  # noqa: F401 — test bench fixtures
from netns_bench import sh as _sh

pytestmark = MARKS


def test_in_scope_reachable():
    assert MARKER in netns.run_isolated([*CURL, f"http://{IN_SCOPE}:8000/"])


@pytest.mark.parametrize("url", [
    "http://198.51.100.10.:8000/",     # trailing dot
    "http://3325256714:8000/",         # decimal
    "http://0xc633640a:8000/",         # hexadecimal
    "http:///198.51.100.10:8000/",     # slash confusion
])
def test_in_scope_reachable_whatever_the_notation(url):
    # Control for the notations: curl does accept them and connects. The
    # symmetric test below is therefore not green "because curl rejects the URL".
    assert MARKER in netns.run_isolated([*CURL, url])


@pytest.mark.parametrize("url", [
    "http://203.0.113.9:8000/",        # classic dotted
    "http://203.0.113.9.:8000/",       # trailing dot
    "http://3405803785:8000/",         # decimal
    "http://0xcb007109:8000/",         # hexadecimal
    "http:///203.0.113.9:8000/",       # slash confusion
])
def test_out_of_scope_blocked_whatever_the_notation(url):
    assert MARKER not in netns.run_isolated([*CURL, url])


@pytest.mark.parametrize("url", [
    f"http://{netns.HOST_ADDR}:8001/",  # the host, via the namespace link
    "http://127.0.0.1:8001/",          # loopback: the namespace's own, empty
    "http://198.51.100.1:8001/",       # another host address
])
def test_host_services_unreachable(url):
    assert MARKER not in netns.run_isolated([*CURL, url])


def test_no_dns():
    # "(no output)" is the empty-output marker produced by tools.registry._run
    assert netns.run_isolated(["getent", "hosts", "example.com"]) == "(no output)"


def test_privileges_follow_the_caller():
    expected = os.environ.get("SUDO_UID", "0")
    assert netns.run_isolated(["id", "-u"]).strip() == expected


def test_no_ipv6_in_namespace():
    assert "inet6" not in netns.run_isolated(["ip", "-6", "addr", "show"])


def test_scope_drift_blocks():
    set_active_scope(Scope.from_lines([f"{IN_SCOPE}/32", f"{OUT_OF_SCOPE}/32"]))
    with pytest.raises(netns.NetnsError, match="offense.netns up"):
        netns.run_isolated([*CURL, f"http://{OUT_OF_SCOPE}:8000/"])


def test_widening_scope_opens_exactly_that_address(bench):
    # Re-running `up` with a widened scope (namespace already in place) opens
    # the added address; going back to the initial scope closes it again. So it is
    # indeed the set — and only the set — that decides.
    wide = Scope.from_lines([f"{IN_SCOPE}/32", f"{OUT_OF_SCOPE}/32"])
    try:
        netns.up(wide)
        set_active_scope(wide)
        assert MARKER in netns.run_isolated([*CURL, f"http://{OUT_OF_SCOPE}:8000/"])
    finally:
        netns.up(bench)
        set_active_scope(bench)
    assert MARKER not in netns.run_isolated([*CURL, f"http://{OUT_OF_SCOPE}:8000/"])
    assert MARKER in netns.run_isolated([*CURL, f"http://{IN_SCOPE}:8000/"])


def test_timeout_is_enforced_inside_the_namespace():
    # The deadline is applied after privileges are dropped (`timeout`), not
    # only by subprocess on the caller's side: the command is really killed.
    start = time.monotonic()
    netns.run_isolated(["sleep", "300"], timeout=2)
    assert time.monotonic() - start < 12
    assert _sh("ip", "netns", "pids", netns.NS_NAME).stdout.strip() == ""


@pytest.fixture
def tool_dir():
    # "User" tool directory (like venv/bin, ~/.local/bin), readable
    # after privileges are dropped.
    path = tempfile.mkdtemp(prefix="pc-it-bin-", dir="/tmp")
    os.chmod(path, 0o755)
    tool = os.path.join(path, "pc-it-tool")
    with open(tool, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\necho TOOL_OK\n")
    os.chmod(tool, 0o755)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_tool_on_callers_path_is_found(tool_dir, monkeypatch):
    # The helper script fixes its own PATH; the mission's PATH is handed back to
    # the tool after privileges are dropped.
    monkeypatch.setenv("PATH", f"{tool_dir}:{os.environ['PATH']}")
    assert "TOOL_OK" in netns.run_isolated(["pc-it-tool"])


def test_tool_on_callers_path_is_found_through_sudo(tool_dir, monkeypatch):
    # Same thing going through sudo for real (environment reset,
    # secure_path). Run by root, sudo does not ask for a password.
    monkeypatch.setattr(netns, "_is_root", lambda: False)
    monkeypatch.setenv("PATH", f"{tool_dir}:{os.environ['PATH']}")
    assert "TOOL_OK" in netns.run_isolated(["pc-it-tool"])
    assert MARKER in netns.run_isolated([*CURL, f"http://{IN_SCOPE}:8000/"])
    assert MARKER not in netns.run_isolated([*CURL, f"http://{OUT_OF_SCOPE}:8000/"])


def test_identity_environment_follows_the_caller():
    name = pwd.getpwuid(int(os.environ.get("SUDO_UID", "0"))).pw_name
    assert netns.run_isolated(["printenv", "USER"]).strip() == name
    assert netns.run_isolated(["printenv", "LOGNAME"]).strip() == name
    assert netns.run_isolated(["printenv", "HOME"]).strip() == pwd.getpwnam(name).pw_dir


_WIN_CMD = "/mnt/c/Windows/System32/cmd.exe"


@pytest.mark.skipif(not os.path.exists(_WIN_CMD), reason="Windows interop: WSL only")
def test_wsl_interop_is_closed_inside_the_namespace():
    # Under WSL2, a Windows binary launched from Linux runs on the Windows side,
    # outside any network namespace: `curl.exe` would get out without going through the
    # filter. Interop must therefore be inoperative for isolated commands.
    out = netns.run_isolated([_WIN_CMD, "/c", "echo", "INTEROP_OK"])
    assert "INTEROP_OK" not in out


def test_down_cuts_a_running_command_and_up_works_again(bench):
    # A command still occupies the namespace: `ip netns del` does not destroy it.
    # The teardown must still cut its link (no more transit possible once the
    # table is removed), and a following `up` must succeed.
    pinned = subprocess.Popen(["ip", "netns", "exec", netns.NS_NAME, "sleep", "60"])
    try:
        time.sleep(0.5)
        netns.down()
        assert _sh("ip", "link", "show", netns.HOST_IF, check=False).returncode != 0
        netns.up(bench)
        assert MARKER in netns.run_isolated([*CURL, f"http://{IN_SCOPE}:8000/"])
    finally:
        pinned.kill()
        pinned.wait(timeout=5)
        netns.up(bench)


def test_rules_flushed_blocks(bench):
    # `nft flush table` keeps the set (so the set verification would pass) but
    # empties the chains: no filter at all. The helper script must refuse.
    _sh("nft", "flush", "table", "inet", "piratecrew")
    try:
        with pytest.raises(netns.NetnsError):
            netns.run_isolated([*CURL, f"http://{IN_SCOPE}:8000/"])
    finally:
        netns.up(bench)


def test_namespace_removed_blocks(bench):
    # Table present but namespace gone: explicit block, not a
    # "tool output" that would mark the technique as tried.
    _sh("ip", "netns", "del", netns.NS_NAME)
    try:
        with pytest.raises(netns.NetnsError, match="namespace pc-offense missing"):
            netns.run_isolated([*CURL, f"http://{IN_SCOPE}:8000/"])
    finally:
        netns.up(bench)


def test_table_removed_blocks():   # last: destroys the table
    _sh("nft", "delete", "table", "inet", "piratecrew")
    with pytest.raises(netns.NetnsError):
        netns.run_isolated([*CURL, f"http://{IN_SCOPE}:8000/"])
    # The helper script itself refuses to enter an unfiltered namespace.
    assert _sh(netns.HELPER_PATH, "true", check=False).returncode == 97
