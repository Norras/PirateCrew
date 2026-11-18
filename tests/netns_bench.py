"""Shared test bench for the network scope integration tests.

This is not a test module: it provides the fixtures and probes shared by
`test_netns_integration.py` and `test_netns_round3_replay.py`.

A second namespace (`pc-it-target`) plays the target, with one in-scope address
(198.51.100.10) and one out-of-scope address (203.0.113.9), both served by the
same HTTP server. Nothing leaves the machine.

Two protocol-independent probes:
- `target_packets(addr)`: packets RECEIVED by the target for that address;
- `host_drops()`: packets from the namespace that the host filter dropped.
"""
import os
import re
import socket
import subprocess
import sys
import time

import pytest

from offense import netns
from scope import Scope, set_active_scope

ENABLED = (sys.platform == "linux"
           and getattr(os, "geteuid", lambda: -1)() == 0
           and os.environ.get("PIRATECREW_NETNS_IT") == "1")

MARKS = [
    pytest.mark.netns,
    pytest.mark.skipif(not ENABLED, reason="netns integration: Linux + root + PIRATECREW_NETNS_IT=1"),
]

TARGET_NS = "pc-it-target"
HOST_IF, TARGET_IF = "pc-it-h", "pc-it-t"
IN_SCOPE, OUT_OF_SCOPE = "198.51.100.10", "203.0.113.9"
MARKER = "PC_IT_MARKER_7f3a"
CURL = ["curl", "-s", "-m", "3"]

# Names resolved INSIDE the namespace only (via /etc/netns/pc-offense/hosts):
# they stand in for out-of-scope hosts designated by name (evil.report, corp.evil.com).
OOS_NAMES = ("pc-it-oos.report", "pc-it-oos.corp")
_NS_HOSTS = f"/etc/netns/{netns.NS_NAME}/hosts"

_PROBE_RULESET = f"""table inet pc_it_probe {{
    chain input {{
        type filter hook input priority filter; policy accept;
        ip daddr {OUT_OF_SCOPE} counter
        ip daddr {IN_SCOPE} counter
    }}
}}
"""


def sh(*argv, check=True):
    return subprocess.run(list(argv), capture_output=True, text=True, check=check)


def target_packets(addr: str) -> int:
    """Number of packets the target received for `addr` (all protocols)."""
    out = sh("ip", "netns", "exec", TARGET_NS, "nft", "list", "chain", "inet", "pc_it_probe", "input").stdout
    return int(re.search(rf"ip daddr {re.escape(addr)} counter packets (\d+)", out).group(1))


def host_drops() -> int:
    """Number of packets leaving the namespace that the host filter dropped."""
    out = sh("nft", "list", "chain", "inet", netns.NFT_TABLE, "forward").stdout
    return int(re.search(rf'iifname "{netns.HOST_IF}" counter packets (\d+) bytes \d+ drop', out).group(1))


def _wait_port(host, port, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"test server unreachable: {host}:{port}")


def _cleanup_target():
    sh("ip", "netns", "del", TARGET_NS, check=False)
    sh("ip", "link", "del", HOST_IF, check=False)


@pytest.fixture(scope="module")
def bench(tmp_path_factory):
    web = tmp_path_factory.mktemp("web")
    (web / "index.html").write_text(MARKER, encoding="utf-8")
    os.chmod(web, 0o755)
    forward_before = open("/proc/sys/net/ipv4/ip_forward").read().strip()

    _cleanup_target()
    in_target = ["ip", "netns", "exec", TARGET_NS]
    sh("ip", "netns", "add", TARGET_NS)
    sh("ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", TARGET_IF)
    sh("ip", "link", "set", TARGET_IF, "netns", TARGET_NS)
    sh("ip", "addr", "add", "198.51.100.1/24", "dev", HOST_IF)
    sh("ip", "addr", "add", "203.0.113.1/24", "dev", HOST_IF)
    sh("ip", "link", "set", HOST_IF, "up")
    sh(*in_target, "ip", "addr", "add", f"{IN_SCOPE}/24", "dev", TARGET_IF)
    sh(*in_target, "ip", "addr", "add", f"{OUT_OF_SCOPE}/24", "dev", TARGET_IF)
    sh(*in_target, "ip", "link", "set", TARGET_IF, "up")
    sh(*in_target, "ip", "link", "set", "lo", "up")
    subprocess.run([*in_target, "nft", "-f", "-"], input=_PROBE_RULESET, text=True,
                   capture_output=True, check=True)

    serve = [sys.executable, "-m", "http.server", "--bind", "0.0.0.0", "--directory", str(web)]
    quiet = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    servers = [subprocess.Popen([*in_target, *serve, "8000"], **quiet),   # the target
               subprocess.Popen([*serve, "8001"], **quiet)]               # a host service
    scope = Scope.from_lines([f"{IN_SCOPE}/32"])
    try:
        # Control: from the host (unfiltered), BOTH target addresses respond.
        # A refusal from the namespace can therefore only come from the filter.
        _wait_port(IN_SCOPE, 8000)
        _wait_port(OUT_OF_SCOPE, 8000)
        _wait_port("127.0.0.1", 8001)
        netns.up(scope)
        with open("/etc/hosts", encoding="utf-8") as fh:
            hosts = fh.read().rstrip("\n")
        hosts += "".join(f"\n{OUT_OF_SCOPE} {name}" for name in OOS_NAMES) + "\n"
        with open(_NS_HOSTS, "w", encoding="utf-8") as fh:
            fh.write(hosts)
        yield scope
    finally:
        netns.down()
        try:
            os.remove(_NS_HOSTS)
        except OSError:
            pass
        for proc in servers:
            proc.terminate()
        for proc in servers:
            proc.wait(timeout=5)
        _cleanup_target()
        sh("sysctl", "-w", f"net.ipv4.ip_forward={forward_before}", check=False)


@pytest.fixture(autouse=True)
def _active_scope(bench, monkeypatch, tmp_path):
    import tools.registry as reg
    monkeypatch.setattr(reg, "AUDIT_LOG", str(tmp_path / "audit.log"))
    set_active_scope(bench)
