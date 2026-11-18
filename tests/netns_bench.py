"""Banc d'essai partagé des tests d'intégration du périmètre réseau.

Ce n'est pas un module de tests : il fournit les fixtures et les sondes
communes à `test_netns_integration.py` et `test_netns_round3_replay.py`.

Un second namespace (`pc-it-target`) joue la cible, avec une adresse dans le
périmètre (198.51.100.10) et une hors périmètre (203.0.113.9), toutes deux
servies par le même serveur HTTP. Rien ne sort de la machine.

Deux sondes indépendantes de tout protocole :
- `target_packets(addr)` : paquets REÇUS par la cible pour cette adresse ;
- `host_drops()` : paquets issus du namespace que le filtre de l'hôte a jetés.
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
    pytest.mark.skipif(not ENABLED, reason="intégration netns : Linux + root + PIRATECREW_NETNS_IT=1"),
]

TARGET_NS = "pc-it-target"
HOST_IF, TARGET_IF = "pc-it-h", "pc-it-t"
IN_SCOPE, OUT_OF_SCOPE = "198.51.100.10", "203.0.113.9"
MARKER = "PC_IT_MARKER_7f3a"
CURL = ["curl", "-s", "-m", "3"]

# Noms résolus DANS le namespace seulement (via /etc/netns/pc-offense/hosts) :
# ils jouent les hôtes hors périmètre désignés par un nom (evil.report, corp.evil.com).
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
    """Nombre de paquets que la cible a reçus pour `addr` (tous protocoles)."""
    out = sh("ip", "netns", "exec", TARGET_NS, "nft", "list", "chain", "inet", "pc_it_probe", "input").stdout
    return int(re.search(rf"ip daddr {re.escape(addr)} counter packets (\d+)", out).group(1))


def host_drops() -> int:
    """Nombre de paquets sortis du namespace que le filtre de l'hôte a jetés."""
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
    raise RuntimeError(f"serveur de test injoignable : {host}:{port}")


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
    servers = [subprocess.Popen([*in_target, *serve, "8000"], **quiet),   # la cible
               subprocess.Popen([*serve, "8001"], **quiet)]               # un service de l'hôte
    scope = Scope.from_lines([f"{IN_SCOPE}/32"])
    try:
        # Témoin : depuis l'hôte (non filtré), les DEUX adresses de la cible répondent.
        # Un refus depuis le namespace ne peut donc venir que du filtre.
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
