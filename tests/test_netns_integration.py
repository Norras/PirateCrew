"""Preuve d'intégration du périmètre réseau — c'est le NOYAU qui est testé.

Ces tests appellent `netns.run_isolated` directement, SANS passer par
`offense.guardrails` : ils prouvent que la frontière tient même quand le
contrôle texte laisse tout passer, et quelle que soit l'écriture de l'hôte.

Banc d'essai : un second namespace (`pc-it-target`) joue la cible, avec une
adresse dans le périmètre (198.51.100.10) et une hors périmètre (203.0.113.9),
toutes deux servies par le même serveur HTTP. Rien ne sort de la machine.

Lancement (Linux, root) :
    sudo PIRATECREW_NETNS_IT=1 venv/bin/pytest tests/test_netns_integration.py -v
"""
import os
import socket
import subprocess
import sys
import time

import pytest

from offense import netns
from scope import Scope, set_active_scope

_ENABLED = (sys.platform == "linux"
            and getattr(os, "geteuid", lambda: -1)() == 0
            and os.environ.get("PIRATECREW_NETNS_IT") == "1")

pytestmark = [
    pytest.mark.netns,
    pytest.mark.skipif(not _ENABLED, reason="intégration netns : Linux + root + PIRATECREW_NETNS_IT=1"),
]

TARGET_NS = "pc-it-target"
HOST_IF, TARGET_IF = "pc-it-h", "pc-it-t"
IN_SCOPE, OUT_OF_SCOPE = "198.51.100.10", "203.0.113.9"
MARKER = "PC_IT_MARKER_7f3a"
CURL = ["curl", "-s", "-m", "3"]


def _sh(*argv, check=True):
    return subprocess.run(list(argv), capture_output=True, text=True, check=check)


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
    _sh("ip", "netns", "del", TARGET_NS, check=False)
    _sh("ip", "link", "del", HOST_IF, check=False)


@pytest.fixture(scope="module")
def bench(tmp_path_factory):
    web = tmp_path_factory.mktemp("web")
    (web / "index.html").write_text(MARKER, encoding="utf-8")
    os.chmod(web, 0o755)
    forward_before = open("/proc/sys/net/ipv4/ip_forward").read().strip()

    _cleanup_target()
    in_target = ["ip", "netns", "exec", TARGET_NS]
    _sh("ip", "netns", "add", TARGET_NS)
    _sh("ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", TARGET_IF)
    _sh("ip", "link", "set", TARGET_IF, "netns", TARGET_NS)
    _sh("ip", "addr", "add", "198.51.100.1/24", "dev", HOST_IF)
    _sh("ip", "addr", "add", "203.0.113.1/24", "dev", HOST_IF)
    _sh("ip", "link", "set", HOST_IF, "up")
    _sh(*in_target, "ip", "addr", "add", f"{IN_SCOPE}/24", "dev", TARGET_IF)
    _sh(*in_target, "ip", "addr", "add", f"{OUT_OF_SCOPE}/24", "dev", TARGET_IF)
    _sh(*in_target, "ip", "link", "set", TARGET_IF, "up")
    _sh(*in_target, "ip", "link", "set", "lo", "up")

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
        yield scope
    finally:
        netns.down()
        for proc in servers:
            proc.terminate()
        for proc in servers:
            proc.wait(timeout=5)
        _cleanup_target()
        _sh("sysctl", "-w", f"net.ipv4.ip_forward={forward_before}", check=False)


@pytest.fixture(autouse=True)
def _active_scope(bench, monkeypatch, tmp_path):
    import tools.registry as reg
    monkeypatch.setattr(reg, "AUDIT_LOG", str(tmp_path / "audit.log"))
    set_active_scope(bench)


def test_in_scope_reachable():
    assert MARKER in netns.run_isolated([*CURL, f"http://{IN_SCOPE}:8000/"])


@pytest.mark.parametrize("url", [
    "http://198.51.100.10.:8000/",     # point final
    "http://3325256714:8000/",         # décimale
    "http://0xc633640a:8000/",         # hexadécimale
    "http:///198.51.100.10:8000/",     # confusion de slashs
])
def test_in_scope_reachable_whatever_the_notation(url):
    # Témoin des notations : curl les accepte bien et se connecte. Le test
    # symétrique ci-dessous n'est donc pas vert « parce que curl refuse l'URL ».
    assert MARKER in netns.run_isolated([*CURL, url])


@pytest.mark.parametrize("url", [
    "http://203.0.113.9:8000/",        # pointée classique
    "http://203.0.113.9.:8000/",       # point final
    "http://3405803785:8000/",         # décimale
    "http://0xcb007109:8000/",         # hexadécimale
    "http:///203.0.113.9:8000/",       # confusion de slashs
])
def test_out_of_scope_blocked_whatever_the_notation(url):
    assert MARKER not in netns.run_isolated([*CURL, url])


@pytest.mark.parametrize("url", [
    "http://10.200.77.1:8001/",        # l'hôte, par le lien du namespace
    "http://127.0.0.1:8001/",          # loopback : celui du namespace, vide
    "http://198.51.100.1:8001/",       # une autre adresse de l'hôte
])
def test_host_services_unreachable(url):
    assert MARKER not in netns.run_isolated([*CURL, url])


def test_no_dns():
    assert netns.run_isolated(["getent", "hosts", "example.com"]) == "(aucune sortie)"


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
    # Relancer `up` avec un périmètre élargi (namespace déjà en place) ouvre
    # l'adresse ajoutée ; revenir au périmètre initial la referme. C'est donc
    # bien le set — et lui seul — qui décide.
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


def test_table_removed_blocks():   # en dernier : détruit la table
    _sh("nft", "delete", "table", "inet", "piratecrew")
    with pytest.raises(netns.NetnsError):
        netns.run_isolated([*CURL, f"http://{IN_SCOPE}:8000/"])
    # Le script d'aide lui-même refuse d'entrer dans un namespace non filtré.
    assert _sh(netns.HELPER_PATH, "true", check=False).returncode == 97
