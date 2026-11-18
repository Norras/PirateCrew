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
import shutil
import subprocess
import tempfile
import time

try:
    import pwd
except ImportError:          # Windows : module absent, les tests y sont ignorés
    pwd = None

import pytest

from offense import netns
from scope import Scope, set_active_scope

from netns_bench import CURL, IN_SCOPE, MARKER, MARKS, OUT_OF_SCOPE
from netns_bench import _active_scope, bench  # noqa: F401 — fixtures du banc d'essai
from netns_bench import sh as _sh

pytestmark = MARKS


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


def test_timeout_is_enforced_inside_the_namespace():
    # Le délai est appliqué après la descente de privilèges (`timeout`), pas
    # seulement par subprocess côté appelant : la commande est réellement tuée.
    start = time.monotonic()
    netns.run_isolated(["sleep", "300"], timeout=2)
    assert time.monotonic() - start < 12
    assert _sh("ip", "netns", "pids", netns.NS_NAME).stdout.strip() == ""


@pytest.fixture
def tool_dir():
    # Répertoire d'outils « utilisateur » (type venv/bin, ~/.local/bin), lisible
    # après la descente de privilèges.
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
    # Le script d'aide fixe son propre PATH ; celui de la mission est rendu à
    # l'outil après la descente de privilèges.
    monkeypatch.setenv("PATH", f"{tool_dir}:{os.environ['PATH']}")
    assert "TOOL_OK" in netns.run_isolated(["pc-it-tool"])


def test_tool_on_callers_path_is_found_through_sudo(tool_dir, monkeypatch):
    # Même chose en passant réellement par sudo (remise à zéro de l'environnement,
    # secure_path). Lancé par root, sudo ne demande pas de mot de passe.
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


@pytest.mark.skipif(not os.path.exists(_WIN_CMD), reason="interop Windows : WSL uniquement")
def test_wsl_interop_is_closed_inside_the_namespace():
    # Sous WSL2, un binaire Windows lancé depuis Linux s'exécute côté Windows,
    # hors de tout namespace réseau : `curl.exe` sortirait sans passer par le
    # filtre. L'interop doit donc être inopérante pour les commandes isolées.
    out = netns.run_isolated([_WIN_CMD, "/c", "echo", "INTEROP_OK"])
    assert "INTEROP_OK" not in out


def test_down_cuts_a_running_command_and_up_works_again(bench):
    # Une commande occupe encore le namespace : `ip netns del` ne le détruit pas.
    # Le démontage doit quand même couper son lien (plus de transit possible une
    # fois la table retirée), et un `up` suivant doit réussir.
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
    # `nft flush table` garde le set (donc la vérification du set passerait) mais
    # vide les chaînes : plus aucun filtre. Le script d'aide doit refuser.
    _sh("nft", "flush", "table", "inet", "piratecrew")
    try:
        with pytest.raises(netns.NetnsError):
            netns.run_isolated([*CURL, f"http://{IN_SCOPE}:8000/"])
    finally:
        netns.up(bench)


def test_namespace_removed_blocks(bench):
    # Table présente mais namespace disparu : blocage explicite, pas une
    # « sortie d'outil » qui marquerait la technique comme tentée.
    _sh("ip", "netns", "del", netns.NS_NAME)
    try:
        with pytest.raises(netns.NetnsError, match="namespace pc-offense absent"):
            netns.run_isolated([*CURL, f"http://{IN_SCOPE}:8000/"])
    finally:
        netns.up(bench)


def test_table_removed_blocks():   # en dernier : détruit la table
    _sh("nft", "delete", "table", "inet", "piratecrew")
    with pytest.raises(netns.NetnsError):
        netns.run_isolated([*CURL, f"http://{IN_SCOPE}:8000/"])
    # Le script d'aide lui-même refuse d'entrer dans un namespace non filtré.
    assert _sh(netns.HELPER_PATH, "true", check=False).returncode == 97
