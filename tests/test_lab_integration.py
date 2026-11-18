"""Kernel-level proof of the lab target (offense.lab).

A service started in the lab namespace is reachable from the machine (recon) AND
from the offensive namespace (through the filter), while the machine's loopback
stays out of reach of the offensive path.

Run (Linux, root):
    sudo PIRATECREW_NETNS_IT=1 venv/bin/pytest tests/test_lab_integration.py -v
"""
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

from offense import executor, lab, netns
from scope import Scope, set_active_scope

from netns_bench import CURL, MARKER, MARKS, _wait_port, sh

pytestmark = MARKS

PORT = "8017"


@pytest.fixture(scope="module")
def lab_bench():
    # Under /tmp and world-readable: the service runs as the caller (not root),
    # who cannot read pytest's temporary directory.
    web = tempfile.mkdtemp(prefix="pc-it-lab-", dir="/tmp")
    os.chmod(web, 0o755)
    with open(os.path.join(web, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(MARKER)
    os.chmod(os.path.join(web, "index.html"), 0o644)
    forward_before = open("/proc/sys/net/ipv4/ip_forward").read().strip()
    quiet = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "stdin": subprocess.DEVNULL}
    serve = [sys.executable, "-m", "http.server", "--bind", "0.0.0.0", "--directory", str(web), PORT]

    lab.up()
    # The lab service, started the way "offense.lab run" would (caller's identity).
    server = subprocess.Popen(lab.run_argv(serve, int(os.environ.get("SUDO_UID") or 0),
                                           int(os.environ.get("SUDO_GID") or 0)), **quiet)
    scope = Scope.from_lines([lab.LAB_ADDR])
    try:
        _wait_port(lab.LAB_ADDR, int(PORT))          # from the machine: recon reaches it
        netns.up(scope)
        yield scope
    finally:
        netns.down()
        server.terminate()
        server.wait(timeout=5)
        lab.down()
        sh("sysctl", "-w", f"net.ipv4.ip_forward={forward_before}", check=False)
        shutil.rmtree(web, ignore_errors=True)


@pytest.fixture(autouse=True)
def _active_scope(lab_bench, monkeypatch, tmp_path):
    import tools.registry as reg
    monkeypatch.setattr(reg, "AUDIT_LOG", str(tmp_path / "audit.log"))
    set_active_scope(lab_bench)


def test_lab_service_reachable_from_the_offensive_namespace():
    assert MARKER in netns.run_isolated([*CURL, f"http://{lab.LAB_ADDR}:{PORT}/"])


def test_product_path_reaches_the_lab():
    status, out = executor.execute_command(f"curl -s -m 3 http://{lab.LAB_ADDR}:{PORT}/")
    assert status == "done" and MARKER in out


def test_lab_service_is_not_on_the_machine_loopback():
    # The service lives in the lab: nothing listens on this port on the machine
    # side, and the loopback stays out of reach of the offensive path anyway.
    assert sh("curl", "-s", "-m", "2", f"http://127.0.0.1:{PORT}/", check=False).stdout == ""
    assert MARKER not in netns.run_isolated([*CURL, f"http://127.0.0.1:{PORT}/"])


def test_machine_side_of_the_lab_link_stays_closed_to_the_offensive_path():
    # The machine's address on the lab link is not in scope.
    assert MARKER not in netns.run_isolated([*CURL, f"http://{lab.LAB_HOST_ADDR}:{PORT}/"])


def test_lab_service_runs_as_the_caller():
    uid = os.environ.get("SUDO_UID") or "0"
    out = sh(*lab.run_argv(["id", "-u"], int(uid), int(os.environ.get("SUDO_GID") or 0))).stdout
    assert out.strip() == uid


def test_lab_down_removes_namespace_and_link():
    # Teardown THEN set-up again: `up` is idempotent, and the other tests in the
    # module no longer depend on it (this one runs last).
    lab.down()
    assert not lab.is_up()
    assert sh("ip", "link", "show", lab.LAB_HOST_IF, check=False).returncode != 0
