"""Shared pytest fixtures (project root)."""

import pytest

import scope
from offense import netns
from scope import Scope


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "netns: network perimeter integration test (Linux + root + PIRATECREW_NETNS_IT=1)")


def _no_real_process(argv, **kwargs):
    raise FileNotFoundError("real processes are disabled in unit tests")


@pytest.fixture(autouse=True)
def _isolate_scope_state(request, monkeypatch, tmp_path):
    """No active scope leaks from one test to the next (fail-closed by default).

    Refusals logged during tests go to a temporary file, not to the
    operator's real audit.log.

    Outside integration tests (`netns` marker), the network perimeter's
    process launcher is neutralized: the suite never runs sudo/ip/nft,
    even on a Linux machine where the namespace is in place.
    """
    if request.node.get_closest_marker("netns") is None:
        monkeypatch.setattr(netns, "_spawn", _no_real_process)
    monkeypatch.setattr(scope, "AUDIT_LOG", str(tmp_path / "audit.log"))
    scope.set_active_scope(None)
    yield
    scope.set_active_scope(None)


@pytest.fixture
def local_scope():
    return Scope.from_lines(["127.0.0.1/32"])
