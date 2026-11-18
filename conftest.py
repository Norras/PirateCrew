"""Fixtures pytest partagées (racine du projet)."""

import pytest

import scope
from offense import netns
from scope import Scope


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "netns: test d'intégration du périmètre réseau (Linux + root + PIRATECREW_NETNS_IT=1)")


def _no_real_process(argv, **kwargs):
    raise FileNotFoundError("processus réels désactivés dans les tests unitaires")


@pytest.fixture(autouse=True)
def _isolate_scope_state(request, monkeypatch, tmp_path):
    """Aucun périmètre actif ne fuit d'un test à l'autre (fail-closed par défaut).

    Les refus journalisés pendant les tests vont dans un fichier temporaire,
    pas dans le vrai audit.log de l'opérateur.

    Hors tests d'intégration (marqueur `netns`), le lanceur de processus du
    périmètre réseau est neutralisé : la suite ne lance jamais sudo/ip/nft,
    même sur une machine Linux où le namespace est en place.
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
