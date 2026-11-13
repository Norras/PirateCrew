"""Fixtures pytest partagées (racine du projet)."""

import pytest

import scope
from scope import Scope


@pytest.fixture(autouse=True)
def _isolate_scope_state(monkeypatch, tmp_path):
    """Aucun périmètre actif ne fuit d'un test à l'autre (fail-closed par défaut).

    Les refus journalisés pendant les tests vont dans un fichier temporaire,
    pas dans le vrai audit.log de l'opérateur.
    """
    monkeypatch.setattr(scope, "AUDIT_LOG", str(tmp_path / "audit.log"))
    scope.set_active_scope(None)
    yield
    scope.set_active_scope(None)


@pytest.fixture
def local_scope():
    return Scope.from_lines(["127.0.0.1/32"])
