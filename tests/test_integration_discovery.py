"""Intégration bout-en-bout (sans LLM) : découverte d'un service HTTP sur un port
inhabituel puis récupération d'un credential dans un fichier listé."""
import functools
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import pytest

from scope import Scope, get_active_scope, set_active_scope
from state.world_model import WorldModel
from orchestrator import discover_services, reconcile_evidence, _port_open, _http_name
from tools.registry import http_get_listing


@pytest.fixture
def http_server(tmp_path):
    (tmp_path / ".secret").write_text("Cred for DC :\nDamulsan:AAJJAQBenough1728!",
                                      encoding="utf-8")
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(tmp_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    previous = get_active_scope()
    scope = Scope.from_lines(["127.0.0.1/32"])
    set_active_scope(scope)
    try:
        yield server.server_address[1], scope
    finally:
        server.shutdown()
        server.server_close()
        set_active_scope(previous)


def test_decouverte_puis_moisson_de_credential(http_server):
    port, scope = http_server
    world = WorldModel(scope=scope)
    n = discover_services(world, ["127.0.0.1"], [port], _port_open, _http_name)
    assert n == 1
    assert any(s.name == "http" and s.port == port
               for h in world.in_scope_hosts() for s in h.services)
    out = http_get_listing.invoke({"url": f"http://127.0.0.1:{port}/"})
    reconcile_evidence(world, out)
    assert any(c.principal == "Damulsan" and c.secret == "AAJJAQBenough1728!"
               for c in world.credentials)
