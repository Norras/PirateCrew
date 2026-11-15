from scope import Scope
from state.world_model import WorldModel, Credential, inputs_fingerprint


def _wm():
    return WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))


def test_add_host_in_scope():
    wm = _wm()
    h = wm.add_host("10.10.10.5")
    assert h.in_scope is True and "10.10.10.5" in wm.hosts


def test_add_host_out_of_scope_flagged_not_raised():
    wm = _wm()
    h = wm.add_host("8.8.8.8")
    assert h.in_scope is False
    assert "8.8.8.8" not in [x.ip for x in wm.in_scope_hosts()]


def test_cred_propagates_between_agents():
    wm = _wm()
    wm.add_credential(Credential(kind="password", principal="svc", secret="P@ss", source="agentA"))
    assert any(c.principal == "svc" for c in wm.creds_applicable("smb"))


def test_ledger_keyed_by_inputs():
    wm = _wm()
    wm.mark_technique("10.10.10.5", "smb", "smb.exploit", inputs_fp="", status="fail")
    assert wm.is_tried("10.10.10.5", "smb", "smb.exploit", inputs_fp="") is True
    fp = inputs_fingerprint({"cred": "svc:P@ss"})
    assert wm.is_tried("10.10.10.5", "smb", "smb.exploit", inputs_fp=fp) is False


def test_add_service_updates_name_when_first_seen_anonymously():
    # Un port peut être remonté ouvert AVANT d'être identifié (name="") puis nommé.
    wm = _wm()
    wm.add_service("10.10.10.5", 445, name="")        # vu ouvert, pas encore identifié
    svc = wm.add_service("10.10.10.5", 445, name="smb")  # identifié ensuite
    assert svc.name == "smb"                           # le nom tardif n'est pas perdu
    host = wm.hosts["10.10.10.5"]
    assert len([s for s in host.services if s.port == 445]) == 1  # toujours dédupliqué
    assert "smb" in {s.name for s in host.services if s.name}


def test_add_service_fills_version_on_existing():
    wm = _wm()
    wm.add_service("10.10.10.5", 445, name="smb")
    wm.add_service("10.10.10.5", 445, name="smb", version="Samba 4.x")
    svc = next(s for s in wm.hosts["10.10.10.5"].services if s.port == 445)
    assert svc.version == "Samba 4.x"


def test_out_of_scope_host_trace_escapes_newline():
    # conftest redirige déjà scope.AUDIT_LOG vers un tmp isolé.
    import scope as scope_mod
    from pathlib import Path
    wm = _wm()
    wm.add_host("8.8.8.8\n2026-01-01T00:00:00 | RUN | nmap -A 10.0.0.1")  # hors-scope + newline
    audit = Path(scope_mod.AUDIT_LOG).read_text(encoding="utf-8")
    assert audit.count("\n") == 1 and audit.endswith("\n")  # une seule ligne, pas deux
    assert "\\n" in audit                                    # le saut de ligne est échappé
    assert "| OUT_OF_SCOPE |" in audit


def test_ledger_distinguishes_port():
    # Deux services de même nom sur des ports différents ne doivent pas se
    # confondre dans le ledger : marquer l'un ne marque pas l'autre.
    wm = _wm()
    wm.mark_technique("10.10.10.5", "http", "http.get", inputs_fp="", port=80)
    assert wm.is_tried("10.10.10.5", "http", "http.get", inputs_fp="", port=80) is True
    assert wm.is_tried("10.10.10.5", "http", "http.get", inputs_fp="", port=8080) is False
