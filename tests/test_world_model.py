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
