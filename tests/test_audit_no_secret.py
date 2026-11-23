"""audit.log must never carry a secret or a rendered command — ON ANY CHANNEL.

The README guarantees audit.log holds only STRUCTURAL fields: no password, no
rendered command, no loot. The pre-existing suite only checked the FINDING
channel; these cover the rest:

- `_run` (RUN / TIMEOUT): the subprocess argv — where credentials and targets
  live — must not be written. Only the binary name is structural.
- `AGENT:` (`log_audit_event`): agent-controlled free text must have known
  secrets redacted.
- any channel: a credential recorded in the world model is redacted everywhere,
  via a central registry scrubbed at the single `_audit_escape` choke point.
"""
import subprocess
import types

import pytest

import scope
import tools.registry as reg
from scope import Scope
from state.world_model import WorldModel, Credential


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Redirect both audit sinks to a temp file and reset the secret registry."""
    log = str(tmp_path / "audit.log")
    monkeypatch.setattr(reg, "AUDIT_LOG", log)
    monkeypatch.setattr(scope, "AUDIT_LOG", log)
    if hasattr(scope, "_SECRETS"):
        scope._SECRETS.clear()
    yield log
    if hasattr(scope, "_SECRETS"):
        scope._SECRETS.clear()


def _read(log):
    with open(log, encoding="utf-8") as fh:
        return fh.read()


def test_run_audit_logs_only_the_binary_not_arguments(_isolate, monkeypatch):
    monkeypatch.setattr(
        reg.subprocess, "run",
        lambda *a, **k: types.SimpleNamespace(stdout="shares", stderr=""),
    )
    reg._run(["smbclient", "//10.10.10.5/archives", "-U", "svc%TopS3cret!", "-c", "ls"])
    audit = _read(_isolate)
    assert "RUN" in audit and "smbclient" in audit   # the fact a binary ran is traced
    assert "TopS3cret!" not in audit                 # the credential never reaches audit.log
    assert "svc%" not in audit
    assert "-U" not in audit                         # no rendered argument at all
    assert "archives" not in audit


def test_run_timeout_audit_omits_the_rendered_command(_isolate, monkeypatch):
    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="smbclient", timeout=1)
    monkeypatch.setattr(reg.subprocess, "run", _boom)
    reg._run(["smbclient", "//10.10.10.5/archives", "-U", "svc%TopS3cret!"], timeout=1)
    audit = _read(_isolate)
    assert "TIMEOUT" in audit
    assert "TopS3cret!" not in audit
    assert "svc%" not in audit


def test_log_audit_event_redacts_a_registered_secret(_isolate):
    scope.register_secret("TopS3cret!")
    reg.log_audit_event.invoke({"action": "note", "detail": "logged in as svc / TopS3cret!"})
    audit = _read(_isolate)
    assert "AGENT:note" in audit
    assert "TopS3cret!" not in audit
    assert "***" in audit


def test_add_credential_registers_the_secret_for_redaction(_isolate):
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    wm.add_credential(Credential(kind="password", principal="svc", secret="Hunter2xyz"))
    scope._audit("NOTE", "exfil Hunter2xyz from host")
    audit = _read(_isolate)
    assert "Hunter2xyz" not in audit
    assert "***" in audit


def test_short_value_is_not_registered_to_avoid_over_redaction(_isolate):
    scope.register_secret("ab")                  # too short: must be ignored
    scope._audit("NOTE", "label abcd stays intact")
    audit = _read(_isolate)
    assert "abcd" in audit
    assert "***" not in audit
