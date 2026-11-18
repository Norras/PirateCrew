from scope import Scope
from state.world_model import WorldModel
from catalog import load_catalog, technique_by_id
from orchestrator import (plan_tasks, route_after_integrate, reconcile_evidence,
                          _parse_services, _task_inputs_fp)
from state.world_model import Credential


def test_plan_tasks_filters_by_requires_and_ledger():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    wm.add_host("10.10.10.5")
    wm.add_service("10.10.10.5", 445, name="smb")
    cat = load_catalog()
    tasks = plan_tasks(wm, cat)
    assert any(t["service"] == "smb" for t in tasks)          # technique with no requires is proposed
    # a technique requiring a cred does not appear as long as no cred is applicable
    assert all("credential" not in technique_by_id(cat, t["technique_id"]).requires
               for t in tasks)


def test_author_model_configurable_via_env(monkeypatch):
    import orchestrator as o
    monkeypatch.delenv("PIRATECREW_AUTHOR_MODEL", raising=False)
    assert o._author_model_name() == "claude-sonnet-4-6"
    monkeypatch.setenv("PIRATECREW_AUTHOR_MODEL", "claude-opus-4-8")
    assert o._author_model_name() == "claude-opus-4-8"


def test_route_finishes_on_cycle_cap():
    assert route_after_integrate({"cycle": 6, "max_cycles": 6}) == "finish"


def test_author_context_rich():
    from orchestrator import _author_context
    w = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    w.add_service("10.0.0.5", 445, name="smb", version="Samba 4.15")
    w.add_service("10.0.0.5", 80, name="http", version="nginx 1.25")
    w.add_credential(Credential(kind="password", principal="CORP\\admin", secret="p@ss"))
    w.mark_technique("10.0.0.5", "smb", "smb-brute", status="tried", port=445)
    w.add_evidence({"phase": "execute", "technique": "smb-brute", "host": "10.0.0.5",
                    "raw": "NT_STATUS_LOGON_FAILURE for admin"})
    ctx = _author_context(w, "smb")
    assert "445" in ctx and "Samba 4.15" in ctx          # version + port of the targeted service
    assert "http" in ctx                                  # neighboring service
    assert "CORP\\admin" in ctx and "p@ss" not in ctx     # principal yes, secret no
    assert "smb-brute" in ctx and "LOGON_FAILURE" in ctx  # failed attempt + result excerpt


def test_author_context_truncates_long_outputs():
    from orchestrator import _author_context
    w = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    w.add_service("10.0.0.5", 445, name="smb")
    w.mark_technique("10.0.0.5", "smb", "t", status="tried", port=445)
    # long but low entropy (spaces) to test truncation, not masking
    w.add_evidence({"phase": "execute", "technique": "t", "host": "10.0.0.5", "raw": "failed " * 1000})
    ctx = _author_context(w, "smb")
    assert "failed failed" in ctx      # start of the excerpt is present
    assert ctx.count("failed") < 60    # truncated (not all 1000 occurrences)


def test_author_context_masks_high_entropy_unknown_hash():
    from orchestrator import _author_context
    w = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    w.add_service("10.0.0.5", 445, name="smb")
    w.mark_technique("10.0.0.5", "smb", "dump", status="tried", port=445)
    # unknown NT hash (never reconciled into a Credential) in the raw output
    w.add_evidence({"phase": "execute", "technique": "dump", "host": "10.0.0.5",
                    "raw": "Administrator ::: 31d6cfe0d16ae931b73c59d7e0c089c0 :::"})
    ctx = _author_context(w, "smb")   # no known credential -> entropy-based masking
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in ctx
    assert "***" in ctx


def test_author_context_redacts_known_secret():
    from orchestrator import _author_context
    w = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    w.add_service("10.0.0.5", 445, name="smb")
    w.add_credential(Credential(kind="password", principal="admin", secret="Summer2024!"))
    w.mark_technique("10.0.0.5", "smb", "smb-brute", status="tried", port=445)
    w.add_evidence({"phase": "execute", "technique": "smb-brute", "host": "10.0.0.5",
                    "raw": "admin:Summer2024! (valid session)"})
    ctx = _author_context(w, "smb")
    assert "Summer2024!" not in ctx   # known secret redacted from the excerpt sent to the LLM
    assert "***" in ctx               # redaction marker present


def test_author_context_adds_rag_knowledge():
    from orchestrator import _author_context
    w = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    w.add_service("10.0.0.5", 445, name="smb")
    assert "Knowledge" not in _author_context(w, "smb")          # without RAG: unchanged
    ctx = _author_context(w, "smb", extra="Note: enumerate shares over a null session")
    assert "Knowledge" in ctx and "null session" in ctx


class _Doc:
    def __init__(self, text, source=""):
        self.page_content = text
        self.metadata = {"source": source} if source else {}


def test_rag_for_author_queries_the_service_and_bounds_excerpts():
    import orchestrator as o
    queries = []

    def search(query, k):
        queries.append((query, k))
        return [_Doc("A" * 5000), _Doc("smbclient template", source="llm_authored")]
    out = o._rag_for_author("smb", search=search)
    assert "smb" in queries[0][0]
    assert "A" * 500 in out and "A" * 600 not in out                  # bounded excerpt
    assert "smbclient template" in out and "promoted technique" in out   # source flagged


def test_rag_for_author_never_raises():
    import orchestrator as o

    def boom(query, k):
        raise RuntimeError("chroma offline")
    assert o._rag_for_author("smb", search=boom) == ""
    assert o._rag_for_author("smb", search=lambda q, k: []) == ""


def test_node_decide_passes_the_rag_to_the_author(monkeypatch, tmp_path):
    import orchestrator as o
    import offense.catalog_author as author
    w = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    w.add_service("10.0.0.5", 5432, name="postgresql")               # no builtin
    monkeypatch.setattr(o, "get_world", lambda tid: w)
    monkeypatch.setattr(o, "_rag_for_author", lambda svc, search=None: f"NOTE-RAG-{svc}")
    seen = []
    monkeypatch.setattr(author, "author_technique",
                        lambda svc, ctx, invoke: seen.append((svc, ctx)) or None)
    o.node_decide({"discovered_services": []}, {"configurable": {"thread_id": "t-rag"}})
    assert seen and seen[0][0] == "postgresql" and "NOTE-RAG-postgresql" in seen[0][1]


def test_node_execute_audits_each_technique(monkeypatch):
    # Every technique going through node_execute leaves an EXEC line (id, host,
    # service, status), WITHOUT the rendered command (which would carry a credential).
    import orchestrator as orch
    import scope as scope_mod
    from pathlib import Path
    _patch_fake_agent(monkeypatch)
    monkeypatch.setattr(orch, "_CATALOG", load_catalog(operator_dir="catalog/__none__"))
    w = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    w.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_exec_audit"] = w
    cfg = {"configurable": {"thread_id": "t_exec_audit"}}
    planned = plan_tasks(w, orch._CATALOG)
    orch.node_execute({"planned": planned, "rag_context": ""}, cfg)
    audit = Path(scope_mod.AUDIT_LOG).read_text(encoding="utf-8")
    assert "EXEC" in audit
    assert "smb.port_probe" in audit and "127.0.0.1:445" in audit


def test_node_execute_audit_exec_without_credential(monkeypatch):
    # Operator offensive path: the EXEC line must NOT contain the rendered password.
    import orchestrator as orch
    import scope as scope_mod
    from pathlib import Path
    from catalog.loader import Technique
    from state.world_model import Credential
    tech = Technique(id="op.smb", name="x", domain="ad", service="smb", requires={"credential"},
                     tool="smbclient", command_template="smbclient //{target}/s -U {user}%{password} -c ls",
                     success_signal="ok", provided_by="operator")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    monkeypatch.setattr(orch.offense.executor, "execute_command",
                        lambda rendered, timeout=120: ("done", "output"))
    w = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    w.add_service("127.0.0.1", 445, name="smb")
    w.add_credential(Credential(kind="password", principal="svc", secret="Zz-Secret-1!"))
    orch._MISSIONS["t_exec_nocred"] = w
    cfg = {"configurable": {"thread_id": "t_exec_nocred"}}
    orch.node_execute({"planned": plan_tasks(w, orch._CATALOG), "rag_context": ""}, cfg)
    audit = Path(scope_mod.AUDIT_LOG).read_text(encoding="utf-8")
    exec_lines = [l for l in audit.splitlines() if "| EXEC |" in l]
    assert exec_lines and any("op.smb" in l for l in exec_lines)
    assert all("Zz-Secret-1!" not in l for l in exec_lines)  # never the secret


def test_node_recon_audits_the_scan(monkeypatch):
    # Recon is an action: it must leave a line in audit.log, even if
    # its probes only target in-scope hosts (no scope violation).
    import orchestrator as orch
    import scope as scope_mod
    from pathlib import Path
    _patch_fake_agent(monkeypatch)
    monkeypatch.setattr(orch, "_port_open", lambda h, p, timeout=1.0: False)
    w = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    orch._MISSIONS["t_audit_recon"] = w
    orch.node_recon({"target": "127.0.0.1", "cycle": 0, "question": "", "max_cycles": 6},
                    {"configurable": {"thread_id": "t_audit_recon"}})
    audit = Path(scope_mod.AUDIT_LOG).read_text(encoding="utf-8")
    assert "RECON" in audit and "127.0.0.1" in audit


def test_node_decide_audits_the_tasks(monkeypatch):
    # The planning decision is an action: the planned techniques must
    # appear in audit.log.
    import orchestrator as orch
    import scope as scope_mod
    from pathlib import Path
    w = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    w.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_audit_decide"] = w
    orch.node_decide({"discovered_services": []},
                     {"configurable": {"thread_id": "t_audit_decide"}})
    audit = Path(scope_mod.AUDIT_LOG).read_text(encoding="utf-8")
    assert "DECIDE" in audit
    assert "smb.port_probe" in audit or "smb.enum_shares" in audit


def test_integrate_captures_raw_evidence():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    n = reconcile_evidence(wm, "Found creds admin:Password1 on 10.10.10.5")
    assert n >= 1 and any(c.principal == "admin" for c in wm.credentials)


def test_out_of_scope_discovery_not_tasked():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    wm.add_host("8.8.8.8")  # out-of-scope discovery
    assert "8.8.8.8" not in [t["host"] for t in plan_tasks(wm, load_catalog())]


def test_parse_services_ignores_substrings_and_closed_ports():
    # A version number/netmask must not create a service by substring match,
    # nor must an enumeration of closed ports.
    assert _parse_services("Apache/2.2.15 built 2021") == []        # "2021" != port 21
    assert _parse_services("Netmask 255.255.255.0") == []
    assert _parse_services("Host down. Checked 21,22,80,445 - none open.") == []


def test_parse_services_detects_open_services():
    txt = "PORT   STATE SERVICE\n445/tcp open  microsoft-ds\n80/tcp open http"
    svc = _parse_services(txt)
    assert "smb" in svc and "http" in svc


def test_reconcile_requires_credential_cue():
    # Ordinary 'word:value' prose WITHOUT a credential cue => no false secret.
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    reconcile_evidence(wm, "Server:nginx\nHost:10.10.10.9\nDomain:WORKGROUP")
    assert wm.credentials == []


def test_task_inputs_fp_changes_when_new_cred_discovered():
    # R2: a new applicable credential changes the fingerprint => technique re-opened.
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    wm.add_credential(Credential(kind="password", principal="svcA", secret="a", source="t"))
    fp1 = _task_inputs_fp(wm, "smb", {"credential"})
    wm.add_credential(Credential(kind="password", principal="svcB", secret="b", source="t"))
    fp2 = _task_inputs_fp(wm, "smb", {"credential"})
    assert fp1 and fp2 and fp1 != fp2


def test_task_inputs_fp_empty_without_credential_requirement():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    assert _task_inputs_fp(wm, "smb", set()) == ""


# --- Milestone 1: port propagation + "missing tool" escalation (Option Y) --- #
def test_plan_task_carries_service_port():
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 8080, name="http")
    http_tasks = [t for t in plan_tasks(wm, load_catalog()) if t["service"] == "http"]
    assert http_tasks and all(t.get("port") == 8080 for t in http_tasks)


def test_technique_available_python_vs_missing_binary(monkeypatch):
    import orchestrator as orch
    cat = load_catalog()
    assert orch.technique_available(technique_by_id(cat, "http.fingerprint")) is True
    monkeypatch.setattr(orch.shutil, "which", lambda b: None)
    assert orch.technique_available(technique_by_id(cat, "smb.enum_shares")) is False


def test_render_template_fills_target_and_port():
    import orchestrator as orch
    assert orch._render_template("x http://{target}:{port}/", "127.0.0.1", 8080) == "x http://127.0.0.1:8080/"
    assert orch._render_template("", "127.0.0.1", 80) == ""


def test_render_template_substitutes_credential_fields():
    import orchestrator as orch
    from state.world_model import Credential
    creds = [Credential(kind="hash", principal="CORP\\admin", secret="aad3b:deadbeef", source="t")]
    out = orch._render_template("evil-winrm -i {target} -u {user} -H {hash}", "127.0.0.1", creds=creds)
    assert out == "evil-winrm -i 127.0.0.1 -u admin -H aad3b:deadbeef"


def test_render_template_domain_from_principal():
    import orchestrator as orch
    from state.world_model import Credential
    creds = [Credential(kind="password", principal="user@corp.local", secret="P@ss", source="t")]
    out = orch._render_template("cmd {user} {domain} {password}", "127.0.0.1", creds=creds)
    assert out == "cmd user corp.local P@ss"


def test_render_template_unknown_placeholder_returns_raw():
    import orchestrator as orch
    # No cred: unknown {user} -> raw template (Project 1 contract unchanged).
    assert orch._render_template("x {user}", "127.0.0.1") == "x {user}"


def _patch_fake_agent(monkeypatch):
    class _Msg:
        content = "OK (fake)"

    class _FakeAgent:
        def invoke(self, _):
            return {"messages": [_Msg()]}

    monkeypatch.setattr("agents.dynamic_agent.build_task_agent",
                        lambda domain, world=None, mission_context="": _FakeAgent())


def test_blocked_missing_tool_escalates_and_not_marked_tried(monkeypatch, tmp_path):
    import orchestrator as orch
    from state import mission_io
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    _patch_fake_agent(monkeypatch)
    monkeypatch.setattr(orch.shutil, "which", lambda b: None)  # smbclient absent
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_block"] = wm
    cfg = {"configurable": {"thread_id": "t_block"}}
    planned = plan_tasks(wm, orch._CATALOG)
    reports = orch.node_execute({"planned": planned}, cfg)["execution_reports"]
    assert any(r["status"] == "blocked_missing_tool" and r["tool"] == "smbclient" for r in reports)
    out = orch.node_integrate({"planned": planned, "execution_reports": reports, "cycle": 0}, cfg)
    assert "smbclient" in out["final_response"]
    # blocked => NOT marked (replannable after install); executed => marked
    assert wm.is_tried("127.0.0.1", "smb", "smb.enum_shares", inputs_fp="", port=445) is False
    assert wm.is_tried("127.0.0.1", "smb", "smb.port_probe", inputs_fp="", port=445) is True


def test_route_finishes_when_only_blocked_tasks_remain(monkeypatch):
    import orchestrator as orch
    monkeypatch.setattr(orch.shutil, "which", lambda b: None)  # smbclient absent
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    wm.mark_technique("127.0.0.1", "smb", "smb.port_probe", inputs_fp="", port=445)
    orch._MISSIONS["t_route_block"] = wm
    assert route_after_integrate({"cycle": 1, "max_cycles": 6, "thread_id": "t_route_block"}) == "finish"


def test_route_continues_when_runnable_task_remains():
    import orchestrator as orch
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 80, name="http")
    orch._MISSIONS["t_route_cont"] = wm
    assert route_after_integrate({"cycle": 1, "max_cycles": 6, "thread_id": "t_route_cont"}) == "continue"


def test_start_mission_reuses_worldmodel_on_same_thread():
    import orchestrator as orch
    sc = Scope.from_lines(["127.0.0.1/32"])
    w1 = orch.start_mission("t_reuse", sc)
    w1.mark_technique("127.0.0.1", "smb", "smb.port_probe", inputs_fp="", port=445)
    w2 = orch.start_mission("t_reuse", sc)
    assert w2 is w1 and w2.is_tried("127.0.0.1", "smb", "smb.port_probe", inputs_fp="", port=445) is True
    assert orch.start_mission("t_other_thread", sc) is not w1


def test_requested_ports_host_port():
    from orchestrator import requested_ports
    assert requested_ports("run an analysis on 127.0.0.1:8980") == [8980]


def test_requested_ports_word_port():
    from orchestrator import requested_ports
    assert requested_ports("check port 8980") == [8980]


def test_requested_ports_none():
    from orchestrator import requested_ports
    assert requested_ports("analyze the whole authorized scope") == []


def test_requested_ports_out_of_range():
    from orchestrator import requested_ports
    assert requested_ports("port 99999") == []


def _services_named(wm, host, port):
    return [s.name for h in wm.in_scope_hosts() if h.ip == host
            for s in h.services if s.port == port]


def test_discover_services_fingerprint_names_unusual_port():
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    n = discover_services(wm, ["127.0.0.1"], [80, 8980],
                          probe=lambda h, p: p == 8980,
                          fingerprint=lambda h, p: "http")
    assert n == 1
    assert _services_named(wm, "127.0.0.1", 8980) == ["http"]


def test_discover_services_known_port_uses_mapping():
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    discover_services(wm, ["127.0.0.1"], [80, 8980], probe=lambda h, p: p == 80)
    assert _services_named(wm, "127.0.0.1", 80) == ["http"]


def test_discover_services_nothing_open():
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    n = discover_services(wm, ["127.0.0.1"], [80, 8980], probe=lambda h, p: False)
    assert n == 0
    assert [s for h in wm.in_scope_hosts() for s in h.services] == []


def test_reconcile_credential_on_line_after_cue():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    reconcile_evidence(wm, "Cred for DC :\nDamulsan:AAJJAQBenough1728!")
    assert any(c.principal == "Damulsan" and c.secret == "AAJJAQBenough1728!"
               for c in wm.credentials)


def test_reconcile_no_cue_word_adds_no_credential():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    reconcile_evidence(wm, "Server:nginx\nHost:10.0.0.1")
    assert len(wm.credentials) == 0


def test_reconcile_ignores_header_like_value_near_cue():
    # A compact "Key:value" header inside a cue's window must NOT
    # become a false credential (anti-fabrication guard, see "Server:nginx").
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    reconcile_evidence(wm, "Password policy:\nServer:nginx")
    assert len(wm.credentials) == 0


def _creds(text):
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    reconcile_evidence(wm, text)
    return {(c.principal, c.secret) for c in wm.credentials}


def test_reconcile_key_value_french():
    # "key = value" configuration file with French key names: neighboring identifier + password.
    assert _creds("[sauvegarde]\nutilisateur = svc-sauvegarde\nmot_de_passe = Lab-Fictif-2026!") \
        == {("svc-sauvegarde", "Lab-Fictif-2026!")}


def test_reconcile_key_value_env_yaml_json():
    assert _creds('DB_USER=app\nDB_PASSWORD="s3cret!"') == {("app", "s3cret!")}
    assert _creds("db:\n  username: alice\n  password: 'Wond3rland'") == {("alice", "Wond3rland")}
    assert _creds('{\n  "login": "bob",\n  "passwd": "B0bPass!",\n}') == {("bob", "B0bPass!")}


def test_reconcile_key_value_without_identifier_or_dummy_value():
    assert _creds("password = hunter2") == set()                      # no neighboring identifier
    assert _creds("user = admin\npassword = ${DB_PASS}") == set()     # variable, not a secret
    assert _creds("user = admin\npassword = ********") == set()       # masked
    assert _creds("user = admin\npassword =") == set()                # empty
    assert _creds("user = admin\n\n\n\n\npassword = hunter2") == set()  # too far apart


def test_reconcile_key_name_never_mistaken_for_an_identifier():
    # "password:hunter2" on a cue line: the principal would be "password".
    assert _creds("password:hunter2") == set()


def test_reconcile_french_cue_for_the_identifier_secret_form():
    assert _creds("Identifiants du serveur :\nbob:Sup3rSecret") == {("bob", "Sup3rSecret")}


def test_node_integrate_reads_tool_outputs_not_only_the_summary(monkeypatch, tmp_path):
    # Agent path (builtin): the LLM summary does not copy the file read, but the
    # tool output contains it — the back-stop must see it.
    import orchestrator as orch
    from state import mission_io
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)

    class _Tool:
        type = "tool"
        content = "HTTP 200\n[site]\nutilisateur = svc-x\nmot_de_passe = Xy-Fictif-99!"

    class _Final:
        type = "ai"
        content = "I read the backup file."

    class _Agent:
        def invoke(self, _):
            return {"messages": [_Tool(), _Final()]}
    monkeypatch.setattr("agents.dynamic_agent.build_task_agent",
                        lambda domain, world=None, mission_context="": _Agent())
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    wm.add_service("10.10.10.5", 80, name="http")
    orch._MISSIONS["t_tool_out"] = wm
    cfg = {"configurable": {"thread_id": "t_tool_out"}}
    planned = [t for t in plan_tasks(wm, orch._CATALOG) if t["technique_id"] == "http.get"]
    reports = orch.node_execute({"planned": planned, "rag_context": ""}, cfg)["execution_reports"]
    orch.node_integrate({"planned": planned, "execution_reports": reports, "cycle": 0}, cfg)
    assert any(c.principal == "svc-x" and c.secret == "Xy-Fictif-99!" for c in wm.credentials)


def test_discover_services_logs_each_open_port():
    # Verbose mode: a `log` callback receives one line per open port (and none
    # for closed ports), with the host, the port and the detected service.
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    msgs = []
    discover_services(wm, ["127.0.0.1"], [80, 8980],
                      probe=lambda h, p: p == 8980,
                      fingerprint=lambda h, p: "http",
                      log=msgs.append)
    assert len(msgs) == 1
    assert "8980" in msgs[0] and "http" in msgs[0]


def test_vprint_respects_verbose_flag(capsys):
    # _vprint only prints when verbose mode is on; set_verbose toggles it.
    import orchestrator as orch
    orch.set_verbose(False)
    orch._vprint("hidden")
    assert capsys.readouterr().out == ""
    orch.set_verbose(True)
    orch._vprint("visible")
    assert "visible" in capsys.readouterr().out
    orch.set_verbose(False)  # restore the global state


def test_wants_full_scan_detects_phrases():
    # Recognizes an intent to sweep the FULL range; ignores an explicit port or the
    # mere word "tout" (scope) without "ports". The French phrasings are intentional:
    # the detection regex matches French requests.
    from orchestrator import wants_full_scan
    assert wants_full_scan("scanne tous les ports") is True
    assert wants_full_scan("fais un scan complet de 127.0.0.1") is True
    assert wants_full_scan("attaque 127.0.0.1:8980") is False
    assert wants_full_scan("analyse tout le périmètre autorisé") is False


def test_discover_services_parallel_finds_open_ports():
    # Parallel probing (workers>1): finds the same open ports, deterministic
    # result, sequential registration in the WorldModel.
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    opened = {22, 8980}
    n = discover_services(wm, ["127.0.0.1"], [22, 80, 8980],
                          probe=lambda h, p: p in opened,
                          workers=4)
    assert n == 2
    ports_found = sorted(s.port for h in wm.in_scope_hosts() for s in h.services)
    assert ports_found == [22, 8980]


def test_autonomous_discovery_escalates_on_empty_host():
    from orchestrator import autonomous_discovery
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    # nothing on the default ports; one service on a high non-default port
    probe = lambda h, p: p == 50000
    n = autonomous_discovery(wm, ["127.0.0.1"], [80, 443], probe=probe,
                             fingerprint=lambda h, p: "http")
    assert n == 1
    assert any(s.port == 50000 and s.name == "http"
               for h in wm.in_scope_hosts() for s in h.services)


def test_autonomous_discovery_no_escalation_when_service_found():
    from orchestrator import autonomous_discovery
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    probe = lambda h, p: p in (80, 50000)   # 80 is in the defaults
    autonomous_discovery(wm, ["127.0.0.1"], [80], probe=probe)
    ports = sorted(s.port for h in wm.in_scope_hosts() for s in h.services)
    assert ports == [80]  # no escalation → 50000 never probed/registered


def test_node_integrate_persists_world_each_cycle(tmp_path, monkeypatch):
    import orchestrator as orch
    from state import mission_io
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    sc = Scope.from_lines(["127.0.0.1/32"])
    orch.start_mission("mX", sc)
    state = {"execution_reports": [], "cycle": 0, "thread_id": "mX"}
    orch.node_integrate(state, {"configurable": {"thread_id": "mX"}})
    assert (tmp_path / "mX" / "world.json").exists()


def test_requires_session_needs_authorized_session():
    import orchestrator as orch
    from state.world_model import Session
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_session(Session(host="127.0.0.1", channel="evil-winrm", authorized=False))
    assert orch._requires_satisfied(wm, "127.0.0.1", "smb", {"session"}) is False
    assert orch.authorize_sessions(wm, "127.0.0.1") == 1
    assert orch._requires_satisfied(wm, "127.0.0.1", "smb", {"session"}) is True


def test_authorize_sessions_counts_only_unauthorized_alive():
    import orchestrator as orch
    from state.world_model import Session
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_session(Session(host="127.0.0.1", channel="ssh", authorized=True))
    wm.add_session(Session(host="127.0.0.1", channel="x", alive=False))
    assert orch.authorize_sessions(wm, "127.0.0.1") == 0


def test_node_execute_runs_offensive_technique_deterministically(monkeypatch, tmp_path):
    import orchestrator as orch
    from state import mission_io
    from catalog.loader import Technique
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    # agent = tripwire: if it is called on an offensive technique, the test fails
    def _boom(*a, **k): raise AssertionError("the agent must not execute an offensive technique")
    monkeypatch.setattr("agents.dynamic_agent.build_task_agent", _boom)
    tech = Technique(id="llm.win", name="n", domain="ad", service="smb", requires=set(),
                     tool="crackmapexec", command_template="crackmapexec smb {target} -u {user} -H {hash}",
                     success_signal="Pwn3d", provided_by="llm", opens_session=True)
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    monkeypatch.setattr("offense.executor.execute_command",
                        lambda rendered, **kw: ("done", "STATUS ... (Pwn3d!) ..."))
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    wm.add_credential(Credential(kind="hash", principal="admin", secret="h", source="t"))
    orch._MISSIONS["t_off"] = wm
    cfg = {"configurable": {"thread_id": "t_off"}}
    planned = plan_tasks(wm, orch._CATALOG)
    reports = orch.node_execute({"planned": planned, "rag_context": ""}, cfg)["execution_reports"]
    assert any(r["status"] == "done" and r["technique"] == "llm.win" for r in reports)
    assert any(s.host == "127.0.0.1" and s.authorized is False for s in wm.sessions)


def test_propose_only_skips_llm_execution(monkeypatch, tmp_path):
    import orchestrator as orch
    from state import mission_io
    from catalog.loader import Technique
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    monkeypatch.setattr("offense.executor.execute_command",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not execute")))
    tech = Technique(id="llm.x", name="n", domain="ad", service="smb", requires=set(),
                     tool="cme", command_template="cme smb {target}", success_signal="ok",
                     provided_by="llm")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    orch.set_propose_only(True)
    try:
        wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
        wm.add_service("127.0.0.1", 445, name="smb"); orch._MISSIONS["t_po"] = wm
        cfg = {"configurable": {"thread_id": "t_po"}}
        reports = orch.node_execute({"planned": plan_tasks(wm, orch._CATALOG), "rag_context": ""}, cfg)["execution_reports"]
        assert any(r["status"] == "proposed_awaiting_operator" for r in reports)
    finally:
        orch.set_propose_only(False)


def test_dry_services_detects_service_without_technique():
    import orchestrator as orch
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 9999, name="exotic")   # no builtin for "exotic"
    assert "exotic" in orch._dry_services(wm, orch._CATALOG, planned=[])
    wm.add_service("127.0.0.1", 445, name="smb")        # smb has builtins
    assert "smb" not in orch._dry_services(wm, orch._CATALOG, planned=plan_tasks(wm, orch._CATALOG))


def test_node_execute_skips_unfillable_placeholder_without_executing(monkeypatch, tmp_path):
    # A template with an unfillable placeholder ({share} with no value) MUST NOT
    # run raw: we report blocked_missing_input, the executor is never called.
    import orchestrator as orch
    from state import mission_io
    from catalog.loader import Technique
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    monkeypatch.setattr("offense.executor.execute_command",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("must not execute an unrendered template")))
    tech = Technique(id="llm.share", name="n", domain="ad", service="smb", requires=set(),
                     tool="smbclient", command_template="smbclient //{target}/{share} -U {user}",
                     success_signal="ok", provided_by="llm")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    wm.add_credential(Credential(kind="password", principal="admin", secret="x", source="t"))
    orch._MISSIONS["t_share"] = wm
    cfg = {"configurable": {"thread_id": "t_share"}}
    planned = plan_tasks(wm, orch._CATALOG)
    reports = orch.node_execute({"planned": planned, "rag_context": ""}, cfg)["execution_reports"]
    r = next(r for r in reports if r["technique"] == "llm.share")
    assert r["status"] == "blocked_missing_input" and "share" in r["detail"]


def test_node_execute_blocks_out_of_scope_literal_ip(monkeypatch, tmp_path):
    # A LITERAL out-of-scope host in the template (operator/LLM) is blocked BEFORE
    # execution (check on the template), the executor is never called.
    import orchestrator as orch
    from state import mission_io
    from catalog.loader import Technique
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    monkeypatch.setattr("offense.executor.execute_command",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("must not execute an out-of-scope technique")))
    tech = Technique(id="op.x", name="n", domain="network", service="smb", requires=set(),
                     tool="nmap", command_template="nmap -sV {target} 10.0.0.9",
                     success_signal="open", provided_by="operator")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_oos"] = wm
    cfg = {"configurable": {"thread_id": "t_oos"}}
    planned = plan_tasks(wm, orch._CATALOG)
    reports = orch.node_execute({"planned": planned, "rag_context": ""}, cfg)["execution_reports"]
    r = next(r for r in reports if r["technique"] == "op.x")
    assert r["status"] == "blocked_out_of_scope" and "10.0.0.9" in r["detail"]


def test_node_execute_blocks_out_of_scope_hostname_resolving(monkeypatch, tmp_path):
    # A literal HOST NAME is resolved then checked at execution time ("resolve + report" model).
    import orchestrator as orch
    import scope
    from state import mission_io
    from catalog.loader import Technique
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    monkeypatch.setattr(scope.socket, "gethostbyname",
                        lambda n: "203.0.113.9" if n == "evil.example.com" else (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr("offense.executor.execute_command",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not execute")))
    tech = Technique(id="op.h", name="n", domain="network", service="smb", requires=set(),
                     tool="nmap", command_template="nmap -sV {target} evil.example.com",
                     success_signal="open", provided_by="operator")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    wm = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    wm.add_service("10.0.0.5", 445, name="smb")
    orch._MISSIONS["t_h"] = wm
    cfg = {"configurable": {"thread_id": "t_h"}}
    reports = orch.node_execute({"planned": plan_tasks(wm, orch._CATALOG), "rag_context": ""},
                                cfg)["execution_reports"]
    r = next(r for r in reports if r["technique"] == "op.h")
    assert r["status"] == "blocked_out_of_scope" and "evil.example.com" in r["detail"]


def test_node_integrate_marks_missing_input_tried(monkeypatch, tmp_path):
    # blocked_missing_input is marked 'tried' (loop-safe: no infinite replanning).
    import orchestrator as orch
    from state import mission_io
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_mi"] = wm
    cfg = {"configurable": {"thread_id": "t_mi"}}
    reports = [{"technique": "llm.share", "host": "127.0.0.1", "service": "smb", "port": 445,
                "inputs_fp": "", "status": "blocked_missing_input", "detail": "missing {share}"}]
    orch.node_integrate({"planned": [], "execution_reports": reports, "cycle": 0}, cfg)
    assert wm.is_tried("127.0.0.1", "smb", "llm.share", inputs_fp="", port=445) is True


def test_blocked_no_netns_escalates_and_is_not_marked_tried(monkeypatch, tmp_path):
    # Network perimeter absent: the technique is NOT burned (replannable after
    # `offense.netns up`), the operator is warned, and the error message — which cites
    # addresses — does not feed the world model.
    import orchestrator as orch
    from state import mission_io
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    wm = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    wm.add_service("10.0.0.5", 445, name="smb")
    orch._MISSIONS["t_nn"] = wm
    cfg = {"configurable": {"thread_id": "t_nn"}}
    reports = [{"technique": "op.n", "host": "10.0.0.5", "service": "smb", "port": 445,
                "inputs_fp": "", "status": "blocked_no_netns",
                "detail": "The installed network perimeter (10.0.0.77) does not match"}]
    out = orch.node_integrate({"planned": [], "execution_reports": reports, "cycle": 0}, cfg)
    assert wm.is_tried("10.0.0.5", "smb", "op.n", inputs_fp="", port=445) is False
    assert out["netns_missing"] is True
    assert "sudo python -m offense.netns up" in out["final_response"]
    assert "10.0.0.77" not in wm.hosts


def test_no_netns_through_node_execute_then_integrate(monkeypatch, tmp_path):
    # Same contract, end to end: the executor's status goes through node_execute
    # as is, and node_integrate does not burn the technique.
    import orchestrator as orch
    from state import mission_io
    from catalog.loader import Technique
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    monkeypatch.setattr("offense.executor.execute_command",
                        lambda rendered, **kw: ("blocked_no_netns", "namespace missing"))
    tech = Technique(id="op.n", name="n", domain="network", service="smb", requires=set(),
                     tool="nmap", command_template="nmap -sV {target}",
                     success_signal="open", provided_by="operator")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_nn3"] = wm
    cfg = {"configurable": {"thread_id": "t_nn3"}}
    planned = plan_tasks(wm, orch._CATALOG)
    reports = orch.node_execute({"planned": planned, "rag_context": ""}, cfg)["execution_reports"]
    assert [r["status"] for r in reports if r["technique"] == "op.n"] == ["blocked_no_netns"]
    out = orch.node_integrate({"planned": planned, "execution_reports": reports, "cycle": 0}, cfg)
    assert out["netns_missing"] is True
    assert wm.is_tried("127.0.0.1", "smb", "op.n", inputs_fp="", port=445) is False
    assert plan_tasks(wm, orch._CATALOG)          # still replannable after `up`


def test_node_integrate_clears_netns_missing_when_nothing_blocked(monkeypatch, tmp_path):
    import orchestrator as orch
    from state import mission_io
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    wm = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    orch._MISSIONS["t_nn2"] = wm
    out = orch.node_integrate({"planned": [], "execution_reports": [], "cycle": 0,
                               "netns_missing": True}, {"configurable": {"thread_id": "t_nn2"}})
    assert out["netns_missing"] is False


def _smb_exhausted(thread_id, monkeypatch):
    import orchestrator as orch
    # Builtin catalog ONLY: these tests are about exhausting the service's builtin
    # techniques, not the local operator arsenal (catalog/operator/*.yaml),
    # which would make the result machine-dependent.
    monkeypatch.setattr(orch, "_CATALOG", load_catalog(operator_dir="catalog/__none__"))
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    for tid in ("smb.port_probe", "smb.enum_shares"):
        wm.mark_technique("127.0.0.1", "smb", tid, inputs_fp="", port=445)
    orch._MISSIONS[thread_id] = wm
    return wm


def test_route_continues_to_let_the_author_handle_an_exhausted_service(monkeypatch):
    # All the service's builtin techniques tried: the mission must go back through
    # decide, where the LLM author takes over — not stop before.
    import orchestrator as orch
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    _smb_exhausted("t_route_dry", monkeypatch)
    base = {"cycle": 1, "max_cycles": 6, "thread_id": "t_route_dry"}
    assert route_after_integrate(base) == "continue"
    # without a network perimeter, an LLM technique could not run: finish
    assert route_after_integrate({**base, "netns_missing": True}) == "finish"


def test_author_one_attempt_per_service(monkeypatch):
    # The author proposes nothing usable: the attempt counts anyway, otherwise the
    # loop would call it again every cycle up to the cap.
    import orchestrator as orch
    import offense.catalog_author as author
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    monkeypatch.setattr(orch, "_rag_for_author", lambda svc, search=None: "")
    calls = []
    monkeypatch.setattr(author, "author_technique",
                        lambda svc, ctx, invoke: calls.append(svc) or None)
    _smb_exhausted("t_author_once", monkeypatch)
    cfg = {"configurable": {"thread_id": "t_author_once"}}
    orch.node_decide({"discovered_services": []}, cfg)
    orch.node_decide({"discovered_services": []}, cfg)
    assert calls == ["smb"]
    assert route_after_integrate({"cycle": 2, "max_cycles": 6,
                                  "thread_id": "t_author_once"}) == "finish"


def test_route_does_not_loop_on_an_llm_technique_in_propose_only(monkeypatch):
    import orchestrator as orch
    from catalog.loader import Technique
    tech = Technique(id="llm.x", name="x", domain="ad", service="smb", requires=set(),
                     tool="smbclient", command_template="smbclient -L //{target} -N",
                     success_signal="Sharename", provided_by="llm")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    wm.add_evidence({"kind": "llm_technique", "service": "smb", "id": "llm.x"})
    orch._MISSIONS["t_route_po"] = wm
    base = {"cycle": 1, "max_cycles": 6, "thread_id": "t_route_po"}
    assert route_after_integrate(base) == "continue"
    monkeypatch.setattr(orch, "_PROPOSE_ONLY", True)
    assert route_after_integrate(base) == "finish"      # proposed, never executed: no loop


def test_route_finishes_when_only_netns_blocked_tasks_remain(monkeypatch):
    # Without the network perimeter, operator/llm techniques are not runnable:
    # the loop does not spin idle up to the cycle cap.
    import orchestrator as orch
    from catalog.loader import Technique
    tech = Technique(id="op.n", name="n", domain="network", service="smb", requires=set(),
                     tool="nmap", command_template="nmap -sV {target}",
                     success_signal="open", provided_by="operator")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_route_netns"] = wm
    base = {"cycle": 1, "max_cycles": 6, "thread_id": "t_route_netns"}
    assert route_after_integrate(base) == "continue"
    assert route_after_integrate({**base, "netns_missing": True}) == "finish"


def test_netns_missing_is_a_declared_state_channel():
    # LangGraph only accepts, as node output, keys declared in the state.
    import orchestrator as orch
    assert "netns_missing" in orch.MissionState.__annotations__
