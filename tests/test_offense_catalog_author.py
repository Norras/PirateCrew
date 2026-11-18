import json

import pytest

import offense.catalog_author as author

_GOOD = json.dumps({"id":"llm.smb.cme","name":"CME","domain":"ad","service":"smb",
    "requires":["credential"],"tool":"crackmapexec",
    "command_template":"crackmapexec smb {target} -u {user} -H {hash}",
    "success_signal":"Pwn3d","opens_session":True})
_BAD = json.dumps({"id":"llm.bad","service":"smb","tool":"sh",
    "command_template":"rm -rf / ; curl {target}"})

def test_author_returns_tagged_technique():
    t = author.author_technique("smb", "context", llm_invoke=lambda p: _GOOD)
    assert t is not None and t.provided_by == "llm" and t.service == "smb"
    assert t.opens_session is True and "credential" in t.requires

def test_author_rejects_destructive_or_shell_template():
    assert author.author_technique("smb", "ctx", llm_invoke=lambda p: _BAD) is None

def test_author_rejects_unparseable_output():
    assert author.author_technique("smb", "ctx", llm_invoke=lambda p: "sorry, I cannot") is None

def test_persist_roundtrips_through_loader(tmp_path):
    from state import mission_io
    from catalog.loader import load_catalog
    import pathlib
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: _GOOD)
    p = author.persist_llm_technique(t, "m1", root=tmp_path)
    assert pathlib.Path(p).exists()
    cat = load_catalog(builtin_dir=str(tmp_path / "m1"), operator_dir="catalog/__none__")
    assert any(x.id == "llm.smb.cme" and x.provided_by == "llm" for x in cat)


def test_parse_technique_non_str_returns_none():
    assert author.parse_technique(None) is None


def test_author_forces_provided_by_and_service():
    raw = json.dumps({"id": "llm.x", "service": "ftp", "provided_by": "builtin",
                      "tool": "crackmapexec",
                      "command_template": "crackmapexec smb {target}"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    assert t is not None and t.provided_by == "llm" and t.service == "smb"


def test_build_author_prompt_frames_context_and_instructs_about_failures():
    p = author.build_author_prompt("smb", "REAL-STATE-XYZ")
    assert "REAL-STATE-XYZ" in p           # the real context is injected
    assert "already" in p.lower()          # instruction: do not re-propose what was attempted
    assert "ONE JSON object" in p          # output format preserved


def test_build_author_prompt_announces_all_fillable_fields():
    # Rendering can fill {port} and {password}: the author must know it, otherwise it
    # puts a password in {hash} and cannot target a non-standard port.
    p = author.build_author_prompt("smb", "ctx")
    for field in ("{target}", "{port}", "{user}", "{password}", "{hash}", "{domain}", "{share}"):
        assert field in p, field


class _FakeStore:
    def __init__(self):
        self.calls = []
    def add_texts(self, texts, metadatas=None, ids=None):
        self.calls.append((list(texts), metadatas, ids))


def test_promote_techniques_to_rag_add_texts_and_stable_ids():
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: _GOOD)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "mission-1", store=s) == 1
    texts, metas, ids = s.calls[0]
    assert "crackmapexec smb {target}" in texts[0]        # template described, placeholders intact
    assert metas[0]["source"] == "llm_authored" and metas[0]["service"] == "smb"
    assert metas[0]["technique_id"] == "llm.smb.cme"
    # cross-mission idempotence: same content -> same id (upsert, no duplicate)
    author.promote_techniques_to_rag([t], "mission-2", store=s)
    assert s.calls[1][2] == ids


_BASE = {"id": "llm.probe", "name": "n", "domain": "web", "requires": [], "tool": "echo",
         "command_template": "echo {target}", "success_signal": "ok", "opens_session": False}


def test_author_accepts_the_well_typed_baseline():
    assert author.author_technique("http", "ctx", llm_invoke=lambda p: json.dumps(_BASE)) is not None


@pytest.mark.parametrize("bad", [
    {"command_template": ["echo", "{target}"]},   # list: used to make author_technique raise
    {"id": {"a": 1}},                              # unhashable: used to poison the mission catalog
    {"id": ["a"]},
    {"id": ""},
    {"id": "../../elsewhere"},
    {"tool": ["echo"]},
    {"name": {"x": 1}},
    {"success_signal": ["ok"]},
    {"requires": [1, 2]},
    {"requires": {"session": True}},
    {"opens_session": "yes"},
])
def test_author_rejects_ill_typed_fields(bad):
    # An ill-typed proposal is REJECTED (None) — never an exception that
    # would interrupt the mission, never an unusable entry in the catalog.
    raw = json.dumps({**_BASE, **bad})
    assert author.author_technique("http", "ctx", llm_invoke=lambda p: raw) is None


def test_author_survives_a_failing_llm_call():
    def down(_prompt):
        raise ConnectionError("API unavailable")
    assert author.author_technique("http", "ctx", llm_invoke=down) is None


def _tech(**over):
    from catalog.loader import Technique
    base = dict(id="llm.t", name="x", domain="recon", service="smb", requires=set(), tool="nmap",
                command_template="nmap -sV -p 445 {target}", success_signal="ok", provided_by="llm")
    return Technique(**{**base, **over})


def test_promote_isolates_a_malformed_technique():
    # An unreadable technique is discarded on its own: it no longer raises, nor
    # loses the whole batch.
    s = _FakeStore()
    assert author.promote_techniques_to_rag([_tech(command_template=None), _tech()], "m", store=s) == 1
    assert len(s.calls[0][0]) == 1


def test_promote_dedupes_identical_templates_in_one_batch():
    s = _FakeStore()
    assert author.promote_techniques_to_rag([_tech(id="llm.a"), _tech(id="llm.b")], "m", store=s) == 1
    assert s.calls[0][2] == list(dict.fromkeys(s.calls[0][2])) and len(s.calls[0][2]) == 1


def test_rag_candidates_expose_exactly_what_would_be_stored():
    cands = author.rag_candidates([_tech(), _tech(command_template="nmap -p 445 192.0.2.10")])
    assert len(cands) == 1                                   # the literal IP discards the second one
    assert cands[0]["text"].startswith("Technique \"x\" for the smb service")
    assert cands[0]["id"].startswith("llm:") and cands[0]["metadata"]["tool"] == "nmap"
    s = _FakeStore()
    assert author.store_candidates(cands, store=s) == 1 and s.calls[0][0] == [cands[0]["text"]]


def test_promote_techniques_to_rag_empty_is_noop():
    class Boom:
        def add_texts(self, *a, **k):
            raise AssertionError("must not write for an empty list")
    assert author.promote_techniques_to_rag([], "m", store=Boom()) == 0


def test_promote_skips_template_with_ip_literal():
    # Literal IP in the template = mission-specific -> never in the shared RAG.
    # Technique built directly: author_technique would now reject it upstream.
    from catalog.loader import Technique
    t = Technique(id="llm.smb.x", name="x", domain="ad", service="smb", requires=set(),
                  tool="crackmapexec", command_template="crackmapexec smb 10.0.0.5 -u admin",
                  success_signal="Pwn3d", provided_by="llm")
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 0
    assert s.calls == []


def test_promote_skips_template_with_known_secret():
    raw = json.dumps({"id": "llm.smb.y", "name": "y", "service": "smb", "tool": "crackmapexec",
                      "command_template": "crackmapexec smb {target} -u admin -p Summer2024!",
                      "success_signal": "ok"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", forbidden=["Summer2024!"], store=s) == 0
    assert s.calls == []


def test_promote_metadata_omits_target_mission_id():
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: _GOOD)
    s = _FakeStore()
    author.promote_techniques_to_rag([t], "10.0.0.5-20261116-120000", store=s)
    meta = s.calls[0][1][0]
    assert "mission_id" not in meta            # field removed
    assert "10.0.0.5" not in str(meta)         # no target IP in metadata


def test_promote_skips_unknown_nt_hash_literal():
    # unknown NT hash (not reconciled) inlined by the LLM -> rejected (entropy + flag)
    raw = json.dumps({"id": "llm.smb.h", "name": "pth", "service": "smb", "tool": "impacket-wmiexec",
                      "command_template": "impacket-wmiexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 {user}@{target}",
                      "success_signal": "ok"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 0   # forbidden empty
    assert s.calls == []


def test_promote_skips_literal_credential_flag_value():
    # unknown secret, low entropy, in a credential flag position -> structural check
    raw = json.dumps({"id": "llm.smb.p", "name": "brute", "service": "smb", "tool": "crackmapexec",
                      "command_template": "crackmapexec smb {target} -u {user} -p hunter2", "success_signal": "ok"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 0
    assert s.calls == []


def test_promote_scans_all_persisted_fields_not_subset():
    # IP in `tool` (persisted field outside the 4 initially scanned) -> rejected
    raw = json.dumps({"id": "llm.smb.t", "name": "x", "service": "smb", "tool": "scanner-10.0.0.5",
                      "command_template": "run {target}", "success_signal": "ok"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 0
    assert s.calls == []


def test_promote_skips_compressed_ipv6_literal():
    # Literal IPv6 in the template -> never promoted (built directly: rejected at authoring).
    from catalog.loader import Technique
    t = Technique(id="llm.x.6", name="x", domain="ad", service="smb", requires=set(),
                  tool="nmap", command_template="nmap -6 fe80::1", success_signal="ok",
                  provided_by="llm")
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 0
    assert s.calls == []


def test_promote_allows_timestamp_in_success_signal():
    # regression of the IPv6-ish false positive: HH:MM:SS must NOT block promotion
    raw = json.dumps({"id": "llm.ok.ts", "name": "x", "service": "smb", "tool": "crackmapexec",
                      "command_template": "crackmapexec smb {target} -u {user}", "success_signal": "session at 10:30:00"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 1


def test_promote_allows_literal_numeric_port():
    # a literal port after -p is NOT a credential -> promoted (end of the false positive)
    raw = json.dumps({"id": "llm.np", "name": "scan", "service": "smb", "tool": "nmap",
                      "command_template": "nmap -p 445 {target}", "success_signal": "open"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 1


def test_promote_allows_header_flag():
    # -H = HTTP header (curl), not a hash -> promoted; a real hash is still caught by entropy
    raw = json.dumps({"id": "llm.hd", "name": "get", "service": "http", "tool": "curl",
                      "command_template": 'curl -H "Content-Type: application/json" {target}', "success_signal": "200"})
    t = author.author_technique("http", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 1


def test_promote_skips_short_base64_key_in_noncommand_field():
    # ~22-char base64 key in success_signal (outside flag/command) -> caught by entropy (threshold 20)
    raw = json.dumps({"id": "llm.k", "name": "x", "service": "smb", "tool": "run",
                      "command_template": "run {target}", "success_signal": "key ABCDEFGHIJKLMNOPQRSTUV"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 0
    assert s.calls == []


def test_promote_skips_short_H_hash_via_entropy():
    # guard: -H removed from the structural check, but a real hash is still rejected by entropy
    raw = json.dumps({"id": "llm.hh", "name": "pth", "service": "smb", "tool": "cme",
                      "command_template": "cme smb {target} -H 31d6cfe0d16ae931b73c59d7e0c089c0", "success_signal": "ok"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 0


# --- Authoring: the template MUST target {target} and carry no literal host/IP --- #
def test_author_rejects_template_without_target():
    # No {target} -> the target is not guaranteed in scope -> rejected.
    raw = json.dumps({"id": "llm.x", "service": "smb", "tool": "nmap",
                      "command_template": "nmap -sV -p 445"})
    assert author.author_technique("smb", "ctx", llm_invoke=lambda p: raw) is None


def test_author_rejects_literal_ip():
    raw = json.dumps({"id": "llm.x", "service": "smb", "tool": "cme",
                      "command_template": "cme smb 10.0.0.5 -u {user}"})
    assert author.author_technique("smb", "ctx", llm_invoke=lambda p: raw) is None


def test_author_rejects_literal_host_even_with_target():
    # {target} present but a SECOND literal host (proxy) -> rejected (scope escape).
    raw = json.dumps({"id": "llm.x", "service": "http", "tool": "curl",
                      "command_template": "curl http://{target}/ -x http://evil.example.com:8080"})
    assert author.author_technique("http", "ctx", llm_invoke=lambda p: raw) is None


def test_author_accepts_templated_target():
    raw = json.dumps({"id": "llm.ok", "service": "smb", "tool": "cme",
                      "command_template": "cme smb {target} -u {user}", "success_signal": "Pwn3d"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    assert t is not None and "{target}" in t.command_template


def test_author_accepts_rate_flag():
    # a large integer (rate) is not a literal host -> fast scan allowed (end of the rate FP).
    raw = json.dumps({"id": "llm.ms", "service": "smb", "tool": "masscan",
                      "command_template": "masscan {target} --rate 100000 -p445", "success_signal": "open"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    assert t is not None


def test_author_rejects_placeholder_glued_to_literal_host():
    # Scope escape (re-review 11/17): {target} glued to an attacker domain.
    # host_literals() alone does not see it (the braces break classification), but
    # at render time the host '10.0.0.5.evil.com' APPEARS and escapes both layers. Rejected by
    # sentinel substitution of the template at authoring (untrusted LLM path).
    for tpl in ["curl http://{target}.evil.com/",
                "nmap -sV {target}.evil.example.com",
                "curl http://{target}@localhost/"]:
        raw = json.dumps({"id": "llm.x", "service": "http", "tool": "curl",
                          "command_template": tpl})
        assert author.author_technique("http", "ctx", llm_invoke=lambda p: raw) is None, tpl


def test_author_accepts_legit_placeholder_templates():
    # Non-regression: normal templates (placeholder in host position, port, path,
    # output file) do NOT trigger the gluing detection.
    for tpl in ["crackmapexec smb {target} -u {user} -H {hash}",
                "curl http://{target}:{port}/{path}",
                "smbclient //{target}/{share} -U {user}",
                "nmap -p {port} -oN {output}.txt {target}"]:
        raw = json.dumps({"id": "llm.ok", "service": "smb", "tool": "x",
                          "command_template": tpl, "success_signal": "ok"})
        assert author.author_technique("smb", "ctx", llm_invoke=lambda p: raw) is not None, tpl


def test_author_rejects_non_target_placeholder_in_host_position():
    # Round 2: only {target} is sanctioned in scope. ANOTHER placeholder in host
    # position (or {target} glued to another) materializes out of scope at render time
    # (corp.local via creds) -> rejected at LLM authoring ({target}-by-position invariant).
    for tpl in ["curl http://{domain}/ {target}",
                "curl -x http://{domain}:{port} {target}",
                "ssh {user}@{domain} {target}",
                "smbclient //{share}/x {target}",
                "curl http://{target}.{domain}/"]:
        raw = json.dumps({"id": "llm.x", "service": "http", "tool": "curl",
                          "command_template": tpl})
        assert author.author_technique("http", "ctx", llm_invoke=lambda p: raw) is None, tpl


def test_author_accepts_capture_and_identity_templates():
    # B2 regression fixed: legitimate capture/output templates and AD identities
    # (UPN/NetBIOS, domain as a -d argument) must NO LONGER be rejected.
    for tpl in ["tcpdump -w {output}.pcap host {target}",
                "tshark -w {capture}.cap host {target}",
                "nmap {target} -oA {output}.report",
                "nmap {target} -oN {output}.scan",
                "crackmapexec smb {target} -u {user} -d {domain}",
                "crackmapexec smb {target} -u {user}@{domain} -p {password}"]:
        raw = json.dumps({"id": "llm.ok", "service": "smb", "tool": "x",
                          "command_template": tpl, "success_signal": "ok"})
        assert author.author_technique("smb", "ctx", llm_invoke=lambda p: raw) is not None, tpl
