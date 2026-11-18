"""Bounded LLM catalog author: the (injected) LLM proposes a technique,
the guardrails validate it, then it is persisted with the mission."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path

import yaml

from catalog.loader import Technique, _technique_from_dict
from offense.guardrails import (GuardrailError, _host_candidates, _host_kind,
                                 destructive_match, host_literals,
                                 shell_metachar, tokenize_argv)
from state.mission_io import mission_dir


def build_author_prompt(service: str, context: str) -> str:
    """Constrained instruction: a single JSON object, template without metacharacters."""
    return (
        f"Propose ONE offensive technique for the \"{service}\" service, against an "
        "authorized target and within scope.\n"
        f"Actual mission state (take it into account):\n{context}\n\n"
        "Do NOT propose a technique listed above as already attempted; "
        "build on the service version and on the observed failures.\n"
        "Reply with exactly ONE JSON object, with no other text, with the keys: "
        "id, name, domain, service, requires, tool, command_template, "
        "success_signal, opens_session.\n"
        "command_template MUST use the placeholders {target} (host) {port} "
        "{user} {password} (plaintext password) {hash} (hash) {domain} "
        "{share} and NEVER a literal value (IP, username, password): "
        "a technique with literal values is not reusable.\n"
        "FORBIDDEN: shell metacharacters (; | & > < ` $) and any destructive "
        "action (deletion, formatting, shutdown, denial of service)."
    )


def parse_technique(raw: str) -> dict | None:
    """First complete JSON object in `raw` (prose/fences tolerated), otherwise None."""
    if not isinstance(raw, str):
        return None
    try:
        obj, _ = json.JSONDecoder().raw_decode(raw[raw.index("{"):])
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


# Detection of a host FORGED by gluing a placeholder to a literal
# (`{target}.evil.com` → at render time `10.0.0.5.evil.com`). The braces break
# host classification, so `host_literals(template)` sees nothing; we substitute
# each placeholder with a sentinel label, then re-read the literal hosts:
# any materialized host OTHER than the bare sentinel (= the lone placeholder in
# host position, legitimate) betrays a gluing → scope escape at render time.
_PLACEHOLDER_RE = re.compile(r"\{[^{}]*\}")
_TARGET_SENTINEL = "targetsentinelhost"              # {target} = the only sanctioned in-scope spot
_OTHER_SENTINEL = "othersentinelhost"                # any OTHER placeholder


def _materialized_host_literals(template: str) -> list[str]:
    """RENDERED hosts in host position that are NOT exactly {target}. Pure.

    The braces break host classification, so `host_literals(template)` sees
    nothing. We substitute {target} with a sentinel and EVERY OTHER placeholder
    with a DISTINCT sentinel, then re-read the hosts: any host other than the bare
    {target} sentinel — a sibling placeholder in host position ({domain}/{share}/{user}@),
    or {target} glued to a literal / to another placeholder — betrays an
    unsanctioned host position (scope escape at render time). Only {target} is
    guaranteed in scope; a BARE placeholder outside a host position
    (nmap {target} {domain}) remains an accepted residual, like a bare token."""
    def _sub(m: "re.Match[str]") -> str:
        return _TARGET_SENTINEL if m.group(0) == "{target}" else _OTHER_SENTINEL
    subbed = _PLACEHOLDER_RE.sub(_sub, template)
    out: list[str] = []
    for cand, structured in _host_candidates(subbed):
        if _host_kind(cand, structured) is None:
            continue
        if cand == _TARGET_SENTINEL:                 # {target} alone in host position: OK
            continue
        if cand not in out:
            out.append(cand)
    return out


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _well_typed(d: dict) -> bool:
    """Expected types of the fields proposed by the LLM. A badly typed field (list
    instead of a string, unhashable id or path-shaped id...) makes the
    proposal unusable: it is rejected here rather than making planning
    raise later, on every cycle."""
    if not isinstance(d.get("id"), str) or not _ID_RE.match(d["id"]):
        return False
    if not isinstance(d.get("command_template"), str) or not d["command_template"].strip():
        return False
    for key in ("name", "domain", "tool", "success_signal"):
        if d.get(key) is not None and not isinstance(d[key], str):
            return False
    requires = d.get("requires") or []
    if isinstance(requires, str):
        requires = [requires]
    if not isinstance(requires, list) or not all(isinstance(r, str) for r in requires):
        return False
    return isinstance(d.get("opens_session", False), bool)


def author_technique(service: str, context: str, llm_invoke) -> Technique | None:
    """Technique tagged `llm`, or None if unreadable / badly typed / template refused.
    Never raises: a failed LLM call or an unexpected response yields None."""
    try:
        d = parse_technique(llm_invoke(build_author_prompt(service, context)))
    except Exception:  # noqa: BLE001 - API unavailable, response without .content...: no proposal
        return None
    if d is None or not _well_typed(d):
        return None
    d["service"] = service
    d["provided_by"] = "llm"
    try:
        tech = _technique_from_dict(d)
    except (KeyError, TypeError):
        return None
    # Authoring guardrails (defense in depth, on top of the execution-time check):
    # no metacharacter/destructive content; the target MUST be the placeholder
    # {target} (never a hard-coded value); no other literal host/IP
    # (a second literal host = scope escape at execution time).
    tpl = tech.command_template or ""
    reject = None
    if shell_metachar(tpl) or destructive_match(tpl):
        reject = "shell metacharacter or destructive action"
    elif "{target}" not in tpl:
        reject = "template without {target} placeholder (target not guaranteed in scope)"
    elif host_literals(tpl):
        reject = f"literal host/IP forbidden: {', '.join(host_literals(tpl))}"
    else:
        glued = _materialized_host_literals(tpl)
        if glued:                                     # {target}.evil.com → host forged at render time
            reject = ("placeholder glued to a literal host (host forged at render time, "
                      f"scope escape): {', '.join(glued)}")
    if reject:
        try:
            from tools.registry import _audit
            _audit("LLM_TECH_REJECTED", f"{tech.id}: {reject}: {tpl}")
        except Exception:
            pass
        return None
    return tech


def persist_llm_technique(tech: Technique, mission_id: str, root=None) -> Path:
    """Append `tech` to missions/<id>/llm_catalog.yaml (readable by the loader)."""
    d = mission_dir(mission_id, root)
    d.mkdir(parents=True, exist_ok=True)
    path = d / "llm_catalog.yaml"
    entries = []
    if path.exists():
        entries = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    entry = asdict(tech)
    entry["requires"] = sorted(tech.requires)
    entries.append(entry)
    path.write_text(yaml.safe_dump(entries, allow_unicode=True, sort_keys=False),
                    encoding="utf-8")
    return path


_IP_LITERAL = re.compile(
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b"                      # IPv4
    r"|::[0-9A-Fa-f]{0,4}"                               # compressed IPv6 (::1, fe80::1)
    r"|(?:[0-9A-Fa-f]{1,4}:){4,}[0-9A-Fa-f]{0,4}"        # uncompressed IPv6 / MAC (>=4 groups)
)
# The `::` branch over-rejects a lone non-IP `::` (e.g. PowerShell [Ns]::Method,
# pwdump `user:::`): over-rejection is ACCEPTED (fail-safe). Tightening it would risk a
# FALSE NEGATIVE on a real IPv6 — a hole. We prefer to over-reject.

# High-entropy token: probable hash/key/token. Deliberately
# broad (fail-closed): hex >=16, or base64 >=20 (covers a 16-byte key,
# ~22 chars). `_`/`-` are NOT included in the base64 class: they join normal
# identifiers (e.g. NT_STATUS_LOGON_FAILURE) and would cause over-masking /
# over-rejection. Strict base64url not covered → accepted residual.
_HIGH_ENTROPY = re.compile(r"\b[0-9A-Fa-f]{16,}\b|[A-Za-z0-9+/]{20,}={0,2}")

# Flags carrying a credential value: their value MUST be a {placeholder}
# (a number is tolerated: a port is not a secret). The short forms
# `-p`/`-u` also serve as port/URL — `-H` (header or hash) is EXCLUDED because a
# real hash is already caught by entropy, which avoids rejecting `curl -H ...`.
_CRED_FLAGS = frozenset({"-p", "--password", "--pass", "-passwd", "-pw",
                         "-hashes", "--hashes", "--hash",
                         "-u", "--user", "--username"})


def _carries_target_data(text: str, forbidden) -> bool:
    """True if `text` carries target data: literal IP, high-entropy token
    (hash/key/token), or a forbidden string (known secret/principal,
    case-insensitive comparison). Fail-closed: when in doubt, True."""
    if _IP_LITERAL.search(text) or _HIGH_ENTROPY.search(text):
        return True
    low = text.lower()
    return any(bad and len(bad) >= 3 and bad.lower() in low for bad in forbidden)


def _flag_value_is_literal(template: str) -> bool:
    """True if a credential-carrying flag is followed by a LITERAL value
    (neither a {placeholder} nor a number/port) — a mission-specific template."""
    try:
        argv = tokenize_argv(template)
    except GuardrailError:
        return True  # cannot be tokenized → fail-closed
    for i in range(len(argv) - 1):
        val = argv[i + 1]
        if argv[i] in _CRED_FLAGS and "{" not in val and not val.isdigit():
            return True
    return False


def _rag_candidate(t, forbidden) -> dict | None:
    """What would be stored for `t` ({id, text, metadata}), or None if the filter
    discards it. May raise on a malformed technique (handled by the caller)."""
    reqs = ", ".join(sorted(t.requires)) if t.requires else "none"
    text = (
        f"Technique \"{t.name}\" for the {t.service} service "
        f"(tool {t.tool or '?'}). Command: {t.command_template}. "
        f"Success signal: {t.success_signal or '?'}. Prerequisites: {reqs}. "
        f"Opens a session: {t.opens_session}. Source: LLM author."
    )
    meta = {"source": "llm_authored", "service": t.service,
            "technique_id": t.id, "tool": t.tool or ""}
    # Scan ALL persisted content (page_content + metadata), not a
    # subset of fields.
    scanned = text + " " + " ".join(str(v) for v in meta.values())
    if _carries_target_data(scanned, forbidden) or _flag_value_is_literal(t.command_template):
        return None  # mission-specific → never in the shared RAG
    digest = hashlib.sha1(
        f"{t.service}|{t.command_template}".encode("utf-8")).hexdigest()[:16]
    return {"id": f"llm:{digest}", "text": text, "metadata": meta}


def rag_candidates(techniques, forbidden=()) -> list[dict]:
    """RAG promotion candidates: `[{id, text, metadata}]`, exactly what would be
    written. Writes nothing.

    A PRE-SORT filter, not a guarantee: any technique whose content carries a
    literal IP, a high-entropy token (hash/key/token), a `forbidden` string
    (secrets, principals, known hostnames — case-insensitive), or a LITERAL
    value after a credential flag is discarded. It does NOT recognize all target
    data: a name or identifier seen in tool output but absent from `forbidden`,
    a value under 3 characters, an encoded form, an attached value (--user=...),
    URL userinfo, a positional argument. The guarantee is the operator's
    approval: they review these texts before writing (REPL "promote" command).

    A malformed technique (non-text field...) is discarded on its own, without
    raising or losing the batch; two techniques with the same (service, template)
    yield a single candidate (stable id = hash(service|template) → idempotent
    upsert).
    """
    forbidden = [f for f in forbidden if isinstance(f, str)]
    out: list[dict] = []
    seen: set[str] = set()
    for t in techniques or []:
        try:
            cand = _rag_candidate(t, forbidden)
        except Exception:  # noqa: BLE001 - fail-closed per technique: discarded, never written
            cand = None
        if cand is None or cand["id"] in seen:
            continue
        seen.add(cand["id"])
        out.append(cand)
    return out


def store_candidates(candidates, store=None) -> int:
    """Write candidates (from `rag_candidates`) to the shared RAG, in a single
    call. `store=None` → lazy import of the vectorstore. Returns the number written."""
    if not candidates:
        return 0
    if store is None:
        from agents.pirate_agent import vectorstore as store  # lazy import
    store.add_texts([c["text"] for c in candidates],
                    metadatas=[c["metadata"] for c in candidates],
                    ids=[c["id"] for c in candidates])
    return len(candidates)


def promote_techniques_to_rag(techniques, mission_id: str, forbidden=(), store=None) -> int:
    """Filter (`rag_candidates`) then write (`store_candidates`) in one go.
    `mission_id` is accepted but deliberately ABSENT from what is stored (it
    contains the target IP). Returns the number promoted.

    The REPL no longer calls it at the end of a mission: it goes through
    `rag_candidates`, shows the texts to the operator and writes only on their
    command."""
    return store_candidates(rag_candidates(techniques, forbidden), store=store)
