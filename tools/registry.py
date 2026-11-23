"""Central catalog of PirateCrew's intervention tools.

Two groups:
- MANDATORY_TOOLS : tools injected into ALL intervention agents
  (audit + scope check).
- TOOL_CATALOG    : conditional tools indexed by domain (network, web, ad),
                    injected on the fly by the build_task_agent factory.

Security:
- subprocess with shell=False and list arguments (no shell injection).
- target validation (metacharacter rejection) AND authorization-scope check at
  the SAME choke point: `_validate_target` calls `assert_in_scope`, so no tool
  can touch a target outside the allowlist (single chokepoint, see design R4).
- timeouts everywhere.
- every action is logged to audit.log.

For authorized targets only (HTB lab, personal VM, consented audit scope).
"""

import os
import re
import socket
import shutil
import subprocess
import http.client
from datetime import datetime
from urllib.parse import urlparse

from langchain_core.tools import tool

from scope import assert_in_scope, ScopeError, _audit_escape
from state.world_model import WorldModel, Credential, Session

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_LOG = os.path.join(PROJECT_ROOT, "audit.log")

# Hostnames, IPv4, IPv6 (':' is allowed for IPv6). Nothing else.
_TARGET_RE = re.compile(r"^[A-Za-z0-9._:-]+$")

# Common ports tested as a fallback when nmap is missing.
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5985, 8080]


# --------------------------------------------------------------------------- #
# Internal helpers (not exposed as tools)
# --------------------------------------------------------------------------- #
def _audit(action: str, detail: str = "") -> str:
    """Timestamped append to audit.log. Never blocking. Neutralizes CR/LF
    (both action AND detail are often agent-controlled): prevents forging a
    fake audit line."""
    line = f"{datetime.now().isoformat(timespec='seconds')} | {_audit_escape(action)} | {_audit_escape(detail)}\n"
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass
    return line


def _validate_target(target: str) -> str:
    """Normalize, validate and CHECK THE SCOPE of a target.

    Single chokepoint: first the syntactic filter (metacharacter rejection),
    then `assert_in_scope` (fail-closed: raises `ScopeError` if no scope is
    active or the target is outside the allowlist). Returns the normalized IP
    returned by `assert_in_scope`. Defaults to `127.0.0.1` when empty — which
    is also subject to the scope check.
    """
    target = (target or "").strip() or "127.0.0.1"
    if not _TARGET_RE.match(target):
        raise ValueError(f"Invalid target (disallowed characters): {target!r}")
    return assert_in_scope(target)


def _run(cmd_list, timeout: int = 120) -> str:
    """Bounded, audited subprocess.run. Does not raise: returns a message on failure.

    audit.log gets only the STRUCTURAL fact (which binary ran), never the
    rendered argv: a tool argument can carry a credential (`smbclient -U u%pass`)
    or target data, and audit.log is the artifact meant to stay secret-free.
    """
    binary = cmd_list[0] if cmd_list else "?"
    _audit("RUN", binary)
    try:
        proc = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except FileNotFoundError:
        msg = f"Binary not found: {cmd_list[0]!r} (missing from PATH). Install it to use this tool."
        _audit("ERROR", msg)
        return msg
    except subprocess.TimeoutExpired:
        msg = f"Timeout exceeded ({timeout}s) for: {' '.join(cmd_list)}"
        _audit("TIMEOUT", f"{binary} ({timeout}s)")  # structural only, never the rendered argv
        return msg
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return output or "(no output)"


# --------------------------------------------------------------------------- #
# Mandatory tools: audit + scope check
# --------------------------------------------------------------------------- #
@tool
def log_audit_event(action: str, detail: str = "") -> str:
    """Log a timestamped audit action to audit.log.
    Call it to trace each sensitive step of a mission (target, decision, finding)."""
    _audit(f"AGENT:{action}", detail)
    return f"Event logged: {action} — {detail}"


@tool
def scope_check(target: str) -> str:
    """Check whether a target is INSIDE the authorization scope, without running anything.
    Returns "in-scope" (with the resolved IP) or "OUT OF SCOPE"."""
    try:
        ip = assert_in_scope(target)
    except ScopeError as exc:
        return f"{target} → OUT OF SCOPE (refused): {exc}"
    return f"{target} → in-scope ({ip})"


# --------------------------------------------------------------------------- #
# Domain: network
# --------------------------------------------------------------------------- #
@tool
def nmap_scan(target: str, mode: str = "quick") -> str:
    """Scan an AUTHORIZED target with nmap.
    mode='quick' (-T4 -F) for a fast scan of common ports,
    mode='aggressive' (-T4 -A) for version/OS/script detection.
    Returns the raw nmap output (open ports and services)."""
    target = _validate_target(target)
    if shutil.which("nmap") is None:
        msg = ("nmap is not installed/available on this machine. "
               "Use tcp_port_check as a fallback, or install nmap for a full scan.")
        _audit("SKIP", f"nmap_scan {target}: {msg}")
        return msg
    flags = ["-T4", "-A"] if mode == "aggressive" else ["-T4", "-F"]
    return _run(["nmap", *flags, target], timeout=300)


@tool
def tcp_port_check(target: str, port: int) -> str:
    """Test whether a TCP port is open on an AUTHORIZED target.
    Pure-Python socket: works without any external tool. Serves as a fallback for nmap."""
    try:
        target = _validate_target(target)
    except ScopeError as exc:
        return f"{target} → outside the authorization scope, test refused ({exc})"
    try:
        port = int(port)
    except (TypeError, ValueError):
        return f"Invalid port: {port!r}"
    _audit("TCP_CHECK", f"{target}:{port}")
    try:
        with socket.create_connection((target, port), timeout=5):
            return f"{target}:{port} → OPEN"
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return f"{target}:{port} → closed/unreachable ({type(exc).__name__})"


# --------------------------------------------------------------------------- #
# Domain: web
# --------------------------------------------------------------------------- #
@tool
def http_fingerprint(url: str) -> str:
    """Fetch the HTTP status code and revealing headers (Server, X-Powered-By, …)
    of an AUTHORIZED URL. Prepends http:// if the scheme is missing. Stdlib only."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    ip = _validate_target(host)  # filter + scope; we contact the VERIFIED IP, not the hostname
    _audit("HTTP_FINGERPRINT", url)
    is_https = parsed.scheme == "https"
    conn_cls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
    port = parsed.port or (443 if is_https else 80)
    path = parsed.path or "/"
    try:
        # Connect to the IP validated by the scope check (scope.py contract: use
        # the returned IP, never the re-resolved hostname). The original hostname
        # is only used as the Host header, to target the right vhost.
        conn = conn_cls(ip, port, timeout=8)
        conn.request("HEAD", path, headers={"Host": host})
        resp = conn.getresponse()
        headers = dict(resp.getheaders())
        status, reason = resp.status, resp.reason
        conn.close()
    except Exception as exc:  # noqa: BLE001 - report any network error cleanly
        return f"Connection to {url} failed ({type(exc).__name__}: {exc})"
    revealing = {
        k: v for k, v in headers.items()
        if k.lower() in ("server", "x-powered-by", "x-aspnet-version", "via", "x-generator")
    }
    return (f"{url} → HTTP {status} {reason}\n"
            f"Revealing headers: {revealing or '(none)'}")


@tool
def http_get(url: str) -> str:
    """Fetch the BODY of an AUTHORIZED URL (GET request), capped at 64 KB, with the
    status code. Lets you READ a directory listing or a served file
    (unlike http_fingerprint, which only returns headers). Prepends
    http:// if the scheme is missing. Stdlib only."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    ip = _validate_target(host)  # filter + scope; we contact the VERIFIED IP
    _audit("HTTP_GET", url)
    is_https = parsed.scheme == "https"
    conn_cls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
    port = parsed.port or (443 if is_https else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        conn = conn_cls(ip, port, timeout=8)
        conn.request("GET", path, headers={"Host": host})
        resp = conn.getresponse()
        status, reason = resp.status, resp.reason
        body = resp.read(65536)  # capped body: avoids ingesting a huge file
        conn.close()
    except Exception as exc:  # noqa: BLE001 - report any network error cleanly
        return f"Connection to {url} failed ({type(exc).__name__}: {exc})"
    return f"{url} → HTTP {status} {reason}\n{_decode_body(body)}"


def _decode_body(body) -> str:
    """Decode an HTTP body to text honoring the byte-order mark (BOM):
    UTF-16 LE/BE and UTF-8-BOM are common on the Windows side (exports, PowerShell) and
    came out as gibberish with forced utf-8 decoding. Fallback: utf-8. Never raises."""
    if not isinstance(body, (bytes, bytearray)):
        return str(body)
    b = bytes(body)
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):          # UTF-16 BOM: .decode consumes it and detects byte order
        return b.decode("utf-16", errors="replace")
    if b[:3] == b"\xef\xbb\xbf":                      # UTF-8 BOM
        return b.decode("utf-8-sig", errors="replace")
    return b.decode("utf-8", errors="replace")


_HREF_RE = re.compile(r"""href\s*=\s*["']([^"']*)["']""", re.IGNORECASE)


def _listing_links(html: str) -> list[str]:
    """Relative links (files/folders) of an http.server directory index.
    Drops sort links (`?`), absolute links (`/`, `http`), anchors (`#`) and the parent
    (`..`). Deduplicated, order preserved."""
    out: list[str] = []
    for m in _HREF_RE.finditer(html or ""):
        href = m.group(1).strip()
        if not href or href.startswith(("?", "/", "http", "#")) or ".." in href:
            continue
        if href not in out:
            out.append(href)
    return out


@tool
def http_get_listing(url: str) -> str:
    """Read an AUTHORIZED HTTP directory index AND the contents of the listed files
    (20 max). Reuses http_get: scope validation is inherited."""
    root = http_get.invoke({"url": url})
    base = url if url.endswith("/") else url + "/"
    parts = [root]
    for name in _listing_links(root)[:20]:
        body = http_get.invoke({"url": base + name})
        parts.append(f"=== {name} ===\n{body}")
    return "\n\n".join(parts)


# --------------------------------------------------------------------------- #
# Domain: ad (Active Directory / SMB)
# --------------------------------------------------------------------------- #
@tool
def smb_port_probe(target: str) -> str:
    """Check whether the SMB (445) and NetBIOS (139) ports are open on an AUTHORIZED target.
    Hint of Active Directory / file-sharing surface. Pure-Python socket."""
    try:
        target = _validate_target(target)
    except ScopeError as exc:
        return f"{target} → outside the authorization scope, probe refused ({exc})"
    _audit("SMB_PROBE", target)
    results = []
    for port in (445, 139):
        try:
            with socket.create_connection((target, port), timeout=5):
                results.append(f"{port}=OPEN")
        except OSError:
            results.append(f"{port}=closed")
    summary = ", ".join(results)
    lead = ""
    if "445=OPEN" in summary:
        lead = ("\nSMB exposed → AUTHORIZED enumeration leads: null sessions, share listing, "
                "user enumeration (e.g. enum4linux, smbclient -L). No automatic exploitation.")
    return f"SMB/NetBIOS on {target}: {summary}{lead}"


@tool
def smb_list_shares(target: str) -> str:
    """List the SMB shares of an AUTHORIZED target via `smbclient` (null session, -N).
    Requires the `smbclient` binary (available on Kali). AUTHORIZED enumeration
    only; no writes, no exploitation."""
    try:
        target = _validate_target(target)
    except ScopeError as exc:
        return f"{target} → outside the authorization scope, listing refused ({exc})"
    return _run(["smbclient", "-L", f"//{target}", "-N"], timeout=60)


# --------------------------------------------------------------------------- #
# Structured reporting of findings (bound to a world model)
# --------------------------------------------------------------------------- #
def make_report_finding_tool(world: WorldModel):
    """Build the `report_finding` tool bound to a given world model.

    PRIMARY (structured) channel through which an executing agent reports what
    it finds. The raw output is kept in `world.evidence` regardless (safety net
    + report material, see design R1).
    """

    @tool
    def report_finding(kind: str, host: str, detail: str = "", service: str = "",
                        port: int = 0, principal: str = "", secret: str = "",
                        cred_kind: str = "", loot: str = "",
                        session_channel: str = "", session_handle: str = "") -> str:
        """Record a STRUCTURED finding in the world model.

        kind ∈ service | credential | session | loot | note. `host` = the IP
        concerned (classified in/out of scope by the model). The other
        fields depend on the kind."""
        world.add_evidence({
            "kind": kind, "host": host, "service": service, "port": port,
            "principal": principal, "detail": detail,
        })
        # Audit trace: STRUCTURAL fields only. Never the secret, nor the loot
        # content, nor the raw detail (they may carry target data).
        _audit("FINDING", f"{kind} host={host or '-'} port={port} service={service or '-'}"
               + (f" principal={principal}" if principal else ""))
        if host:
            world.add_host(host)  # sets in_scope via the model's scope
        if kind == "service":
            try:
                p = int(port or 0)
            except (TypeError, ValueError):
                p = 0
            world.add_service(host, p, name=service)
        elif kind == "credential":
            world.add_credential(Credential(
                kind=cred_kind or "password", principal=principal,
                secret=secret, source="agent"))
        elif kind == "session":
            world.add_session(Session(
                host=host, channel=session_channel, handle=session_handle))
        elif kind == "loot":
            world.add_loot({"host": host, "detail": detail, "loot": loot})
        # kind == "note": the raw trace in evidence is enough
        return f"Finding '{kind}' recorded for {host or '(no host)'}."

    return report_finding


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
MANDATORY_TOOLS = [log_audit_event, scope_check]

TOOL_CATALOG = {
    "network": [nmap_scan, tcp_port_check],
    "web": [http_fingerprint, http_get, http_get_listing],
    "ad": [smb_port_probe, smb_list_shares],
}
