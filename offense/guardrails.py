"""Offensive guardrails: checks on a command.

FROZEN (2026-11-18) — the TEXT scope check below is defense in depth, no longer
the boundary. The boundary is `offense/netns.py`: commands run in a network
namespace from which the kernel lets out only the scope's IPs, however the host
is written. Do not add any more host notations here: three adversarial reviews
showed that this list does not converge. The non-network checks (shell
metacharacters, destructive commands) remain fully in force.

Two levels of scope enforcement, to avoid confusing a connection target with an
identity argument (-d corp.local), a rate (--rate 100000) or a file
(-oN scan.txt):

- `scope_literal_violations(template)` — the REFERENCE check of the offensive
  path, called on the TEMPLATE (placeholders {target}/{domain}/{share} still
  intact, never mistaken for hosts). Each LITERAL host (IP in any notation —
  dotted in any base, abbreviated like 8.524296, and bare integer in a URL/UNC
  host position —, hostname including trailing dot, URL/UNC host) goes through
  `assert_in_scope`, which RESOLVES names (bounded + cached, see scope.py).
  Fail-closed: out of scope / unresolvable / no scope => violation (the operator
  adds the target to the scope).
- `scope_violations(rendered)`/`evaluate` — backstop on the RENDERED command,
  limited to LITERAL IPs (no DNS, no false positive), abbreviated notations
  included. Hostnames are NOT resolved there (they are on the template); a bare
  integer is treated as an IP only in a HOST POSITION (URL/UNC/user@), never an
  argument integer (--rate 100000).

Host classification remains a best-effort filter: the notation is delegated to
the OS (inet_aton / resolver), not reimplemented, but telling a bare argument
integer from an encoded IP stays undecidable outside a host position — an
accepted boundary, the real bound being deterministic resolution + the {target}
constraint.

`shell_metachar`, `destructive_match`, `tokenize_argv`, `host_literals` and
host extraction/classification are pure. The denylist is deliberately broad
(case-insensitive): when in doubt, block.
"""

import ipaddress
import re
import shlex
import socket
from urllib.parse import urlparse

from scope import ScopeError, assert_in_scope


class GuardrailError(Exception):
    """Command rejected by a guardrail (e.g. shell metacharacter)."""


SHELL_METACHARS: frozenset[str] = frozenset(";|&><`$\n\r")

DENYLIST: list[tuple[re.Pattern, str]] = [
    (re.compile(p, re.I), label)
    for p, label in [
        (r"\brm\b.*\s-[a-z-]*[rf]", "rm -rf"),
        (r"\bmkfs", "mkfs"),
        (r"\bdd\s+[^|]*\bof=", "dd of="),
        (r"\bshutdown\b", "shutdown"),
        (r"\breboot\b", "reboot"),
        (r":\(\)\s*\{", "fork-bomb"),
        (r"\bformat\b.*\b[a-z]:", "format <drive>:"),
        (r"\bdel\b.*\s/[sqf]\b", "del /s|/q|/f"),
        (r"\bDROP\s+(TABLE|DATABASE)\b", "DROP TABLE/DATABASE"),
        (r"\bTRUNCATE\b", "TRUNCATE"),
        (r"of=/dev/", "block device write (of=/dev/)"),
        (r">\s*/dev/sd", "block device write (>/dev/sd)"),
        (r"/dev/(sd|nvme|vd|hd|mapper|disk|loop)", "block device (/dev/...)"),
        (r"\bshred\b", "shred"),
        (r"\bwipefs\b", "wipefs"),
        (r"\bmkswap\b", "mkswap"),
        (r"\bsgdisk\b", "sgdisk"),
        (r"\bparted\b", "parted"),
        (r"\bbadblocks\b.*-w", "badblocks -w"),
    ]
]

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# A token "looks like an FQDN": at least one dot, alphanumeric labels
# (+ hyphen), last label starting with a letter, optional trailing dot (DNS
# root) (evil.example.com. is a host, resolved by nc/curl). Excludes dotted
# IPs (numeric last label → not caught here, handled as IPv4).
_FQDN_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.)+[A-Za-z][A-Za-z0-9-]{0,62}\.?$")

# Single DNS label, no dot (localhost, dc01, wpad, short NetBIOS/AD names),
# optional trailing dot. Treated as a host ONLY in a structured position
# (URL/UNC/user@): a bare label is indistinguishable from a tool/flag/value name
# (nmap, admin, -sV) → never a host outside a host position, otherwise massive
# false positives.
_HOSTLABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.?$")

# URI scheme followed by an ABNORMAL number of slashes (http:/h, http:///h). curl/wget
# skip all leading slashes, then read the authority up to the next delimiter,
# whereas urlparse only fills netloc on an exact '://': without renormalization,
# http:///IP and http:/IP are silent although the tool does connect to the IP.
_SCHEME_SLASHES_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]+):/+")  # scheme of 2+ chars (not a C:/ drive)

# Common file extensions: a token shaped like an FQDN but ending in one of
# them is treated as a FILE NAME (data), not a host to resolve. Anti-false-positive
# heuristic (e.g. `-oN scan.txt`), accepted: a real host whose TLD appears here
# (rare) would not be checked — documented residual.
_NON_HOST_SUFFIXES = frozenset({
    "txt", "log", "csv", "json", "xml", "yaml", "yml", "ini", "conf", "cfg",
    "html", "htm", "md", "pdf", "png", "jpg", "jpeg", "gif", "svg",
    "zip", "gz", "tgz", "tar", "bz2", "7z", "rar", "bak", "dump", "db", "sqlite",
    "pem", "key", "crt", "cer", "pfx", "p12", "sh", "py", "pl", "rb", "ps1",
    "exe", "dll", "so", "bin", "dat", "out", "nmap", "gnmap", "lst", "wordlist",
    # common offensive output/capture formats (FILE names, not hosts)
    "pcap", "pcapng", "cap", "scan", "report", "results", "ndjson", "jsonl",
    "har", "nessus",
})

# URI schemes that REQUIRE a network authority: only these get their leading
# slashes renormalized (http:/h, http:///h → http://h). A scheme with an empty
# authority (file:, data:, classpath:, jar:...) is NOT renormalized, otherwise the
# first path segment would become a phantom host (file:///etc/passwd → 'etc').
_NETWORK_SCHEMES: frozenset[str] = frozenset({
    "http", "https", "ftp", "ftps", "sftp", "ssh", "scp", "smb", "cifs", "telnet",
    "ldap", "ldaps", "rdp", "vnc", "rtsp", "ws", "wss", "redis", "mysql", "mssql",
    "mongodb", "gopher", "dict", "rsync", "nfs",
})

# Flags whose @ VALUE is an identity (UPN user@realm): no host is extracted from the
# token that FOLLOWS AND CONTAINS '@' (see _host_candidates). Only the @ form is skipped:
# a bare host after -u (nc = UDP) or -d (nmap = debug) is still checked (no bypass).
_IDENTITY_FLAGS: frozenset[str] = frozenset({
    "-u", "--user", "--username", "-U", "-p", "--password", "--pass",
    "-d", "--domain", "-H", "--hashes", "--hash",
})


def shell_metachar(rendered: str) -> str | None:
    """First shell metacharacter found in the command, otherwise None."""
    for ch in rendered:
        if ch in SHELL_METACHARS:
            return ch
    return None


def destructive_match(rendered: str) -> str | None:
    """Denylist label matching the command, otherwise None."""
    for pattern, label in DENYLIST:
        if pattern.search(rendered):
            return label
    return None


def _host_from_token(tok: str) -> tuple[str, bool] | None:
    """Extract `(host, structured)` from an argv token. None if nothing usable. Pure.

    `structured` is True when the host comes from an unambiguous HOST POSITION —
    URL (http://h:port/p), UNC (//h/s), user@h, [ipv6]: whatever is there IS a
    host, even encoded as a bare integer (http://2130706433/). A bare token
    (structured=False: h:port or the cleaned-up token of a path) is treated as a
    host only if it has the SHAPE of one (see `_host_kind`), so as not to take an
    argument integer (--rate 100000) for an IP."""
    t = (tok or "").strip().strip("\"'")
    if not t:
        return None
    m = _SCHEME_SLASHES_RE.match(t)
    if m and m.group(1).lower() in _NETWORK_SCHEMES:  # NETWORK scheme + abnormal slashes → '://'
        t = m.group(1) + "://" + t[m.end():]          # (never file:/data: → no phantom host)
    if "://" in t:                                   # URL
        try:
            h = urlparse(t).hostname
        except ValueError:
            return None
        return (h, True) if h else None
    if t.startswith("//") or t.startswith("\\\\"):   # UNC //host/share
        h = re.split(r"[/\\]", t.lstrip("/\\"), maxsplit=1)[0]
        return (h, True) if h else None
    structured = False
    if "@" in t:                                     # user:pass@host
        t = t.rsplit("@", 1)[1]
        structured = True
    if t.startswith("[") and "]" in t:               # [ipv6] ou [ipv6]:port
        h = t[1:t.index("]")]
        return (h, True) if h else None
    t = re.split(r"[/\\]", t, maxsplit=1)[0]         # strip any path
    if t.count(":") == 1:                            # host:port (IPv6 a >= 2 ':')
        t = t.split(":", 1)[0]
    return (t, structured) if t else None


def _host_candidates(rendered: str) -> list[tuple[str, bool]]:
    """`(host, structured)` candidates of a rendered command (order kept,
    deduplicated by host). If the same host appears in a bare AND a structured
    position, the structured flag wins. Pure."""
    try:
        tokens = shlex.split(rendered or "", posix=True)
    except ValueError:
        tokens = (rendered or "").split()
    out: list[tuple[str, bool]] = []
    pos: dict[str, int] = {}
    prev = ""
    for tok in tokens:
        # Only the @ form of an identity flag is skipped (-u svc@REALM = UPN/credential,
        # never a connection target). A BARE host after the same flag keeps its check:
        # -u is also "UDP" (nc), -d "debug" (nmap) -> nc -u IP / nmap -d IP stay verified.
        is_identity_at_value = prev in _IDENTITY_FLAGS and "@" in tok
        prev = tok
        if is_identity_at_value:
            continue
        res = _host_from_token(tok)
        if res is None:
            continue
        host, structured = res
        if host in pos:
            i = pos[host]
            out[i] = (host, out[i][1] or structured)
        else:
            pos[host] = len(out)
            out.append((host, structured))
    return out


def _normalize_ipv4_any(cand: str) -> str | None:
    """Normalized dotted IPv4 if `cand` is a form accepted by inet_aton
    (dotted decimal/octal/hexadecimal, like nmap/curl), otherwise None. Pure.

    A single trailing dot (DNS root: 203.0.113.9.) is stripped before inet_aton:
    inet_aton rejects it whereas getaddrinfo/curl accept it and connect."""
    try:
        return socket.inet_ntoa(socket.inet_aton(cand))
    except (OSError, UnicodeError, TypeError):
        pass
    if cand.endswith(".") and not cand.endswith(".."):
        try:
            return socket.inet_ntoa(socket.inet_aton(cand[:-1]))
        except (OSError, UnicodeError, TypeError):
            return None
    return None


def _host_kind(cand: str, structured: bool = False) -> str | None:
    """Classify a candidate — UNAMBIGUOUS forms only:
    'ip6' (literal IPv6), 'ip4' (IPv4 in any base via inet_aton — decimal, octal,
    hex — abbreviated forms included: 8.524296, 127.1), 'bad_ipv4' (invalid dotted
    decimal quad → local violation without DNS), 'hostname' (FQDN, optional trailing
    dot, excluding file extensions), otherwise None. Pure.

    `structured`=True (host coming from a URL/UNC/user@/[ipv6] position) accepts as
    'ip4' a bare integer encoding an IP (http://2130706433/ == 127.0.0.1): in a host
    position, an integer IS the host. Elsewhere, a BARE integer (no dot) returns
    None, indistinguishable from a numeric CLI value (rate, size) — accepted
    residual: an IP encoded as a single bare integer OUTSIDE a host position is not
    caught; the sanctioned target {target} is in scope by construction."""
    try:
        if ipaddress.ip_address(cand).version == 6:
            return "ip6"
    except ValueError:
        pass
    # IPv4 in any base (inet_aton). A dot is required on a BARE token — otherwise a
    # bare integer (--rate 100000 == 0.1.134.160) would be taken for an IP; in a
    # STRUCTURED host position the encoded integer is indeed the host, so it is
    # accepted without a dot.
    if ("." in cand or structured) and _normalize_ipv4_any(cand) is not None:
        return "ip4"
    if "." in cand:
        if _IPV4.fullmatch(cand):                     # 4 decimals but invalid (e.g. 256.0.0.1)
            return "bad_ipv4"
        if _FQDN_RE.match(cand):
            if structured:                            # URL/UNC host position: ALWAYS a host
                return "hostname"                     # (.zip/.sh TLDs included), never a file
            suffix = cand.rstrip(".").rsplit(".", 1)[-1].lower()  # trailing dot ignored
            return None if suffix in _NON_HOST_SUFFIXES else "hostname"
    if structured and _HOSTLABEL_RE.match(cand):      # single label IN A HOST POSITION
        return "hostname"                             # (http://localhost/, ssh u@dc01, //wpad/s)
    return None


def host_literals(text: str) -> list[str]:
    """LITERAL hosts/IPs of a template/command (deduplicated, order kept):
    dotted IPs, hostnames, URL/UNC hosts. `{...}` placeholders and bare integers
    are NOT among them. Pure, WITHOUT resolution: used for authoring and for the
    scope check on the template."""
    out: list[str] = []
    for cand, structured in _host_candidates(text):
        if cand not in out and _host_kind(cand, structured) is not None:
            out.append(cand)
    return out


def scope_violations(rendered: str) -> list[str]:
    """Backstop on the RENDERED command: LITERAL IPs out of scope (no DNS,
    no false positive). Checks ONLY IPs (v4 in any base via inet_aton,
    abbreviated forms included; v6; invalid decimal quad) and the integer encoding
    an IP in a HOST POSITION (URL/UNC/user@) — never a hostname (resolved on the
    template via `scope_literal_violations`) nor a bare argument integer, so as not
    to over-block an identity argument (-d corp.local) or a rate (--rate 100000).
    """
    out: list[str] = []
    for cand, structured in _host_candidates(rendered):
        if cand in out:
            continue
        kind = _host_kind(cand, structured)
        if kind not in ("ip4", "ip6", "bad_ipv4"):    # names/bare integers: not here (see docstring)
            continue
        if kind == "bad_ipv4":
            out.append(cand)                           # invalid quad: local violation, never DNS
            continue
        target = _normalize_ipv4_any(cand) if kind == "ip4" else cand
        try:
            assert_in_scope(target)                    # literal IP: no DNS
        except ScopeError:
            out.append(cand)
    return out


def scope_literal_violations(text: str) -> list[str]:
    """LITERAL hosts/IPs of the template that are OUT of scope (deduplicated, order kept).

    Reference scope check of the offensive path. Operates on the TEMPLATE
    (placeholders {target}/{domain}/{share} intact → never confused with
    hosts). Each literal — IP (dotted notations) OR hostname OR URL/UNC host —
    goes through `assert_in_scope`, which RESOLVES names (bounded + cached).
    Out of scope, unresolvable, or no active scope => violation
    (fail-closed): the operator can then add the target to the scope.
    {target} (the sanctioned target) stays in scope by construction.
    """
    out: list[str] = []
    for cand, structured in _host_candidates(text):
        if cand in out:
            continue
        kind = _host_kind(cand, structured)
        if kind is None:                               # placeholder, bare integer outside a host, file
            continue
        if kind == "bad_ipv4":
            out.append(cand)
            continue
        target = _normalize_ipv4_any(cand) if kind == "ip4" else cand
        try:
            assert_in_scope(target)                    # 'ip4': no DNS; 'hostname': resolves
        except ScopeError:
            out.append(cand)
    return out


def tokenize_argv(rendered: str) -> list[str]:
    """Split the command into argv; refuse any shell metacharacter (before splitting)."""
    meta = shell_metachar(rendered)
    if meta is not None:
        raise GuardrailError(f"shell metacharacter forbidden: {meta!r}")
    try:
        return shlex.split(rendered, posix=True)
    except ValueError as exc:
        raise GuardrailError(f"command cannot be split: {exc}") from exc


def evaluate(rendered: str) -> tuple[str, str] | None:
    """None if the command passes; otherwise (tag, detail). Order: meta, destructive, scope."""
    meta = shell_metachar(rendered)
    if meta is not None:
        return ("blocked_shell_meta", f"shell metacharacter: {meta!r}")
    label = destructive_match(rendered)
    if label is not None:
        return ("blocked_destructive", label)
    bad = scope_violations(rendered)
    if bad:
        return ("blocked_out_of_scope", ", ".join(bad))
    return None
