"""PirateCrew authorization scope (IP/CIDR allowlist, fail-closed).

Every network target must belong to the active scope before a tool touches
it. With no active scope, everything is refused: a missing scope is an
error, never an implicit permission. No bypass flag.

Callers must use the IP returned by `assert_in_scope` (not the original
hostname): that is the address that was actually verified.
"""

import ipaddress
import os
import socket
import threading
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
AUDIT_LOG = os.path.join(PROJECT_ROOT, "audit.log")


class ScopeError(Exception):
    """Scope missing or invalid, or target out of scope."""


def _audit_escape(value: str) -> str:
    """Neutralize the CR/LF of an audit field.

    One line per event: a target-controlled value (host, detail, URL) must
    not be able to forge a fake entry by injecting a line break. Single point
    of neutralization, shared by scope._audit, tools.registry._audit and
    state.world_model._trace_out_of_scope.
    """
    return str(value).replace("\r", "\\r").replace("\n", "\\n")


def _audit(action: str, detail: str = "") -> None:
    """Timestamped append to audit.log. Never blocking.

    Local helper (same format as tools.registry._audit): importing the `tools`
    package here would create a circular import.
    """
    line = f"{datetime.now().isoformat(timespec='seconds')} | {_audit_escape(action)} | {_audit_escape(detail)}\n"
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass


# Bounded DNS resolution (anti-hang) + per-mission cache (latency + OPSEC).
# A hostname is resolved only once per mission; set_active_scope clears the cache.
_DNS_TIMEOUT: float = 3.0
_RESOLVE_CACHE: dict = {}


def _gethostbyname_bounded(name: str, timeout: float):
    """socket.gethostbyname bounded by a timeout (daemon thread). None if the timeout
    is exceeded (fail-closed: a slow/blocked resolver is not waited for) or on failure."""
    box: dict = {}

    def _work():
        try:
            box["ip"] = socket.gethostbyname(name)
        except Exception as exc:  # gaierror ⊂ OSError, etc.: caught, never propagated
            box["err"] = exc

    th = threading.Thread(target=_work, daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        return None  # do not wait for a blocked resolver (OPSEC + anti-hang)
    return box.get("ip")


def _resolve(target: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """IP address of the target, or None if it cannot be resolved.

    Literal IPs trigger no DNS call. Hostnames are resolved through a BOUNDED
    resolution (timeout, fail-closed) and CACHED per mission
    (`_RESOLVE_CACHE`, cleared by `set_active_scope`)."""
    if not isinstance(target, str) or not target:
        return None
    try:
        return ipaddress.ip_address(target)  # literal IP: no DNS call
    except ValueError:
        pass
    if target in _RESOLVE_CACHE:
        return _RESOLVE_CACHE[target]
    ip_str = _gethostbyname_bounded(target, _DNS_TIMEOUT)
    resolved = None
    if ip_str is not None:
        try:
            resolved = ipaddress.ip_address(ip_str)
        except ValueError:  # UnicodeError ⊂ ValueError
            resolved = None
    if resolved is not None:
        # Cache ONLY successes: a transient failure (bounded timeout, resolver
        # momentarily unavailable) must not poison an in-scope host for the
        # whole mission. A durably unresolvable name is retried (bounded) on
        # each call — negligible cost (literals are rare).
        _RESOLVE_CACHE[target] = resolved
    return resolved


class Scope:
    """Allowlist of authorized networks."""

    def __init__(self, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]):
        self.networks = list(networks)

    def hosts(self, max_hosts: int = 256) -> list[str]:
        """Enumerate the scope's host addresses (capped at `max_hosts`).

        A /32 yields its single address; otherwise the usable addresses
        (no IPv4 network/broadcast). Deduplicated, order of appearance preserved.
        """
        out: list[str] = []
        seen: set[str] = set()
        for net in self.networks:
            it = ([net.network_address] if net.num_addresses == 1 else net.hosts())
            for addr in it:
                if len(out) >= max_hosts:
                    return out
                text = str(addr)
                if text not in seen:
                    seen.add(text)
                    out.append(text)
        return out

    @classmethod
    def from_lines(cls, lines: list[str]) -> "Scope":
        """Build a scope: one IP or CIDR entry per line.

        Blank lines and comments (`#`) are ignored. An invalid entry raises
        ScopeError rather than being silently dropped.

        Strict parsing: a CIDR with host bits (`10.10.10.5/24`) is rejected
        instead of being widened to the whole network without the operator's
        knowledge.
        """
        networks = []
        for number, line in enumerate(lines, start=1):
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            try:
                networks.append(ipaddress.ip_network(entry, strict=True))
            except ValueError as exc:
                raise ScopeError(
                    f"Invalid scope entry (line {number}): {entry!r} ({exc})"
                ) from exc
        return cls(networks)

    def contains(self, target: str) -> bool:
        """True if the target (IP or resolved hostname) is within the scope.

        Never raises: an unresolvable target is simply out of scope.
        """
        ip = _resolve(target)
        return ip is not None and any(ip in network for network in self.networks)


def load_scope(path: str = "scope.txt") -> Scope:
    """Load the scope from a file (one IP/CIDR entry per line).

    Raises ScopeError if the file is missing, unreadable or has no valid entry.
    """
    try:
        with open(path, encoding="utf-8-sig") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeError) as exc:
        raise ScopeError(f"Scope file unreadable: {path!r} ({exc})") from exc
    scope = Scope.from_lines(lines)
    if not scope.networks:
        raise ScopeError(f"No IP/CIDR entry in the scope file: {path!r}")
    return scope


_ACTIVE_SCOPE: Scope | None = None


def set_active_scope(scope: Scope | None) -> None:
    """Set the process's active scope (None = refuse everything).

    Also clears the resolution cache: a new mission (new scope) starts with
    fresh resolutions, never an address cached under a past scope."""
    global _ACTIVE_SCOPE
    _ACTIVE_SCOPE = scope
    _RESOLVE_CACHE.clear()


def get_active_scope() -> Scope | None:
    return _ACTIVE_SCOPE


def assert_in_scope(target: str) -> str:
    """Return the target's normalized IP if it is within the active scope.

    Raises ScopeError (and logs OUT_OF_SCOPE) if no scope is active, if the
    target is unresolvable or if it is out of scope.
    """
    scope = get_active_scope()
    if scope is None:
        reason = "no active scope"
    else:
        # Single resolution: the verified address is exactly the one returned.
        ip = _resolve(target)
        if ip is not None and scope.contains(str(ip)):
            return str(ip)
        reason = "out of scope or unresolvable"
    _audit("OUT_OF_SCOPE", target)
    raise ScopeError(f"Target refused ({reason}): {target!r}")
