"""Scope enforced at the network level (network namespace + nftables).

Commands on the deterministic offensive path run in a dedicated network
namespace whose only exit is a veth pair. On the host side, an nftables table
lets through only packets whose DESTINATION IP is in the set fed from the
scope. The kernel decides: how the host is written in the command (decimal,
hexadecimal, trailing dot, twisted URL...) no longer matters.

The filter sits in the host's `forward` hook, not in the namespace: a tool
that emits over AF_PACKET bypasses an `output` hook, but not a veth.

Setup (root): `sudo python -m offense.netns up`. Re-run after any change
to scope.txt.
"""
import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys

from scope import Scope, ScopeError, get_active_scope, load_scope

NS_NAME = "pc-offense"
HOST_IF = "pc-host"
NS_IF = "pc-ns"
# Internal host <-> namespace link (the two ends of the veth pair). Taken from the
# carrier-grade shared range (100.64.0.0/10, RFC 6598) rather than a private
# range: a scope covering 10/8, 172.16/12 or 192.168/16 does not overlap it.
LINK_NET = "100.127.77.0/30"
HOST_ADDR = "100.127.77.1"
NS_ADDR = "100.127.77.2"
NFT_TABLE = "piratecrew"
NFT_SET = "scope4"
HELPER_PATH = "/usr/local/sbin/pc-netns-exec"
SUDOERS_PATH = "/etc/sudoers.d/piratecrew"

# Default process launcher. Single injection point: the functions take
# `run=None` and fall back to it, which lets the test suite neutralize it in one
# go (conftest) — no unit test runs sudo/ip/nft.
_spawn = subprocess.run

_LINK_PREFIXLEN = LINK_NET.split("/")[1]
_RESOLV_PATH = f"/etc/netns/{NS_NAME}/resolv.conf"
_SUDO_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]*$")

# Helper script installed as root by `up`. It is the ONLY command the sudoers
# rule allows: it enters the namespace, then drops back to the calling user
# (setpriv) before executing — no root execution is granted.
#
# - PATH is fixed up front: the script runs as root, so it must not resolve
#   nft/ip/setpriv in the caller's PATH (sudoers without secure_path).
# - The guard applies to BOTH modes (--check and execution): namespace present
#   (code 96) and blocking rules present in the forward and input chains
#   (code 97). Checking only the set's contents is not enough: an
#   `nft flush table` keeps the set but empties the chains (policy accept).
# - After dropping privileges, HOME/USER/LOGNAME are the caller's
#   (sudo reset them); the tool's PATH is passed by `run_isolated`.
# - WSL2: a Windows binary (curl.exe...) launched from Linux runs on the
#   Windows side, outside any network namespace. Interop goes through sockets
#   under /run/WSL: they are masked by an empty tmpfs, inside the private
#   mount namespace that `ip netns exec` creates (nothing changes for the rest
#   of the system), before dropping privileges. Masking impossible: code 98.
HELPER_SCRIPT = """#!/bin/sh
# Installed by `python -m offense.netns up`. Do not edit by hand.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
refuse() {
    echo "pc-netns-exec: $1" >&2
    exit "$2"
}
[ -e /run/netns/pc-offense ] || refuse "namespace pc-offense missing" 96
nft list chain inet piratecrew forward 2>/dev/null | grep -Eq 'iifname "pc-host" counter .*drop' || refuse "nft filter piratecrew missing or incomplete" 97
nft list chain inet piratecrew input 2>/dev/null | grep -Eq 'iifname "pc-host" drop' || refuse "nft filter piratecrew missing or incomplete" 97
if [ "${1:-}" = "--check" ]; then
    exec nft -j list set inet piratecrew scope4
fi
uid="${SUDO_UID:-0}"
gid="${SUDO_GID:-0}"
USER="$(getent passwd "$uid" | cut -d: -f1)"
HOME="$(getent passwd "$uid" | cut -d: -f6)"
LOGNAME="$USER"
export HOME USER LOGNAME
exec ip netns exec pc-offense /bin/sh -c '
uid="$1"
gid="$2"
shift 2
if [ -d /run/WSL ]; then
    mount -t tmpfs -o ro,nosuid,nodev,noexec tmpfs /run/WSL || {
        echo "pc-netns-exec: WSL interop cannot be masked" >&2
        exit 98
    }
fi
exec setpriv --reuid "$uid" --regid "$gid" --init-groups -- "$@"
' pc-netns-exec "$uid" "$gid" "$@"
"""


class NetnsError(Exception):
    """Namespace missing, not matching the active scope, or setup impossible."""


def scope_v4(scope: Scope) -> list[ipaddress.IPv4Network]:
    """IPv4 scope entries, merged and sorted (IPv6 ignored: not enforced at
    the network level in v1, the namespace has no IPv6)."""
    v4 = [n for n in scope.networks if n.version == 4]
    return sorted(ipaddress.collapse_addresses(v4))


_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")


def loopback_entries(scope: Scope) -> list[str]:
    """IPv4 scope entries located in 127.0.0.0/8. From inside the namespace,
    these addresses refer to ITS OWN loopback (empty), not the machine's: the
    offensive path cannot reach the host's local services there."""
    return [str(n) for n in scope_v4(scope) if n.overlaps(_LOOPBACK)]


def loopback_warning(scope: Scope) -> str | None:
    """Warning to display if the scope contains the loopback, otherwise None."""
    entries = loopback_entries(scope)
    if not entries:
        return None
    return (f"[NETNS] Warning: {', '.join(entries)} is the loopback. Inside the namespace, "
            "that is the namespace's own (empty) loopback, not this machine's: the "
            "offensive path cannot reach its local services. For a local lab, give the "
            "target its own address: `sudo python -m offense.lab up`.")


def _element(net: ipaddress.IPv4Network) -> str:
    return str(net.network_address) if net.prefixlen == 32 else str(net)


def nft_ruleset(networks: list[ipaddress.IPv4Network]) -> str:
    """Complete nftables script, loaded in a single transaction by `nft -f -`.

    The `table ... {}` / `delete table ...` preamble makes loading idempotent
    and atomic: the old ruleset is replaced in one go, with no window where
    the namespace would transit unfiltered.
    """
    if not networks:
        raise NetnsError("Scope has no IPv4 entry: nothing to allow at the network level.")
    link = ipaddress.ip_network(LINK_NET)
    for net in networks:
        if net.overlaps(link):
            raise NetnsError(
                f"Scope entry {net} overlaps the namespace's internal link ({LINK_NET})."
            )
    elements = ", ".join(_element(n) for n in networks)
    return f"""table inet {NFT_TABLE} {{}}
delete table inet {NFT_TABLE}
table inet {NFT_TABLE} {{
    set {NFT_SET} {{
        type ipv4_addr
        flags interval
        auto-merge
        elements = {{ {elements} }}
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        iifname "{HOST_IF}" ip daddr @{NFT_SET} accept
        iifname "{HOST_IF}" limit rate 10/second log prefix "PC_OOS "
        iifname "{HOST_IF}" counter drop
        oifname "{HOST_IF}" ct state established,related accept
        oifname "{HOST_IF}" drop
    }}
    chain input {{
        type filter hook input priority filter; policy accept;
        iifname "{HOST_IF}" drop
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr {LINK_NET} oifname != "{HOST_IF}" masquerade
    }}
}}
"""


def setup_commands() -> list[list[str]]:
    """Commands (root) creating the namespace and its veth link, in order."""
    in_ns = ["ip", "netns", "exec", NS_NAME]
    return [
        ["ip", "netns", "add", NS_NAME],
        ["ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", NS_IF],
        ["ip", "link", "set", NS_IF, "netns", NS_NAME],
        ["ip", "addr", "add", f"{HOST_ADDR}/{_LINK_PREFIXLEN}", "dev", HOST_IF],
        ["ip", "link", "set", HOST_IF, "up"],
        [*in_ns, "ip", "addr", "add", f"{NS_ADDR}/{_LINK_PREFIXLEN}", "dev", NS_IF],
        [*in_ns, "ip", "link", "set", NS_IF, "up"],
        [*in_ns, "ip", "link", "set", "lo", "up"],
        [*in_ns, "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"],
        [*in_ns, "ip", "route", "add", "default", "via", HOST_ADDR],
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
    ]


def teardown_commands() -> list[list[str]]:
    """Teardown commands (root), in order.

    The host veth goes FIRST. `ip netns del` only removes the name: if a
    command is still running in the namespace, the namespace survives with its
    link. Deleting one end destroys the pair even in that case — the running
    command loses the network BEFORE the nftables table is removed, and a
    following `up` does not trip over a leftover `pc-host`.
    """
    return [
        ["ip", "link", "del", HOST_IF],
        ["ip", "netns", "del", NS_NAME],
        ["nft", "delete", "table", "inet", NFT_TABLE],
    ]


# --------------------------------------------------------------------------- #
# Setup / teardown (root)
# --------------------------------------------------------------------------- #
def _write_root_file(path: str, content: str, mode: int) -> None:
    """Write `content` to `path` (parent directory created), atomically,
    with permissions `mode`. LF line endings regardless of the OS."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _try(run, argv: list[str]) -> None:
    """Run a command whose failure does not matter (teardown)."""
    try:
        run(argv, capture_output=True, text=True)
    except Exception:  # missing binary, etc.: a teardown never raises
        pass


def _must(run, argv: list[str], stdin: str | None = None) -> None:
    """Run a command that MUST succeed; otherwise NetnsError (command + stderr)."""
    try:
        proc = run(argv, input=stdin, capture_output=True, text=True)
    except OSError as exc:
        raise NetnsError(f"Cannot run command: {' '.join(argv)} ({exc})") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip()
        raise NetnsError(f"Failed: {' '.join(argv)}" + (f" — {detail}" if detail else ""))


def down(run=None) -> None:
    """Tear down the namespace and the nftables table. Never raises."""
    run = run or _spawn
    for argv in teardown_commands():
        _try(run, argv)


def up(scope: Scope, dns: str | None = None, sudo_user: str | None = None,
       run=None, write=_write_root_file) -> None:
    """Set up the filtered namespace for `scope` (root). Idempotent.

    Everything is validated BEFORE the first command. The nftables rules are
    loaded before the namespace is created: it never exists without a filter.
    A failure along the way tears down what was created, then raises NetnsError.
    """
    run = run or _spawn
    networks = scope_v4(scope)
    ruleset = nft_ruleset(networks)                       # raises if empty / overlapping
    resolv = ""
    if dns is not None:
        try:
            dns_ip = ipaddress.IPv4Address(dns)
        except ValueError as exc:
            raise NetnsError(f"--dns expects a literal IPv4: {dns!r}") from exc
        if not any(dns_ip in net for net in networks):
            raise NetnsError(f"Resolver {dns} is out of scope: refused.")
        resolv = f"nameserver {dns_ip}\n"
    if sudo_user is not None and not _SUDO_USER_RE.match(sudo_user):
        raise NetnsError(f"Invalid sudo user name: {sudo_user!r}")

    down(run)                                             # start from a clean state
    try:
        _must(run, ["nft", "-f", "-"], stdin=ruleset)
        for argv in setup_commands():
            _must(run, argv)
        try:
            write(_RESOLV_PATH, resolv, 0o644)
            write(HELPER_PATH, HELPER_SCRIPT, 0o755)
            if sudo_user is not None:
                write(SUDOERS_PATH, f"{sudo_user} ALL=(root) NOPASSWD: {HELPER_PATH}\n", 0o440)
        except OSError as exc:
            raise NetnsError(f"Cannot write file: {exc}") from exc
        if sudo_user is not None:
            try:
                _must(run, ["visudo", "-cf", SUDOERS_PATH])
            except NetnsError:
                try:
                    os.remove(SUDOERS_PATH)               # never leave an invalid sudoers file
                except OSError:
                    pass
                raise
    except NetnsError:
        down(run)
        raise


# --------------------------------------------------------------------------- #
# Entering the namespace and verification (PirateCrew process, non-root)
# --------------------------------------------------------------------------- #
_UP_HINT = "run `sudo python -m offense.netns up` then retry"
_DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_HELPER_REFUSAL = "pc-netns-exec:"   # prefix of the helper script's refusals (stderr)


def _is_root() -> bool:
    return getattr(os, "geteuid", lambda: -1)() == 0


def wrap(argv: list[str]) -> list[str]:
    """Prefix `argv` so it runs in the namespace via the helper script
    (`sudo -n` if the process is not root: never a password prompt).
    `sudo` is called by its absolute path: a mission's PATH often starts
    with a directory writable by the user (venv/bin)."""
    prefix = [] if _is_root() else ["/usr/bin/sudo", "-n"]
    return [*prefix, HELPER_PATH, *argv]


def _element_networks(elem) -> list[ipaddress.IPv4Network]:
    """Networks of an nftables set element (JSON). Unknown shape -> ValueError."""
    if isinstance(elem, str):
        return [ipaddress.IPv4Network(elem)]
    if isinstance(elem, dict) and set(elem) == {"prefix"}:
        prefix = elem["prefix"]
        return [ipaddress.IPv4Network(f"{prefix['addr']}/{prefix['len']}")]
    if isinstance(elem, dict) and set(elem) == {"range"}:
        first, last = elem["range"]
        return list(ipaddress.summarize_address_range(
            ipaddress.IPv4Address(first), ipaddress.IPv4Address(last)))
    raise ValueError(f"unexpected set element: {elem!r}")


def installed_networks(run=None) -> list[ipaddress.IPv4Network]:
    """Networks actually allowed by the KERNEL (nftables set), merged and sorted.

    Reads the set via the helper script (`--check`). Fail-closed: any missing,
    unreadable or unexpectedly shaped output raises NetnsError — never a set
    "assumed to conform"."""
    run = run or _spawn
    argv = wrap(["--check"])
    try:
        proc = run(argv, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise NetnsError(f"Network scope unreadable ({type(exc).__name__}: {exc})") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip()
        raise NetnsError(f"Network scope missing (code {proc.returncode})"
                         + (f" — {detail}" if detail else ""))
    try:
        data = json.loads(proc.stdout)
        sets = [obj["set"] for obj in data["nftables"] if isinstance(obj, dict) and "set" in obj]
        if len(sets) != 1:
            raise ValueError(f"{len(sets)} set(s) in the nft output")
        networks: list[ipaddress.IPv4Network] = []
        for elem in sets[0].get("elem", []):
            networks.extend(_element_networks(elem))
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise NetnsError(f"Unexpected nft output ({exc})") from exc
    return sorted(ipaddress.collapse_addresses(networks))


def verify(scope: Scope, run=None) -> None:
    """Raise NetnsError if the kernel's set is not EXACTLY the `scope`."""
    if sys.platform != "linux":
        raise NetnsError("Network scope unavailable outside Linux (network namespaces).")
    expected = scope_v4(scope)
    if not expected:
        raise NetnsError("Scope has no IPv4 entry: nothing is allowed at the network level.")
    try:
        installed = installed_networks(run)
    except NetnsError as exc:
        raise NetnsError(f"{exc} — {_UP_HINT}.") from exc
    if installed != expected:
        raise NetnsError(
            f"The installed network scope ({', '.join(map(str, installed)) or 'empty'}) does "
            f"not match the active scope ({', '.join(map(str, expected))}) — {_UP_HINT}.")


def run_isolated(argv: list[str], timeout: int = 120) -> str:
    """Run `argv` in the filtered namespace, after verifying the scope.

    The verification is redone on EVERY call (no cache): a modified scope.txt
    or a table deleted mid-mission blocks from the very next command.
    Raises NetnsError; nothing is run in that case."""
    scope = get_active_scope()
    if scope is None:
        raise NetnsError("No active scope: execution refused.")
    verify(scope)
    from tools.registry import _run  # lazy: avoids an import cycle
    # What follows runs AFTER the helper script drops privileges:
    # - `env PATH=...` gives the tool the mission's PATH back (sudo reset it),
    #   the very one `technique_available` used to find it;
    # - `timeout -k 5` applies the deadline where it can be: a non-root
    #   process cannot kill `sudo` (EPERM), so subprocess's own timeout alone
    #   would hang the mission. The outer timeout (+15 s) is only a safety net.
    inner = ["env", f"PATH={os.environ.get('PATH') or _DEFAULT_PATH}",
             "timeout", "-k", "5", str(int(timeout)), *argv]
    out = _run(wrap(inner), timeout + 15)
    if out.startswith(_HELPER_REFUSAL):
        # Namespace or filter vanished between verification and execution: the
        # helper script refused, nothing ran — a block, not tool output.
        raise NetnsError(f"{out} — {_UP_HINT}.")
    return out


def main(argv: list[str] | None = None) -> int:
    """CLI: `python -m offense.netns {up,down,status} [--scope scope.txt] [--dns IP]`
    (`up` and `down` as root)."""
    parser = argparse.ArgumentParser(
        prog="python -m offense.netns",
        description="Network scope of the offensive path (namespace + nftables).")
    parser.add_argument("action", choices=["up", "down", "status"])
    parser.add_argument("--scope", default="scope.txt", help="scope file (default: scope.txt)")
    parser.add_argument("--dns", default=None, help="in-scope IPv4 resolver visible from the namespace")
    args = parser.parse_args(argv)

    if sys.platform != "linux":
        print("offense.netns: Linux only (network namespaces).", file=sys.stderr)
        return 2
    if args.action == "status":
        try:
            installed = installed_networks()
        except NetnsError as exc:
            print(f"[NETNS] absent — {exc}")
            return 1
        print(f"[NETNS] active — allowed egress: {', '.join(map(str, installed)) or 'none'}")
        return 0
    if not _is_root():
        print("offense.netns: must be run as root (sudo python -m offense.netns ...).", file=sys.stderr)
        return 2

    if args.action == "down":
        down()
        print(f"[NETNS] Namespace {NS_NAME} and table {NFT_TABLE} torn down.")
        return 0
    try:
        scope = load_scope(args.scope)
        up(scope, dns=args.dns, sudo_user=os.environ.get("SUDO_USER"))
    except (ScopeError, NetnsError) as exc:
        print(f"[NETNS] Setup refused: {exc}", file=sys.stderr)
        return 1
    print(f"[NETNS] Namespace {NS_NAME} in place — allowed egress: "
          f"{', '.join(str(n) for n in scope_v4(scope))}")
    warning = loopback_warning(scope)
    if warning:
        print(warning)
    return 0


if __name__ == "__main__":
    sys.exit(main())
