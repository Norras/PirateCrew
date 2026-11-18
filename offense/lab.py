"""Local lab target: a network namespace with its own address.

The offensive path (`offense.netns`) cannot reach `127.0.0.1`: inside its
namespace, the loopback is its own, not the machine's. To practise on a local
service, it is started here, in a second namespace (`pc-lab`) that has an
address of its own: 192.0.2.2 (RFC 5737 documentation range, never routed on
the Internet). This address goes into `scope.txt` like any other target. Recon
(from the machine) and the offensive path (from `pc-offense`, through the
filter) can both reach it; the machine's own local services stay out of reach
of the offensive path.

    sudo python -m offense.lab up
    sudo python -m offense.lab run -- python3 -m http.server 8000
    sudo python -m offense.lab down

`run` starts the command in the lab with YOUR privileges (not root) and stays in
the foreground: Ctrl-C stops it. The lab only isolates the service's network, not
its files - it is a separate address, not a sandbox.
"""
from __future__ import annotations

import argparse
import os
import sys

from offense import netns
from offense.netns import NetnsError

LAB_NS = "pc-lab"
LAB_HOST_IF = "pc-lab-host"
LAB_NS_IF = "pc-lab-ns"
LAB_NET = "192.0.2.0/30"
LAB_HOST_ADDR = "192.0.2.1"
LAB_ADDR = "192.0.2.2"

_PREFIXLEN = LAB_NET.split("/")[1]


def setup_commands() -> list[list[str]]:
    """Commands (root) that create the lab namespace and its link, in order.

    No default route in the lab: the target answers on its link (packets from the
    offensive path reach it with the machine's address on that link), so it has
    no need to go anywhere else."""
    in_lab = ["ip", "netns", "exec", LAB_NS]
    return [
        ["ip", "netns", "add", LAB_NS],
        ["ip", "link", "add", LAB_HOST_IF, "type", "veth", "peer", "name", LAB_NS_IF],
        ["ip", "link", "set", LAB_NS_IF, "netns", LAB_NS],
        ["ip", "addr", "add", f"{LAB_HOST_ADDR}/{_PREFIXLEN}", "dev", LAB_HOST_IF],
        ["ip", "link", "set", LAB_HOST_IF, "up"],
        [*in_lab, "ip", "addr", "add", f"{LAB_ADDR}/{_PREFIXLEN}", "dev", LAB_NS_IF],
        [*in_lab, "ip", "link", "set", LAB_NS_IF, "up"],
        [*in_lab, "ip", "link", "set", "lo", "up"],
    ]


def teardown_commands() -> list[list[str]]:
    """Teardown commands (root): the link first (it goes away even if a service
    still occupies the namespace), then the namespace."""
    return [
        ["ip", "link", "del", LAB_HOST_IF],
        ["ip", "netns", "del", LAB_NS],
    ]


def down(run=None) -> None:
    """Tear the lab down. Never raises."""
    run = run or netns._spawn
    for argv in teardown_commands():
        netns._try(run, argv)


def up(run=None) -> None:
    """Set the lab up (root). Idempotent; a failure tears it down, then raises NetnsError."""
    run = run or netns._spawn
    down(run)
    try:
        for argv in setup_commands():
            netns._must(run, argv)
    except NetnsError:
        down(run)
        raise


def is_up() -> bool:
    """True if the lab namespace exists."""
    return os.path.exists(f"/run/netns/{LAB_NS}")


def run_argv(argv: list[str], uid: int, gid: int) -> list[str]:
    """Command (root) that runs `argv` in the lab as identity `uid`/`gid`."""
    return ["ip", "netns", "exec", LAB_NS, "setpriv", "--reuid", str(uid), "--regid", str(gid),
            "--init-groups", "--", *argv]


def _caller_env(uid: int) -> dict:
    """Service environment: that of the sudo caller, not root's."""
    env = dict(os.environ)
    try:
        import pwd
        entry = pwd.getpwuid(uid)
        env.update(HOME=entry.pw_dir, USER=entry.pw_name, LOGNAME=entry.pw_name)
    except (ImportError, KeyError):
        pass
    return env


def main(argv: list[str] | None = None) -> int:
    """CLI: `sudo python -m offense.lab {up,down,run -- command...}`."""
    parser = argparse.ArgumentParser(
        prog="python -m offense.lab",
        description="Local lab target: a network namespace with its own address.")
    parser.add_argument("action", choices=["up", "down", "run"])
    parser.add_argument("command", nargs=argparse.REMAINDER,
                        help="for \"run\": the service command, after --")
    args = parser.parse_args(argv)

    if sys.platform != "linux":
        print("offense.lab: Linux only (network namespaces).", file=sys.stderr)
        return 2
    if not netns._is_root():
        print("offense.lab: must be run as root (sudo python -m offense.lab ...).", file=sys.stderr)
        return 2

    if args.action == "down":
        down()
        print(f"[LAB] Namespace {LAB_NS} torn down.")
        return 0
    if args.action == "up":
        try:
            up()
        except NetnsError as exc:
            print(f"[LAB] Setup refused: {exc}", file=sys.stderr)
            return 1
        print(f"[LAB] Namespace {LAB_NS} is up - target address: {LAB_ADDR}")
        print(f"[LAB] Put \"{LAB_ADDR}\" in scope.txt, then: sudo python -m offense.netns up")
        print("[LAB] Start your service: sudo python -m offense.lab run -- <command>")
        return 0

    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        print("offense.lab: nothing to run (sudo python -m offense.lab run -- <command>).",
              file=sys.stderr)
        return 2
    if not is_up():
        print("[LAB] Lab namespace missing: run \"sudo python -m offense.lab up\" first.",
              file=sys.stderr)
        return 1
    uid = int(os.environ.get("SUDO_UID") or 0)
    gid = int(os.environ.get("SUDO_GID") or 0)
    full = run_argv(command, uid, gid)
    try:
        os.execvpe(full[0], full, _caller_env(uid))      # the service replaces this process
    except OSError as exc:
        print(f"[LAB] Cannot start: {exc}", file=sys.stderr)
        return 1
    return 0  # never reached


if __name__ == "__main__":
    sys.exit(main())
