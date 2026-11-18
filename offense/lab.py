"""Cible de lab locale : un namespace réseau doté de sa propre adresse.

Le chemin offensif (`offense.netns`) ne peut pas joindre `127.0.0.1` : dans son
namespace, la boucle locale est la sienne, pas celle de la machine. Pour
s'exercer sur un service local, on le lance ici, dans un second namespace
(`pc-lab`) qui a une adresse à lui : 192.0.2.2 (plage de documentation RFC 5737,
jamais routée sur Internet). Cette adresse se met dans `scope.txt` comme
n'importe quelle cible. La reconnaissance (depuis la machine) et le chemin
offensif (depuis `pc-offense`, à travers le filtre) l'atteignent tous deux ; les
services locaux de la machine, eux, restent hors d'atteinte du chemin offensif.

    sudo python -m offense.lab up
    sudo python -m offense.lab run -- python3 -m http.server 8000
    sudo python -m offense.lab down

`run` lance la commande dans le lab avec VOS privilèges (pas root) et reste au
premier plan : Ctrl-C l'arrête. Le lab n'isole que le réseau du service, pas ses
fichiers — c'est une adresse à part, pas un bac à sable.
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
    """Commandes (root) créant le namespace de lab et son lien, dans l'ordre.

    Pas de route par défaut dans le lab : la cible répond sur son lien (les
    paquets du chemin offensif lui arrivent avec l'adresse de la machine sur ce
    lien), elle n'a pas à sortir ailleurs."""
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
    """Commandes (root) de démontage : le lien d'abord (il part même si un
    service occupe encore le namespace), puis le namespace."""
    return [
        ["ip", "link", "del", LAB_HOST_IF],
        ["ip", "netns", "del", LAB_NS],
    ]


def down(run=None) -> None:
    """Démonte le lab. Ne lève jamais."""
    run = run or netns._spawn
    for argv in teardown_commands():
        netns._try(run, argv)


def up(run=None) -> None:
    """Met en place le lab (root). Idempotent ; un échec démonte puis lève NetnsError."""
    run = run or netns._spawn
    down(run)
    try:
        for argv in setup_commands():
            netns._must(run, argv)
    except NetnsError:
        down(run)
        raise


def is_up() -> bool:
    """Vrai si le namespace de lab existe."""
    return os.path.exists(f"/run/netns/{LAB_NS}")


def run_argv(argv: list[str], uid: int, gid: int) -> list[str]:
    """Commande (root) lançant `argv` dans le lab avec l'identité `uid`/`gid`."""
    return ["ip", "netns", "exec", LAB_NS, "setpriv", "--reuid", str(uid), "--regid", str(gid),
            "--init-groups", "--", *argv]


def _caller_env(uid: int) -> dict:
    """Environnement du service : celui de l'appelant de sudo, pas celui de root."""
    env = dict(os.environ)
    try:
        import pwd
        entry = pwd.getpwuid(uid)
        env.update(HOME=entry.pw_dir, USER=entry.pw_name, LOGNAME=entry.pw_name)
    except (ImportError, KeyError):
        pass
    return env


def main(argv: list[str] | None = None) -> int:
    """CLI : `sudo python -m offense.lab {up,down,run -- commande…}`."""
    parser = argparse.ArgumentParser(
        prog="python -m offense.lab",
        description="Cible de lab locale : un namespace réseau avec sa propre adresse.")
    parser.add_argument("action", choices=["up", "down", "run"])
    parser.add_argument("command", nargs=argparse.REMAINDER,
                        help="pour « run » : la commande du service, après --")
    args = parser.parse_args(argv)

    if sys.platform != "linux":
        print("offense.lab : Linux uniquement (network namespaces).", file=sys.stderr)
        return 2
    if not netns._is_root():
        print("offense.lab : à lancer en root (sudo python -m offense.lab …).", file=sys.stderr)
        return 2

    if args.action == "down":
        down()
        print(f"[LAB] Namespace {LAB_NS} démonté.")
        return 0
    if args.action == "up":
        try:
            up()
        except NetnsError as exc:
            print(f"[LAB] Mise en place refusée : {exc}", file=sys.stderr)
            return 1
        print(f"[LAB] Namespace {LAB_NS} en place — adresse de la cible : {LAB_ADDR}")
        print(f"[LAB] Mettez « {LAB_ADDR} » dans scope.txt, puis : sudo python -m offense.netns up")
        print("[LAB] Lancez votre service : sudo python -m offense.lab run -- <commande>")
        return 0

    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        print("offense.lab : rien à lancer (sudo python -m offense.lab run -- <commande>).",
              file=sys.stderr)
        return 2
    if not is_up():
        print("[LAB] Namespace de lab absent : lancez « sudo python -m offense.lab up » d'abord.",
              file=sys.stderr)
        return 1
    uid = int(os.environ.get("SUDO_UID") or 0)
    gid = int(os.environ.get("SUDO_GID") or 0)
    full = run_argv(command, uid, gid)
    try:
        os.execvpe(full[0], full, _caller_env(uid))      # le service remplace ce processus
    except OSError as exc:
        print(f"[LAB] Lancement impossible : {exc}", file=sys.stderr)
        return 1
    return 0  # jamais atteint


if __name__ == "__main__":
    sys.exit(main())
