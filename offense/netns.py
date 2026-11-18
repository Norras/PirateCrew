"""Périmètre appliqué au niveau réseau (network namespace + nftables).

Les commandes du chemin offensif déterministe s'exécutent dans un namespace
réseau dédié dont la seule sortie est une paire veth. Côté hôte, une table
nftables ne laisse transiter que les paquets dont l'IP de DESTINATION est dans
le set alimenté par le périmètre. C'est le noyau qui tranche : la façon dont
l'hôte est écrit dans la commande (décimale, hexadécimale, point final, URL
tordue…) n'a plus aucune importance.

Le filtre est dans le hook `forward` de l'hôte, pas dans le namespace : un
outil qui émet en AF_PACKET contourne un hook `output`, pas un veth.

Mise en place (root) : `sudo python -m offense.netns up`. À relancer après
toute modification de scope.txt.
"""
import argparse
import ipaddress
import os
import re
import subprocess
import sys

from scope import Scope, ScopeError, load_scope

NS_NAME = "pc-offense"
HOST_IF = "pc-host"
NS_IF = "pc-ns"
LINK_NET = "10.200.77.0/30"
HOST_ADDR = "10.200.77.1"
NS_ADDR = "10.200.77.2"
NFT_TABLE = "piratecrew"
NFT_SET = "scope4"
HELPER_PATH = "/usr/local/sbin/pc-netns-exec"
SUDOERS_PATH = "/etc/sudoers.d/piratecrew"

_LINK_PREFIXLEN = LINK_NET.split("/")[1]
_RESOLV_PATH = f"/etc/netns/{NS_NAME}/resolv.conf"
_SUDO_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]*$")

# Script d'aide installé en root par `up`. C'est la SEULE commande que la règle
# sudoers autorise : il entre dans le namespace puis redescend à l'utilisateur
# appelant (setpriv) avant d'exécuter — aucune exécution root n'est accordée.
# Il refuse d'exécuter si la table nftables a disparu (code 97).
HELPER_SCRIPT = """#!/bin/sh
# Installé par `python -m offense.netns up`. Ne pas modifier à la main.
set -eu
if [ "${1:-}" = "--check" ]; then
    exec nft -j list set inet piratecrew scope4
fi
nft list table inet piratecrew >/dev/null 2>&1 || {
    echo "pc-netns-exec: table nft piratecrew absente" >&2
    exit 97
}
uid="${SUDO_UID:-0}"
gid="${SUDO_GID:-0}"
HOME="$(getent passwd "$uid" | cut -d: -f6)"
export HOME
exec ip netns exec pc-offense setpriv --reuid "$uid" --regid "$gid" --init-groups -- "$@"
"""


class NetnsError(Exception):
    """Namespace absent, non conforme au périmètre actif, ou mise en place impossible."""


def scope_v4(scope: Scope) -> list[ipaddress.IPv4Network]:
    """Entrées IPv4 du périmètre, fusionnées et triées (IPv6 ignoré : non
    appliqué au niveau réseau en v1, le namespace n'a pas d'IPv6)."""
    v4 = [n for n in scope.networks if n.version == 4]
    return sorted(ipaddress.collapse_addresses(v4))


def _element(net: ipaddress.IPv4Network) -> str:
    return str(net.network_address) if net.prefixlen == 32 else str(net)


def nft_ruleset(networks: list[ipaddress.IPv4Network]) -> str:
    """Script nftables complet, chargé en une transaction par `nft -f -`.

    Le préambule `table … {}` / `delete table …` rend le chargement idempotent
    et atomique : l'ancien jeu de règles est remplacé d'un coup, sans fenêtre
    où le namespace transiterait sans filtre.
    """
    if not networks:
        raise NetnsError("Périmètre sans entrée IPv4 : rien à autoriser au niveau réseau.")
    link = ipaddress.ip_network(LINK_NET)
    for net in networks:
        if net.overlaps(link):
            raise NetnsError(
                f"L'entrée de périmètre {net} chevauche le lien interne du namespace ({LINK_NET})."
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
    """Commandes (root) créant le namespace et son lien veth, dans l'ordre."""
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
    """Commandes (root) de démontage. Supprimer le namespace supprime la paire veth."""
    return [
        ["ip", "netns", "del", NS_NAME],
        ["nft", "delete", "table", "inet", NFT_TABLE],
    ]


# --------------------------------------------------------------------------- #
# Mise en place / démontage (root)
# --------------------------------------------------------------------------- #
def _write_root_file(path: str, content: str, mode: int) -> None:
    """Écrit `content` dans `path` (répertoire parent créé), de façon atomique,
    avec les droits `mode`. Fins de ligne LF quel que soit l'OS."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _try(run, argv: list[str]) -> None:
    """Lance une commande dont l'échec est sans importance (démontage)."""
    try:
        run(argv, capture_output=True, text=True)
    except Exception:  # binaire absent, etc. : un démontage ne lève jamais
        pass


def _must(run, argv: list[str], stdin: str | None = None) -> None:
    """Lance une commande qui DOIT réussir ; sinon NetnsError (commande + stderr)."""
    try:
        proc = run(argv, input=stdin, capture_output=True, text=True)
    except OSError as exc:
        raise NetnsError(f"Commande impossible : {' '.join(argv)} ({exc})") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip()
        raise NetnsError(f"Échec de : {' '.join(argv)}" + (f" — {detail}" if detail else ""))


def down(run=subprocess.run) -> None:
    """Démonte le namespace et la table nftables. Ne lève jamais."""
    for argv in teardown_commands():
        _try(run, argv)


def up(scope: Scope, dns: str | None = None, sudo_user: str | None = None,
       run=subprocess.run, write=_write_root_file) -> None:
    """Met en place le namespace filtré pour `scope` (root). Idempotent.

    Tout est validé AVANT la première commande. Les règles nftables sont
    chargées avant la création du namespace : il n'existe jamais sans filtre.
    Un échec en cours de route démonte ce qui a été créé puis lève NetnsError.
    """
    networks = scope_v4(scope)
    ruleset = nft_ruleset(networks)                       # lève si vide / chevauchement
    resolv = ""
    if dns is not None:
        try:
            dns_ip = ipaddress.IPv4Address(dns)
        except ValueError as exc:
            raise NetnsError(f"--dns attend une IPv4 littérale : {dns!r}") from exc
        if not any(dns_ip in net for net in networks):
            raise NetnsError(f"Le résolveur {dns} est hors périmètre : refusé.")
        resolv = f"nameserver {dns_ip}\n"
    if sudo_user is not None and not _SUDO_USER_RE.match(sudo_user):
        raise NetnsError(f"Nom d'utilisateur sudo invalide : {sudo_user!r}")

    down(run)                                             # repart d'un état propre
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
            raise NetnsError(f"Écriture impossible : {exc}") from exc
        if sudo_user is not None:
            try:
                _must(run, ["visudo", "-cf", SUDOERS_PATH])
            except NetnsError:
                try:
                    os.remove(SUDOERS_PATH)               # ne jamais laisser un sudoers invalide
                except OSError:
                    pass
                raise
    except NetnsError:
        down(run)
        raise


def main(argv: list[str] | None = None) -> int:
    """CLI root : `python -m offense.netns {up,down} [--scope scope.txt] [--dns IP]`."""
    parser = argparse.ArgumentParser(
        prog="python -m offense.netns",
        description="Périmètre réseau du chemin offensif (namespace + nftables).")
    parser.add_argument("action", choices=["up", "down"])
    parser.add_argument("--scope", default="scope.txt", help="fichier de périmètre (défaut : scope.txt)")
    parser.add_argument("--dns", default=None, help="résolveur IPv4 in-scope visible du namespace")
    args = parser.parse_args(argv)

    if sys.platform != "linux":
        print("offense.netns : Linux uniquement (network namespaces).", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("offense.netns : à lancer en root (sudo python -m offense.netns …).", file=sys.stderr)
        return 2

    if args.action == "down":
        down()
        print(f"[NETNS] Namespace {NS_NAME} et table {NFT_TABLE} démontés.")
        return 0
    try:
        scope = load_scope(args.scope)
        up(scope, dns=args.dns, sudo_user=os.environ.get("SUDO_USER"))
    except (ScopeError, NetnsError) as exc:
        print(f"[NETNS] Mise en place refusée : {exc}", file=sys.stderr)
        return 1
    print(f"[NETNS] Namespace {NS_NAME} en place — sorties autorisées : "
          f"{', '.join(str(n) for n in scope_v4(scope))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
