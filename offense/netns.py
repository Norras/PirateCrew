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
import json
import os
import re
import subprocess
import sys

from scope import Scope, ScopeError, get_active_scope, load_scope

NS_NAME = "pc-offense"
HOST_IF = "pc-host"
NS_IF = "pc-ns"
# Lien interne hôte <-> namespace (les deux bouts de la paire veth). Pris dans la
# plage partagée des opérateurs (100.64.0.0/10, RFC 6598) et non dans une plage
# privée : un périmètre couvrant 10/8, 172.16/12 ou 192.168/16 ne le chevauche pas.
LINK_NET = "100.127.77.0/30"
HOST_ADDR = "100.127.77.1"
NS_ADDR = "100.127.77.2"
NFT_TABLE = "piratecrew"
NFT_SET = "scope4"
HELPER_PATH = "/usr/local/sbin/pc-netns-exec"
SUDOERS_PATH = "/etc/sudoers.d/piratecrew"

# Lanceur de processus par défaut. Point d'injection unique : les fonctions
# prennent `run=None` et retombent dessus, ce qui permet à la suite de tests de
# le neutraliser d'un coup (conftest) — aucun test unitaire ne lance sudo/ip/nft.
_spawn = subprocess.run

_LINK_PREFIXLEN = LINK_NET.split("/")[1]
_RESOLV_PATH = f"/etc/netns/{NS_NAME}/resolv.conf"
_SUDO_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]*$")

# Script d'aide installé en root par `up`. C'est la SEULE commande que la règle
# sudoers autorise : il entre dans le namespace puis redescend à l'utilisateur
# appelant (setpriv) avant d'exécuter — aucune exécution root n'est accordée.
#
# - PATH est fixé d'entrée : le script tourne en root, il ne doit pas résoudre
#   nft/ip/setpriv dans le PATH de l'appelant (sudoers sans secure_path).
# - La garde vaut pour les DEUX modes (--check et exécution) : namespace présent
#   (code 96) et règles de blocage présentes dans les chaînes forward et input
#   (code 97). Vérifier le seul contenu du set ne suffit pas : un
#   `nft flush table` garde le set mais vide les chaînes (policy accept).
# - Après la descente de privilèges, HOME/USER/LOGNAME sont ceux de l'appelant
#   (sudo les a remis à zéro) ; le PATH de l'outil est passé par `run_isolated`.
# - WSL2 : un binaire Windows (curl.exe…) lancé depuis Linux s'exécute côté
#   Windows, hors de tout namespace réseau. L'interop passe par des sockets
#   sous /run/WSL : elles sont masquées par un tmpfs vide, dans le namespace de
#   montage privé que crée `ip netns exec` (rien ne change pour le reste du
#   système), avant la descente de privilèges. Masquage impossible : code 98.
HELPER_SCRIPT = """#!/bin/sh
# Installé par `python -m offense.netns up`. Ne pas modifier à la main.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
refuse() {
    echo "pc-netns-exec: $1" >&2
    exit "$2"
}
[ -e /run/netns/pc-offense ] || refuse "namespace pc-offense absent" 96
nft list chain inet piratecrew forward 2>/dev/null | grep -Eq 'iifname "pc-host" counter .*drop' || refuse "filtre nft piratecrew absent ou incomplet" 97
nft list chain inet piratecrew input 2>/dev/null | grep -Eq 'iifname "pc-host" drop' || refuse "filtre nft piratecrew absent ou incomplet" 97
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
        echo "pc-netns-exec: interop WSL non masquable" >&2
        exit 98
    }
fi
exec setpriv --reuid "$uid" --regid "$gid" --init-groups -- "$@"
' pc-netns-exec "$uid" "$gid" "$@"
"""


class NetnsError(Exception):
    """Namespace absent, non conforme au périmètre actif, ou mise en place impossible."""


def scope_v4(scope: Scope) -> list[ipaddress.IPv4Network]:
    """Entrées IPv4 du périmètre, fusionnées et triées (IPv6 ignoré : non
    appliqué au niveau réseau en v1, le namespace n'a pas d'IPv6)."""
    v4 = [n for n in scope.networks if n.version == 4]
    return sorted(ipaddress.collapse_addresses(v4))


_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")


def loopback_entries(scope: Scope) -> list[str]:
    """Entrées IPv4 du périmètre situées dans 127.0.0.0/8. Depuis le namespace,
    ces adresses désignent SA boucle locale (vide), pas celle de la machine : le
    chemin offensif ne peut pas y joindre les services locaux de l'hôte."""
    return [str(n) for n in scope_v4(scope) if n.overlaps(_LOOPBACK)]


def loopback_warning(scope: Scope) -> str | None:
    """Avertissement à afficher si le périmètre contient la boucle locale, sinon None."""
    entries = loopback_entries(scope)
    if not entries:
        return None
    return (f"[NETNS] Attention : {', '.join(entries)} désigne la boucle locale. Dans le "
            "namespace, c'est celle du namespace (vide) et non celle de cette machine : "
            "le chemin offensif ne peut pas joindre ses services locaux. Pour un lab local, "
            "donnez à la cible sa propre adresse : « sudo python -m offense.lab up ».")


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
    """Commandes (root) de démontage, dans l'ordre.

    Le veth hôte part EN PREMIER. `ip netns del` ne fait que retirer le nom : si
    une commande tourne encore dans le namespace, celui-ci survit avec son lien.
    Supprimer une extrémité détruit la paire même dans ce cas — la commande en
    cours perd le réseau AVANT que la table nftables ne soit retirée, et un `up`
    suivant ne bute pas sur un `pc-host` résiduel.
    """
    return [
        ["ip", "link", "del", HOST_IF],
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


def down(run=None) -> None:
    """Démonte le namespace et la table nftables. Ne lève jamais."""
    run = run or _spawn
    for argv in teardown_commands():
        _try(run, argv)


def up(scope: Scope, dns: str | None = None, sudo_user: str | None = None,
       run=None, write=_write_root_file) -> None:
    """Met en place le namespace filtré pour `scope` (root). Idempotent.

    Tout est validé AVANT la première commande. Les règles nftables sont
    chargées avant la création du namespace : il n'existe jamais sans filtre.
    Un échec en cours de route démonte ce qui a été créé puis lève NetnsError.
    """
    run = run or _spawn
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


# --------------------------------------------------------------------------- #
# Entrée dans le namespace et vérification (processus PirateCrew, non root)
# --------------------------------------------------------------------------- #
_UP_HINT = "lancez « sudo python -m offense.netns up » puis relancez"
_DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_HELPER_REFUSAL = "pc-netns-exec:"   # préfixe des refus du script d'aide (stderr)


def _is_root() -> bool:
    return getattr(os, "geteuid", lambda: -1)() == 0


def wrap(argv: list[str]) -> list[str]:
    """Préfixe `argv` pour l'exécuter dans le namespace via le script d'aide
    (`sudo -n` si le processus n'est pas root : jamais de demande de mot de passe).
    `sudo` est appelé par son chemin absolu : le PATH d'une mission commence
    souvent par un répertoire inscriptible par l'utilisateur (venv/bin)."""
    prefix = [] if _is_root() else ["/usr/bin/sudo", "-n"]
    return [*prefix, HELPER_PATH, *argv]


def _element_networks(elem) -> list[ipaddress.IPv4Network]:
    """Réseaux d'un élément de set nftables (JSON). Forme inconnue -> ValueError."""
    if isinstance(elem, str):
        return [ipaddress.IPv4Network(elem)]
    if isinstance(elem, dict) and set(elem) == {"prefix"}:
        prefix = elem["prefix"]
        return [ipaddress.IPv4Network(f"{prefix['addr']}/{prefix['len']}")]
    if isinstance(elem, dict) and set(elem) == {"range"}:
        first, last = elem["range"]
        return list(ipaddress.summarize_address_range(
            ipaddress.IPv4Address(first), ipaddress.IPv4Address(last)))
    raise ValueError(f"élément de set inattendu : {elem!r}")


def installed_networks(run=None) -> list[ipaddress.IPv4Network]:
    """Réseaux réellement autorisés par le NOYAU (set nftables), fusionnés et triés.

    Lit le set via le script d'aide (`--check`). Fail-closed : toute sortie
    absente, illisible ou d'une forme non prévue lève NetnsError — jamais un
    set « supposé conforme »."""
    run = run or _spawn
    argv = wrap(["--check"])
    try:
        proc = run(argv, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise NetnsError(f"Périmètre réseau illisible ({type(exc).__name__}: {exc})") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip()
        raise NetnsError(f"Périmètre réseau absent (code {proc.returncode})"
                         + (f" — {detail}" if detail else ""))
    try:
        data = json.loads(proc.stdout)
        sets = [obj["set"] for obj in data["nftables"] if isinstance(obj, dict) and "set" in obj]
        if len(sets) != 1:
            raise ValueError(f"{len(sets)} set(s) dans la sortie nft")
        networks: list[ipaddress.IPv4Network] = []
        for elem in sets[0].get("elem", []):
            networks.extend(_element_networks(elem))
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise NetnsError(f"Sortie nft inattendue ({exc})") from exc
    return sorted(ipaddress.collapse_addresses(networks))


def verify(scope: Scope, run=None) -> None:
    """Lève NetnsError si le set du noyau n'est pas EXACTEMENT le périmètre `scope`."""
    if sys.platform != "linux":
        raise NetnsError("Périmètre réseau indisponible hors Linux (network namespaces).")
    expected = scope_v4(scope)
    if not expected:
        raise NetnsError("Périmètre sans entrée IPv4 : rien n'est autorisé au niveau réseau.")
    try:
        installed = installed_networks(run)
    except NetnsError as exc:
        raise NetnsError(f"{exc} — {_UP_HINT}.") from exc
    if installed != expected:
        raise NetnsError(
            f"Le périmètre réseau installé ({', '.join(map(str, installed)) or 'vide'}) ne "
            f"correspond pas au périmètre actif ({', '.join(map(str, expected))}) — {_UP_HINT}.")


def run_isolated(argv: list[str], timeout: int = 120) -> str:
    """Exécute `argv` dans le namespace filtré, après vérification du périmètre.

    La vérification est refaite à CHAQUE appel (pas de cache) : un scope.txt
    modifié ou une table supprimée en cours de mission bloque dès la commande
    suivante. Lève NetnsError ; n'exécute alors rien."""
    scope = get_active_scope()
    if scope is None:
        raise NetnsError("Aucun périmètre actif : exécution refusée.")
    verify(scope)
    from tools.registry import _run  # lazy : évite un cycle d'import
    # Ce qui suit s'exécute APRÈS la descente de privilèges du script d'aide :
    # - `env PATH=…` rend à l'outil le PATH de la mission (sudo l'a remis à zéro),
    #   celui-là même que `technique_available` a utilisé pour le trouver ;
    # - `timeout -k 5` applique le délai là où il peut l'être : un processus non
    #   root ne peut pas tuer `sudo` (EPERM), donc le délai de subprocess seul
    #   bloquerait la mission. Le délai externe (+15 s) n'est qu'un filet.
    inner = ["env", f"PATH={os.environ.get('PATH') or _DEFAULT_PATH}",
             "timeout", "-k", "5", str(int(timeout)), *argv]
    out = _run(wrap(inner), timeout + 15)
    if out.startswith(_HELPER_REFUSAL):
        # Namespace ou filtre disparu entre la vérification et l'exécution : le
        # script d'aide a refusé, rien n'a tourné — blocage, pas sortie d'outil.
        raise NetnsError(f"{out} — {_UP_HINT}.")
    return out


def main(argv: list[str] | None = None) -> int:
    """CLI : `python -m offense.netns {up,down,status} [--scope scope.txt] [--dns IP]`
    (`up` et `down` en root)."""
    parser = argparse.ArgumentParser(
        prog="python -m offense.netns",
        description="Périmètre réseau du chemin offensif (namespace + nftables).")
    parser.add_argument("action", choices=["up", "down", "status"])
    parser.add_argument("--scope", default="scope.txt", help="fichier de périmètre (défaut : scope.txt)")
    parser.add_argument("--dns", default=None, help="résolveur IPv4 in-scope visible du namespace")
    args = parser.parse_args(argv)

    if sys.platform != "linux":
        print("offense.netns : Linux uniquement (network namespaces).", file=sys.stderr)
        return 2
    if args.action == "status":
        try:
            installed = installed_networks()
        except NetnsError as exc:
            print(f"[NETNS] absent — {exc}")
            return 1
        print(f"[NETNS] actif — sorties autorisées : {', '.join(map(str, installed)) or 'aucune'}")
        return 0
    if not _is_root():
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
    warning = loopback_warning(scope)
    if warning:
        print(warning)
    return 0


if __name__ == "__main__":
    sys.exit(main())
