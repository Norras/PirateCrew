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
import ipaddress

from scope import Scope

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
