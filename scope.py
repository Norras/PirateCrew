"""Périmètre d'autorisation de PirateCrew (allowlist IP/CIDR, fail-closed).

Toute cible réseau doit appartenir au périmètre actif avant qu'un outil ne la
touche. Sans périmètre actif, tout est refusé : l'absence de périmètre est une
erreur, jamais une permission implicite. Aucun flag de contournement.

Les appelants doivent utiliser l'IP renvoyée par `assert_in_scope` (et non le
nom d'hôte d'origine) : c'est cette adresse-là qui a été vérifiée.
"""

import ipaddress
import os
import socket
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
AUDIT_LOG = os.path.join(PROJECT_ROOT, "audit.log")


class ScopeError(Exception):
    """Périmètre absent ou invalide, ou cible hors périmètre."""


def _audit_escape(value: str) -> str:
    """Neutralise les CR/LF d'un champ d'audit.

    Une ligne par événement : une valeur contrôlée par la cible (hôte, détail,
    URL) ne doit pas pouvoir forger une fausse entrée en injectant un saut de
    ligne. Point unique de neutralisation, partagé par scope._audit,
    tools.registry._audit et state.world_model._trace_out_of_scope.
    """
    return str(value).replace("\r", "\\r").replace("\n", "\\n")


def _audit(action: str, detail: str = "") -> None:
    """Append horodaté dans audit.log. Jamais bloquant.

    Helper local (même format que tools.registry._audit) : importer le paquet
    `tools` ici créerait un import circulaire.
    """
    line = f"{datetime.now().isoformat(timespec='seconds')} | {_audit_escape(action)} | {_audit_escape(detail)}\n"
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass


def _resolve(target: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Adresse IP de la cible, ou None si elle n'est pas résoluble."""
    if not isinstance(target, str) or not target:
        return None
    try:
        return ipaddress.ip_address(target)  # IP littérale : aucun appel DNS
    except ValueError:
        pass
    try:
        return ipaddress.ip_address(socket.gethostbyname(target))
    except (OSError, ValueError):  # gaierror ⊂ OSError, UnicodeError ⊂ ValueError
        return None


class Scope:
    """Liste blanche de réseaux autorisés."""

    def __init__(self, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]):
        self.networks = list(networks)

    def hosts(self, max_hosts: int = 256) -> list[str]:
        """Énumère les adresses hôtes du périmètre (bornée à `max_hosts`).

        Un /32 donne son unique adresse ; sinon les adresses utilisables
        (sans réseau/broadcast IPv4). Dédoublonné, ordre d'apparition conservé.
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
        """Construit un périmètre : une entrée IP ou CIDR par ligne.

        Les lignes vides et les commentaires (`#`) sont ignorés. Une entrée
        invalide lève ScopeError plutôt que d'être écartée en silence.

        Parsing strict : un CIDR avec des bits hôte (`10.10.10.5/24`) est
        refusé au lieu d'être élargi au réseau entier à l'insu de l'opérateur.
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
                    f"Entrée de périmètre invalide (ligne {number}) : {entry!r} ({exc})"
                ) from exc
        return cls(networks)

    def contains(self, target: str) -> bool:
        """True si la cible (IP ou nom d'hôte résolu) est dans le périmètre.

        Ne lève jamais : une cible non résoluble est simplement hors périmètre.
        """
        ip = _resolve(target)
        return ip is not None and any(ip in network for network in self.networks)


def load_scope(path: str = "scope.txt") -> Scope:
    """Charge le périmètre depuis un fichier (une entrée IP/CIDR par ligne).

    Lève ScopeError si le fichier est absent, illisible ou sans entrée valide.
    """
    try:
        with open(path, encoding="utf-8-sig") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeError) as exc:
        raise ScopeError(f"Fichier de périmètre illisible : {path!r} ({exc})") from exc
    scope = Scope.from_lines(lines)
    if not scope.networks:
        raise ScopeError(f"Aucune entrée IP/CIDR dans le fichier de périmètre : {path!r}")
    return scope


_ACTIVE_SCOPE: Scope | None = None


def set_active_scope(scope: Scope | None) -> None:
    """Définit le périmètre actif du processus (None = tout refuser)."""
    global _ACTIVE_SCOPE
    _ACTIVE_SCOPE = scope


def get_active_scope() -> Scope | None:
    return _ACTIVE_SCOPE


def assert_in_scope(target: str) -> str:
    """Renvoie l'IP normalisée de la cible si elle est dans le périmètre actif.

    Lève ScopeError (et journalise OUT_OF_SCOPE) si aucun périmètre n'est actif,
    si la cible n'est pas résoluble ou si elle est hors périmètre.
    """
    scope = get_active_scope()
    if scope is None:
        reason = "aucun périmètre actif"
    else:
        # Résolution unique : l'adresse vérifiée est exactement celle renvoyée.
        ip = _resolve(target)
        if ip is not None and scope.contains(str(ip)):
            return str(ip)
        reason = "hors périmètre ou non résoluble"
    _audit("OUT_OF_SCOPE", target)
    raise ScopeError(f"Cible refusée ({reason}) : {target!r}")
