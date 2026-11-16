"""Garde-fous offensifs : contrôles purs sur une commande déjà rendue.

Aucun LLM, réseau ni sous-processus : ces fonctions inspectent la chaîne de
commande et lisent le périmètre actif (fail-closed : sans périmètre, toute
IPv4 est hors périmètre). Seul effet de bord : `assert_in_scope` journalise
les refus (OUT_OF_SCOPE) dans audit.log, donc `scope_violations`/`evaluate`
ne sont pas strictement sans effet de bord. La denylist est une liste de
blocage volontairement large (insensible à la casse) : en cas de doute, on bloque.
"""

import ipaddress
import re
import shlex

from scope import ScopeError, assert_in_scope


class GuardrailError(Exception):
    """Commande rejetée par un garde-fou (ex. métacaractère shell)."""


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
        (r"\bformat\b.*\b[a-z]:", "format <lecteur>:"),
        (r"\bdel\b.*\s/[sqf]\b", "del /s|/q|/f"),
        (r"\bDROP\s+(TABLE|DATABASE)\b", "DROP TABLE/DATABASE"),
        (r"\bTRUNCATE\b", "TRUNCATE"),
        (r"of=/dev/", "écriture périphérique bloc (of=/dev/)"),
        (r">\s*/dev/sd", "écriture périphérique bloc (>/dev/sd)"),
        (r"/dev/(sd|nvme|vd|hd|mapper|disk|loop)", "périphérique bloc (/dev/…)"),
        (r"\bshred\b", "shred"),
        (r"\bwipefs\b", "wipefs"),
        (r"\bmkswap\b", "mkswap"),
        (r"\bsgdisk\b", "sgdisk"),
        (r"\bparted\b", "parted"),
        (r"\bbadblocks\b.*-w", "badblocks -w"),
    ]
]

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def shell_metachar(rendered: str) -> str | None:
    """Premier métacaractère shell trouvé dans la commande, sinon None."""
    for ch in rendered:
        if ch in SHELL_METACHARS:
            return ch
    return None


def destructive_match(rendered: str) -> str | None:
    """Label de la denylist correspondant à la commande, sinon None."""
    for pattern, label in DENYLIST:
        if pattern.search(rendered):
            return label
    return None


def scope_violations(rendered: str) -> list[str]:
    """Littéraux IPv4/IPv6 hors périmètre (dédoublonnés, ordre conservé).

    Limite acceptée (plan) : les noms d'hôte nus ne sont volontairement PAS
    scannés ici ; les cibles par nom sont contrôlées aux sites d'appel des
    outils curés via `assert_in_scope`.
    """
    out: list[str] = []
    for ip in _IPV4.findall(rendered):
        if ip in out:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            out.append(ip)  # dotted-quad invalide : violation locale, jamais de DNS
            continue
        try:
            assert_in_scope(ip)
        except ScopeError:
            out.append(ip)
    for tok in rendered.split():
        tok = tok.strip("[]").lstrip("/\\")
        tok = tok.split("/", 1)[0].strip("[]")
        try:
            addr = ipaddress.ip_address(tok)
        except ValueError:
            continue
        if addr.version != 6 or tok in out:
            continue
        try:
            assert_in_scope(tok)
        except ScopeError:
            out.append(tok)
    return out


def tokenize_argv(rendered: str) -> list[str]:
    """Découpe la commande en argv ; refuse tout métacaractère shell (avant split)."""
    meta = shell_metachar(rendered)
    if meta is not None:
        raise GuardrailError(f"métacaractère shell interdit : {meta!r}")
    try:
        return shlex.split(rendered, posix=True)
    except ValueError as exc:
        raise GuardrailError(f"commande non découpable : {exc}") from exc


def evaluate(rendered: str) -> tuple[str, str] | None:
    """None si la commande passe ; sinon (tag, détail). Ordre : meta, destructif, scope."""
    meta = shell_metachar(rendered)
    if meta is not None:
        return ("blocked_shell_meta", f"métacaractère shell : {meta!r}")
    label = destructive_match(rendered)
    if label is not None:
        return ("blocked_destructive", label)
    bad = scope_violations(rendered)
    if bad:
        return ("blocked_out_of_scope", ", ".join(bad))
    return None
