"""Garde-fous offensifs : contrôles purs sur une commande déjà rendue.

Aucun LLM, réseau, fichier ni sous-processus : ces fonctions inspectent la
chaîne de commande et consultent le périmètre actif (fail-closed : sans
périmètre, toute IPv4 est hors périmètre). La denylist est une liste de
blocage volontairement large (insensible à la casse) : en cas de doute, on bloque.
"""

import re
import shlex

from scope import ScopeError, assert_in_scope


class GuardrailError(Exception):
    """Commande rejetée par un garde-fou (ex. métacaractère shell)."""


SHELL_METACHARS: frozenset[str] = frozenset(";|&><`$\n\r")

DENYLIST: list[tuple[re.Pattern, str]] = [
    (re.compile(p, re.I), label)
    for p, label in [
        (r"\brm\s+-[a-z]*[rf]", "rm -rf"),
        (r"\bmkfs", "mkfs"),
        (r"\bdd\s+[^|]*\bof=", "dd of="),
        (r"\bshutdown\b", "shutdown"),
        (r"\breboot\b", "reboot"),
        (r":\(\)\s*\{", "fork-bomb"),
        (r"\bformat\s+[a-z]:", "format <lecteur>:"),
        (r"\bdel\s+/s", "del /s"),
        (r"\bDROP\s+(TABLE|DATABASE)\b", "DROP TABLE/DATABASE"),
        (r"\bTRUNCATE\b", "TRUNCATE"),
        (r"of=/dev/", "écriture périphérique bloc (of=/dev/)"),
        (r">\s*/dev/sd", "écriture périphérique bloc (>/dev/sd)"),
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
    """Littéraux IPv4 hors périmètre (dédoublonnés, ordre conservé)."""
    out: list[str] = []
    for ip in _IPV4.findall(rendered):
        if ip in out:
            continue
        try:
            assert_in_scope(ip)
        except ScopeError:
            out.append(ip)
    return out


def tokenize_argv(rendered: str) -> list[str]:
    """Découpe la commande en argv ; refuse tout métacaractère shell (avant split)."""
    meta = shell_metachar(rendered)
    if meta is not None:
        raise GuardrailError(f"métacaractère shell interdit : {meta!r}")
    return shlex.split(rendered, posix=True)


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
