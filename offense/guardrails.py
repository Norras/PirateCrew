"""Garde-fous offensifs : contrôles sur une commande déjà rendue.

`shell_metachar`, `destructive_match`, `tokenize_argv` et l'extraction d'hôtes
(`host_literals`, `_host_candidates`) sont purs. En revanche
`scope_violations`/`evaluate` APPLIQUENT le périmètre par RÉSOLUTION : chaque
token en forme d'hôte (IP littérale toutes notations, URL, UNC, user@h, h:port,
ou nom d'hôte) est passé par `assert_in_scope`, qui résout les noms (résolution
bornée + mise en cache, cf. scope.py) et journalise les refus (OUT_OF_SCOPE).
Ces deux fonctions font donc de la résolution réseau et un effet de bord
d'audit — fail-closed : hors périmètre, non résoluble, ou sans périmètre actif
⇒ violation (l'opérateur peut alors ajouter la cible au périmètre). La denylist
est volontairement large (insensible à la casse) : en cas de doute, on bloque.
"""

import ipaddress
import re
import shlex
from urllib.parse import urlparse

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

# Un token « ressemble à un FQDN » : au moins un point, labels alphanumériques
# (+ tiret), dernier label commençant par une lettre. Exclut les versions
# (2.2.15) et les IP pointées (dernier label numérique).
_FQDN_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.)+[A-Za-z][A-Za-z0-9-]{0,62}$")

# Extensions de fichier courantes : un token en forme de FQDN mais finissant par
# l'une d'elles est traité comme un NOM DE FICHIER (donnée), pas un hôte à
# résoudre. Heuristique anti-faux-positif (ex. `-oN scan.txt`), assumée : un vrai
# hôte dont le TLD figure ici (rare) ne serait pas contrôlé — résiduel documenté.
_NON_HOST_SUFFIXES = frozenset({
    "txt", "log", "csv", "json", "xml", "yaml", "yml", "ini", "conf", "cfg",
    "html", "htm", "md", "pdf", "png", "jpg", "jpeg", "gif", "svg",
    "zip", "gz", "tgz", "tar", "bz2", "7z", "rar", "bak", "dump", "db", "sqlite",
    "pem", "key", "crt", "cer", "pfx", "p12", "sh", "py", "pl", "rb", "ps1",
    "exe", "dll", "so", "bin", "dat", "out", "nmap", "gnmap", "lst", "wordlist",
})


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


def _host_from_token(tok: str) -> str | None:
    """Extrait l'hôte d'un token argv : URL (http://h:port/p), UNC (//h/s),
    user@h, [ipv6], h:port, sinon le token nettoyé d'un chemin. None si rien
    d'exploitable. Pur (aucune résolution)."""
    t = (tok or "").strip().strip("\"'")
    if not t:
        return None
    if "://" in t:                                   # URL
        try:
            return urlparse(t).hostname or None
        except ValueError:
            return None
    if t.startswith("//") or t.startswith("\\\\"):   # UNC //host/share
        return re.split(r"[/\\]", t.lstrip("/\\"), maxsplit=1)[0] or None
    if "@" in t:                                     # user:pass@host
        t = t.rsplit("@", 1)[1]
    if t.startswith("[") and "]" in t:               # [ipv6] ou [ipv6]:port
        return t[1:t.index("]")] or None
    t = re.split(r"[/\\]", t, maxsplit=1)[0]         # retire un chemin éventuel
    if t.count(":") == 1:                            # host:port (IPv6 a >= 2 ':')
        t = t.split(":", 1)[0]
    return t or None


def _host_candidates(rendered: str) -> list[str]:
    """Hôtes/IP candidats d'une commande rendue (ordre conservé, dédoublonnés). Pur."""
    try:
        tokens = shlex.split(rendered or "", posix=True)
    except ValueError:
        tokens = (rendered or "").split()
    out: list[str] = []
    for tok in tokens:
        host = _host_from_token(tok)
        if host and host not in out:
            out.append(host)
    return out


def _host_kind(cand: str) -> str | None:
    """Classe un candidat : 'ip' (littérale valide v4/v6), 'bad_ipv4' (quad pointé
    invalide → violation locale sans DNS), 'decimal_ip' (entier > 65535, évasion
    décimale), 'hostname' (FQDN hors extensions de fichier), ou None (à ignorer).
    Pur (aucune résolution)."""
    try:
        ipaddress.ip_address(cand)
        return "ip"
    except ValueError:
        pass
    if _IPV4.fullmatch(cand):
        return "bad_ipv4"
    if cand.isdigit():
        n = int(cand)
        return "decimal_ip" if 65535 < n <= 0xFFFFFFFF else None
    if _FQDN_RE.match(cand):
        return None if cand.rsplit(".", 1)[-1].lower() in _NON_HOST_SUFFIXES else "hostname"
    return None


def host_literals(text: str) -> list[str]:
    """Hôtes/IP LITTÉRAUX d'une commande/gabarit (les placeholders `{…}` ne sont
    pas des hôtes). Pur, SANS résolution : sert à l'authoring (un gabarit
    réutilisable ne doit porter aucun littéral, seulement `{target}`)."""
    return [c for c in _host_candidates(text) if _host_kind(c) is not None]


def scope_violations(rendered: str) -> list[str]:
    """Hôtes/IP de la commande HORS périmètre (dédoublonnés, ordre conservé).

    Applique le périmètre par RÉSOLUTION sur le chemin d'exécution : chaque token
    en forme d'hôte est passé par `assert_in_scope` (qui résout les noms, de façon
    bornée et mise en cache). Un nom hors périmètre OU non résoluble est une
    violation (fail-closed). Cas particuliers sans DNS : un quad pointé invalide
    (256.0.0.1) est signalé localement ; un entier <= 65535 (port) et un nom de
    fichier (extension connue) ne sont pas traités comme des hôtes. L'évasion
    décimale (ex. 167772169 = 10.0.0.9) est normalisée puis contrôlée sans DNS.
    """
    out: list[str] = []
    for cand in _host_candidates(rendered):
        if cand in out:
            continue
        kind = _host_kind(cand)
        if kind is None:
            continue
        if kind == "bad_ipv4":
            out.append(cand)              # quad pointé invalide : violation locale, jamais de DNS
            continue
        target = str(ipaddress.ip_address(int(cand))) if kind == "decimal_ip" else cand
        try:
            assert_in_scope(target)       # 'ip'/'decimal_ip' : littéral (sans DNS) ; 'hostname' : résout
        except ScopeError:
            out.append(cand)
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
