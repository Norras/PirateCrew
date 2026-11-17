"""Garde-fous offensifs : contrôles sur une commande.

Deux niveaux d'application du périmètre, pour éviter de confondre une cible de
connexion avec un argument d'identité (-d corp.local), un débit (--rate 100000)
ou un fichier (-oN scan.txt) :

- `scope_literal_violations(gabarit)` — contrôle de RÉFÉRENCE du chemin offensif,
  appelé sur le GABARIT (placeholders {target}/{domain}/{share} encore intacts,
  jamais pris pour des hôtes). Chaque hôte LITTÉRAL (IP toutes notations pointées,
  nom d'hôte, hôte d'URL/UNC) est passé par `assert_in_scope`, qui RÉSOUT les noms
  (borné + caché, cf. scope.py). Fail-closed : hors périmètre / non résoluble /
  sans périmètre ⇒ violation (l'opérateur peut ajouter la cible au périmètre).
- `scope_violations(rendu)`/`evaluate` — backstop sur la commande RENDUE, limité
  aux IP LITTÉRALES (aucun DNS, aucun faux positif) : les noms et les entiers nus
  n'y sont pas contrôlés (ils le sont sur le gabarit).

`shell_metachar`, `destructive_match`, `tokenize_argv`, `host_literals` et
l'extraction/classification d'hôtes sont purs. La denylist est volontairement
large (insensible à la casse) : en cas de doute, on bloque.
"""

import ipaddress
import re
import shlex
import socket
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


def _normalize_ipv4_any(cand: str) -> str | None:
    """IPv4 pointée normalisée si `cand` est une forme acceptée par inet_aton
    (décimale/octale/hexadécimale pointée, comme nmap/curl), sinon None. Pur."""
    try:
        return socket.inet_ntoa(socket.inet_aton(cand))
    except (OSError, UnicodeError, TypeError):
        return None


def _host_kind(cand: str) -> str | None:
    """Classe un candidat — formes NON ambiguës uniquement :
    'ip6' (IPv6 littérale), 'ip4' (quad POINTÉ valide, octal/hex inclus via
    inet_aton), 'bad_ipv4' (quad pointé invalide → violation locale sans DNS),
    'hostname' (FQDN hors extensions de fichier), sinon None. Pur.

    Un entier/hex/octal NU (sans point) renvoie None : indissociable d'une valeur
    numérique de CLI (débit, taille) par la seule valeur → non traité en hôte
    (résiduel assumé : une IP encodée en un seul entier nu n'est pas captée). La
    cible sanctionnée {target}, elle, est in-scope par construction."""
    try:
        if ipaddress.ip_address(cand).version == 6:
            return "ip6"
    except ValueError:
        pass
    if "." in cand:                                   # IPv4 : formes POINTÉES seulement
        if len(cand.split(".")) == 4 and _normalize_ipv4_any(cand) is not None:
            return "ip4"
        if _IPV4.fullmatch(cand):                     # 4 décimaux mais invalide (ex. 256.0.0.1)
            return "bad_ipv4"
        if _FQDN_RE.match(cand):
            return None if cand.rsplit(".", 1)[-1].lower() in _NON_HOST_SUFFIXES else "hostname"
    return None


def host_literals(text: str) -> list[str]:
    """Hôtes/IP LITTÉRAUX d'un gabarit/commande (dédoublonnés, ordre conservé) :
    IP pointées, noms d'hôte, hôtes d'URL/UNC. Les placeholders `{…}` et les
    entiers nus n'en sont PAS. Pur, SANS résolution : sert à l'authoring et au
    contrôle de périmètre sur le gabarit."""
    out: list[str] = []
    for cand in _host_candidates(text):
        if cand not in out and _host_kind(cand) is not None:
            out.append(cand)
    return out


def scope_violations(rendered: str) -> list[str]:
    """Backstop sur la commande RENDUE : IP LITTÉRALES hors périmètre (sans DNS,
    sans faux positif). Ne contrôle QUE les IP pointées (v4 toutes bases via
    inet_aton, v6, quad invalide) — jamais un nom d'hôte ni un entier nu, pour ne
    pas sur-bloquer un argument d'identité (-d corp.local) ou un débit
    (--rate 100000). Les noms d'hôte littéraux sont contrôlés, avec résolution,
    sur le gabarit via `scope_literal_violations`.
    """
    out: list[str] = []
    for cand in _host_candidates(rendered):
        if cand in out:
            continue
        kind = _host_kind(cand)
        if kind not in ("ip4", "ip6", "bad_ipv4"):    # noms/entiers nus : pas ici (cf. docstring)
            continue
        if kind == "bad_ipv4":
            out.append(cand)                           # quad invalide : violation locale, jamais de DNS
            continue
        target = _normalize_ipv4_any(cand) if kind == "ip4" else cand
        try:
            assert_in_scope(target)                    # IP littérale : aucun DNS
        except ScopeError:
            out.append(cand)
    return out


def scope_literal_violations(text: str) -> list[str]:
    """Hôtes/IP LITTÉRAUX du gabarit HORS périmètre (dédoublonnés, ordre conservé).

    Contrôle de périmètre de référence du chemin offensif. Opère sur le GABARIT
    (placeholders {target}/{domain}/{share} intacts → jamais confondus avec des
    hôtes). Chaque littéral — IP (notations pointées) OU nom d'hôte OU hôte
    d'URL/UNC — passe par `assert_in_scope`, qui RÉSOUT les noms (borné + caché).
    Hors périmètre, non résoluble, ou sans périmètre actif ⇒ violation
    (fail-closed) : l'opérateur peut alors ajouter la cible au périmètre.
    {target} (cible sanctionnée) reste in-scope par construction.
    """
    out: list[str] = []
    for cand in host_literals(text):
        if cand in out:
            continue
        kind = _host_kind(cand)
        if kind == "bad_ipv4":
            out.append(cand)
            continue
        target = _normalize_ipv4_any(cand) if kind == "ip4" else cand
        try:
            assert_in_scope(target)                    # 'ip4' : sans DNS ; 'hostname' : résout
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
