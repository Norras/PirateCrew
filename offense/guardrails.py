"""Garde-fous offensifs : contrôles sur une commande.

GEL (18/11/2026) — le contrôle TEXTE du périmètre ci-dessous est une défense en
profondeur, plus la frontière. La frontière est `offense/netns.py` : les
commandes s'exécutent dans un namespace réseau dont le noyau ne laisse sortir
que les IP du périmètre, quelle que soit l'écriture de l'hôte. Ne plus ajouter
ici de notation d'hôte : trois revues adverses ont montré que cette liste ne
converge pas. Les contrôles non réseau (métacaractères shell, commandes
destructrices) restent, eux, pleinement en vigueur.

Deux niveaux d'application du périmètre, pour éviter de confondre une cible de
connexion avec un argument d'identité (-d corp.local), un débit (--rate 100000)
ou un fichier (-oN scan.txt) :

- `scope_literal_violations(gabarit)` — contrôle de RÉFÉRENCE du chemin offensif,
  appelé sur le GABARIT (placeholders {target}/{domain}/{share} encore intacts,
  jamais pris pour des hôtes). Chaque hôte LITTÉRAL (IP toutes notations — pointées
  toutes bases, abrégées type 8.524296, et entier nu en position d'hôte d'URL/UNC —,
  nom d'hôte y compris point final, hôte d'URL/UNC) est passé par `assert_in_scope`,
  qui RÉSOUT les noms (borné + caché, cf. scope.py). Fail-closed : hors périmètre /
  non résoluble / sans périmètre ⇒ violation (l'opérateur ajoute la cible au périmètre).
- `scope_violations(rendu)`/`evaluate` — backstop sur la commande RENDUE, limité aux
  IP LITTÉRALES (aucun DNS, aucun faux positif), notations abrégées comprises. Les
  NOMS d'hôte n'y sont pas résolus (ils le sont sur le gabarit) ; un entier nu n'est
  traité en IP que s'il est en POSITION D'HÔTE (URL/UNC/user@), jamais un entier
  d'argument (--rate 100000).

La classification d'hôte reste un filtre best-effort : la notation est déléguée à
l'OS (inet_aton / résolveur), non réimplémentée, mais distinguer un entier nu
d'argument d'une IP encodée reste indécidable hors position d'hôte — frontière
assumée, la borne réelle étant la résolution déterministe + la contrainte {target}.

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
# (+ tiret), dernier label commençant par une lettre, point final (racine DNS)
# optionnel (evil.example.com. est un hôte, résolu par nc/curl). Exclut les
# IP pointées (dernier label numérique → non capté ici, traité en IPv4).
_FQDN_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.)+[A-Za-z][A-Za-z0-9-]{0,62}\.?$")

# Label DNS unique, sans point (localhost, dc01, wpad, noms NetBIOS/AD courts),
# point final optionnel. Traité comme hôte UNIQUEMENT en position structurée
# (URL/UNC/user@) : un label nu est indissociable d'un nom d'outil/flag/valeur
# (nmap, admin, -sV) → jamais hôte hors position d'hôte, sinon faux positif massif.
_HOSTLABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.?$")

# Schéma d'URI suivi d'un nombre ANORMAL de slashs (http:/h, http:///h). curl/wget
# sautent tous les slashs de tête puis lisent l'autorité jusqu'au délimiteur suivant,
# alors qu'urlparse n'alimente netloc que sur '://' exact : sans renormalisation,
# http:///IP et http:/IP sont muets alors que l'outil se connecte bien à l'IP.
_SCHEME_SLASHES_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]+):/+")  # schéma ≥2 car. (pas un lecteur C:/)

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
    # formats de sortie/capture offensifs courants (noms de FICHIERS, pas des hôtes)
    "pcap", "pcapng", "cap", "scan", "report", "results", "ndjson", "jsonl",
    "har", "nessus",
})

# Schémas d'URI qui EXIGENT une autorité réseau : seuls ceux-là voient leurs slashs
# de tête renormalisés (http:/h, http:///h → http://h). Un schéma à autorité vide
# (file:, data:, classpath:, jar:…) N'est PAS renormalisé, sinon le 1er segment de
# chemin deviendrait un hôte fantôme (file:///etc/passwd → 'etc').
_NETWORK_SCHEMES: frozenset[str] = frozenset({
    "http", "https", "ftp", "ftps", "sftp", "ssh", "scp", "smb", "cifs", "telnet",
    "ldap", "ldaps", "rdp", "vnc", "rtsp", "ws", "wss", "redis", "mysql", "mssql",
    "mongodb", "gopher", "dict", "rsync", "nfs",
})

# Flags dont la VALEUR @ est une identité (UPN user@realm) : on n'extrait pas d'hôte du
# token QUI SUIT ET CONTIENT '@' (cf. _host_candidates). On ne skippe QUE la forme @ :
# un hôte nu après -u (nc = UDP) ou -d (nmap = debug) reste contrôlé (pas de contournement).
_IDENTITY_FLAGS: frozenset[str] = frozenset({
    "-u", "--user", "--username", "-U", "-p", "--password", "--pass",
    "-d", "--domain", "-H", "--hashes", "--hash",
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


def _host_from_token(tok: str) -> tuple[str, bool] | None:
    """Extrait `(hôte, structuré)` d'un token argv. None si rien d'exploitable. Pur.

    `structuré` vaut True quand l'hôte provient d'une POSITION D'HÔTE non ambiguë —
    URL (http://h:port/p), UNC (//h/s), user@h, [ipv6] : ce qui s'y trouve EST un
    hôte, même encodé en entier nu (http://2130706433/). Un token nu (structuré=False :
    h:port ou le token nettoyé d'un chemin) n'est traité en hôte que s'il en a la
    FORME (cf. `_host_kind`), pour ne pas prendre un entier d'argument (--rate 100000)
    pour une IP."""
    t = (tok or "").strip().strip("\"'")
    if not t:
        return None
    m = _SCHEME_SLASHES_RE.match(t)
    if m and m.group(1).lower() in _NETWORK_SCHEMES:  # schéma RÉSEAU + slashs anormaux → '://'
        t = m.group(1) + "://" + t[m.end():]          # (jamais file:/data: → pas d'hôte fantôme)
    if "://" in t:                                   # URL
        try:
            h = urlparse(t).hostname
        except ValueError:
            return None
        return (h, True) if h else None
    if t.startswith("//") or t.startswith("\\\\"):   # UNC //host/share
        h = re.split(r"[/\\]", t.lstrip("/\\"), maxsplit=1)[0]
        return (h, True) if h else None
    structured = False
    if "@" in t:                                     # user:pass@host
        t = t.rsplit("@", 1)[1]
        structured = True
    if t.startswith("[") and "]" in t:               # [ipv6] ou [ipv6]:port
        h = t[1:t.index("]")]
        return (h, True) if h else None
    t = re.split(r"[/\\]", t, maxsplit=1)[0]         # retire un chemin éventuel
    if t.count(":") == 1:                            # host:port (IPv6 a >= 2 ':')
        t = t.split(":", 1)[0]
    return (t, structured) if t else None


def _host_candidates(rendered: str) -> list[tuple[str, bool]]:
    """Candidats `(hôte, structuré)` d'une commande rendue (ordre conservé,
    dédoublonnés par hôte). Si un même hôte apparaît en position nue ET structurée,
    le flag structuré l'emporte. Pur."""
    try:
        tokens = shlex.split(rendered or "", posix=True)
    except ValueError:
        tokens = (rendered or "").split()
    out: list[tuple[str, bool]] = []
    pos: dict[str, int] = {}
    prev = ""
    for tok in tokens:
        # On ne skippe QUE la forme @ d'un flag d'identité (-u svc@REALM = UPN/credential,
        # jamais une cible de connexion). Un hôte NU après le même flag garde son contrôle :
        # -u est aussi « UDP » (nc), -d « debug » (nmap) -> nc -u IP / nmap -d IP restent vérifiés.
        is_identity_at_value = prev in _IDENTITY_FLAGS and "@" in tok
        prev = tok
        if is_identity_at_value:
            continue
        res = _host_from_token(tok)
        if res is None:
            continue
        host, structured = res
        if host in pos:
            i = pos[host]
            out[i] = (host, out[i][1] or structured)
        else:
            pos[host] = len(out)
            out.append((host, structured))
    return out


def _normalize_ipv4_any(cand: str) -> str | None:
    """IPv4 pointée normalisée si `cand` est une forme acceptée par inet_aton
    (décimale/octale/hexadécimale pointée, comme nmap/curl), sinon None. Pur.

    Un point final unique (racine DNS : 203.0.113.9.) est retiré avant inet_aton :
    inet_aton le rejette alors que getaddrinfo/curl l'acceptent et se connectent."""
    try:
        return socket.inet_ntoa(socket.inet_aton(cand))
    except (OSError, UnicodeError, TypeError):
        pass
    if cand.endswith(".") and not cand.endswith(".."):
        try:
            return socket.inet_ntoa(socket.inet_aton(cand[:-1]))
        except (OSError, UnicodeError, TypeError):
            return None
    return None


def _host_kind(cand: str, structured: bool = False) -> str | None:
    """Classe un candidat — formes NON ambiguës uniquement :
    'ip6' (IPv6 littérale), 'ip4' (IPv4 toutes bases via inet_aton — décimal, octal,
    hex — formes abrégées comprises : 8.524296, 127.1), 'bad_ipv4' (quad décimal
    pointé invalide → violation locale sans DNS), 'hostname' (FQDN, point final
    optionnel, hors extensions de fichier), sinon None. Pur.

    `structured`=True (hôte issu d'une position d'URL/UNC/user@/[ipv6]) accepte comme
    'ip4' un entier nu encodant une IP (http://2130706433/ == 127.0.0.1) : en position
    d'hôte, un entier EST l'hôte. Hors de là, un entier NU (sans point) renvoie None,
    indissociable d'une valeur numérique de CLI (débit, taille) — résiduel assumé :
    une IP encodée en un seul entier nu HORS position d'hôte n'est pas captée ; la
    cible sanctionnée {target} est in-scope par construction."""
    try:
        if ipaddress.ip_address(cand).version == 6:
            return "ip6"
    except ValueError:
        pass
    # IPv4 toutes bases (inet_aton). On exige un point sur un token NU — sinon un
    # entier nu (--rate 100000 == 0.1.134.160) serait pris pour une IP ; en position
    # d'hôte STRUCTURÉE l'entier encodé est bien l'hôte, donc accepté sans point.
    if ("." in cand or structured) and _normalize_ipv4_any(cand) is not None:
        return "ip4"
    if "." in cand:
        if _IPV4.fullmatch(cand):                     # 4 décimaux mais invalide (ex. 256.0.0.1)
            return "bad_ipv4"
        if _FQDN_RE.match(cand):
            if structured:                            # position d'hôte d'URL/UNC : TOUJOURS un
                return "hostname"                     # hôte (TLD .zip/.sh inclus), jamais un fichier
            suffix = cand.rstrip(".").rsplit(".", 1)[-1].lower()  # point final ignoré
            return None if suffix in _NON_HOST_SUFFIXES else "hostname"
    if structured and _HOSTLABEL_RE.match(cand):      # label unique EN POSITION D'HÔTE
        return "hostname"                             # (http://localhost/, ssh u@dc01, //wpad/s)
    return None


def host_literals(text: str) -> list[str]:
    """Hôtes/IP LITTÉRAUX d'un gabarit/commande (dédoublonnés, ordre conservé) :
    IP pointées, noms d'hôte, hôtes d'URL/UNC. Les placeholders `{…}` et les
    entiers nus n'en sont PAS. Pur, SANS résolution : sert à l'authoring et au
    contrôle de périmètre sur le gabarit."""
    out: list[str] = []
    for cand, structured in _host_candidates(text):
        if cand not in out and _host_kind(cand, structured) is not None:
            out.append(cand)
    return out


def scope_violations(rendered: str) -> list[str]:
    """Backstop sur la commande RENDUE : IP LITTÉRALES hors périmètre (sans DNS,
    sans faux positif). Ne contrôle QUE les IP (v4 toutes bases via inet_aton,
    formes abrégées comprises ; v6 ; quad décimal invalide) et l'entier encodant
    une IP en POSITION D'HÔTE (URL/UNC/user@) — jamais un nom d'hôte (résolu sur le
    gabarit via `scope_literal_violations`) ni un entier nu d'argument, pour ne pas
    sur-bloquer un argument d'identité (-d corp.local) ou un débit (--rate 100000).
    """
    out: list[str] = []
    for cand, structured in _host_candidates(rendered):
        if cand in out:
            continue
        kind = _host_kind(cand, structured)
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
    for cand, structured in _host_candidates(text):
        if cand in out:
            continue
        kind = _host_kind(cand, structured)
        if kind is None:                               # placeholder, entier nu hors hôte, fichier
            continue
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
