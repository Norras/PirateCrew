"""Catalogue centralisé des outils d'intervention de PirateCrew.

Deux groupes :
- MANDATORY_TOOLS : outils injectés dans TOUS les agents d'intervention (audit).
- TOOL_CATALOG    : outils conditionnels indexés par domaine (network, web, ad),
                    injectés à la volée par la fabrique build_task_agent.

Sécurité :
- subprocess en shell=False avec arguments en liste (pas d'injection shell).
- validation de la cible (rejet des métacaractères).
- timeouts systématiques.
- journalisation de chaque action dans audit.log.

Usage sur cibles autorisées uniquement (lab HTB, VM perso, périmètre d'audit consenti).
"""

import os
import re
import socket
import shutil
import subprocess
import http.client
from datetime import datetime
from urllib.parse import urlparse

from langchain_core.tools import tool

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_LOG = os.path.join(PROJECT_ROOT, "audit.log")

# Hostnames, IPv4, IPv6 (les ':' sont autorisés pour IPv6). Rien d'autre.
_TARGET_RE = re.compile(r"^[A-Za-z0-9._:-]+$")

# Ports courants testés en repli quand nmap est absent.
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5985, 8080]


# --------------------------------------------------------------------------- #
# Helpers internes (non exposés comme outils)
# --------------------------------------------------------------------------- #
def _audit(action: str, detail: str = "") -> str:
    """Append horodaté dans audit.log. Jamais bloquant."""
    line = f"{datetime.now().isoformat(timespec='seconds')} | {action} | {detail}\n"
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass
    return line


def _validate_target(target: str) -> str:
    """Normalise et valide une cible. Défaut : 127.0.0.1. Lève si invalide."""
    target = (target or "").strip()
    if not target:
        return "127.0.0.1"
    if not _TARGET_RE.match(target):
        raise ValueError(f"Cible invalide (caractères non autorisés) : {target!r}")
    return target


def _run(cmd_list, timeout: int = 120) -> str:
    """subprocess.run borné et audité. Ne lève pas : renvoie un message en cas d'échec."""
    _audit("RUN", " ".join(cmd_list))
    try:
        proc = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except FileNotFoundError:
        msg = f"Binaire introuvable : {cmd_list[0]!r} (absent du PATH). Installez-le pour utiliser cet outil."
        _audit("ERROR", msg)
        return msg
    except subprocess.TimeoutExpired:
        msg = f"Délai dépassé ({timeout}s) pour : {' '.join(cmd_list)}"
        _audit("TIMEOUT", msg)
        return msg
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return output or "(aucune sortie)"


# --------------------------------------------------------------------------- #
# Outil obligatoire : journalisation d'audit
# --------------------------------------------------------------------------- #
@tool
def log_audit_event(action: str, detail: str = "") -> str:
    """Journalise une action d'audit horodatée dans audit.log.
    À appeler pour tracer chaque étape sensible d'une mission (cible, décision, finding)."""
    _audit(f"AGENT:{action}", detail)
    return f"Événement journalisé : {action} — {detail}"


# --------------------------------------------------------------------------- #
# Domaine : network
# --------------------------------------------------------------------------- #
@tool
def nmap_scan(target: str, mode: str = "quick") -> str:
    """Scanne une cible AUTORISÉE avec nmap.
    mode='quick' (-T4 -F) pour un scan rapide des ports courants,
    mode='aggressive' (-T4 -A) pour détection de version/OS/scripts.
    Retourne la sortie brute nmap (ports et services ouverts)."""
    target = _validate_target(target)
    if shutil.which("nmap") is None:
        msg = ("nmap n'est pas installé/accessible sur cette machine. "
               "Utilise tcp_port_check en repli, ou installe nmap pour un scan complet.")
        _audit("SKIP", f"nmap_scan {target}: {msg}")
        return msg
    flags = ["-T4", "-A"] if mode == "aggressive" else ["-T4", "-F"]
    return _run(["nmap", *flags, target], timeout=300)


@tool
def tcp_port_check(target: str, port: int) -> str:
    """Teste si un port TCP est ouvert sur une cible AUTORISÉE.
    Socket pur Python : fonctionne sans aucun outil externe. Sert de repli à nmap."""
    target = _validate_target(target)
    try:
        port = int(port)
    except (TypeError, ValueError):
        return f"Port invalide : {port!r}"
    _audit("TCP_CHECK", f"{target}:{port}")
    try:
        with socket.create_connection((target, port), timeout=5):
            return f"{target}:{port} → OUVERT"
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return f"{target}:{port} → fermé/inaccessible ({type(exc).__name__})"


# --------------------------------------------------------------------------- #
# Domaine : web
# --------------------------------------------------------------------------- #
@tool
def http_fingerprint(url: str) -> str:
    """Récupère le code de statut HTTP et les en-têtes révélateurs (Server, X-Powered-By, …)
    d'une URL AUTORISÉE. Préfixe http:// si le schéma est absent. Stdlib uniquement."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    _validate_target(host)
    _audit("HTTP_FINGERPRINT", url)
    is_https = parsed.scheme == "https"
    conn_cls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
    port = parsed.port or (443 if is_https else 80)
    path = parsed.path or "/"
    try:
        conn = conn_cls(host, port, timeout=8)
        conn.request("HEAD", path)
        resp = conn.getresponse()
        headers = dict(resp.getheaders())
        status, reason = resp.status, resp.reason
        conn.close()
    except Exception as exc:  # noqa: BLE001 - on rapporte toute erreur réseau proprement
        return f"Échec de la connexion à {url} ({type(exc).__name__}: {exc})"
    révélateurs = {
        k: v for k, v in headers.items()
        if k.lower() in ("server", "x-powered-by", "x-aspnet-version", "via", "x-generator")
    }
    return (f"{url} → HTTP {status} {reason}\n"
            f"En-têtes révélateurs : {révélateurs or '(aucun)'}")


# --------------------------------------------------------------------------- #
# Domaine : ad (Active Directory / SMB)
# --------------------------------------------------------------------------- #
@tool
def smb_port_probe(target: str) -> str:
    """Vérifie l'ouverture des ports SMB (445) et NetBIOS (139) sur une cible AUTORISÉE.
    Indice de surface Active Directory / partage de fichiers. Socket pur Python."""
    target = _validate_target(target)
    _audit("SMB_PROBE", target)
    résultats = []
    for port in (445, 139):
        try:
            with socket.create_connection((target, port), timeout=5):
                résultats.append(f"{port}=OUVERT")
        except OSError:
            résultats.append(f"{port}=fermé")
    résumé = ", ".join(résultats)
    piste = ""
    if "445=OUVERT" in résumé:
        piste = ("\nSMB exposé → pistes d'énumération AUTORISÉE : sessions nulles, listing de partages, "
                 "énumération d'utilisateurs (ex. enum4linux, smbclient -L). Aucune exploitation automatique.")
    return f"SMB/NetBIOS sur {target} : {résumé}{piste}"


# --------------------------------------------------------------------------- #
# Registre
# --------------------------------------------------------------------------- #
MANDATORY_TOOLS = [log_audit_event]

TOOL_CATALOG = {
    "network": [nmap_scan, tcp_port_check],
    "web": [http_fingerprint],
    "ad": [smb_port_probe],
}
