"""Auteur de catalogue LLM borné : le LLM (injecté) propose une technique,
les garde-fous la valident, puis elle est persistée avec la mission."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path

import yaml

from catalog.loader import Technique, _technique_from_dict
from offense.guardrails import GuardrailError, destructive_match, shell_metachar, tokenize_argv
from state.mission_io import mission_dir


def build_author_prompt(service: str, context: str) -> str:
    """Consigne contrainte : un seul objet JSON, gabarit sans métacaractères."""
    return (
        f"Propose UNE technique offensive pour le service « {service} », sur une "
        "cible autorisée et dans le périmètre.\n"
        f"État réel de la mission (tiens-en compte) :\n{context}\n\n"
        "Ne propose PAS une technique listée comme déjà tentée ci-dessus ; "
        "appuie-toi sur la version du service et sur les échecs observés.\n"
        "Réponds par exactement UN objet JSON, sans autre texte, avec les clés : "
        "id, name, domain, service, requires, tool, command_template, "
        "success_signal, opens_session.\n"
        "command_template DOIT utiliser les placeholders {target} {user} {hash} "
        "{domain} {share} et JAMAIS de valeur littérale (IP, identifiant, mot de "
        "passe) : une technique à valeurs littérales n'est pas réutilisable.\n"
        "INTERDIT : métacaractères shell (; | & > < ` $) et toute action "
        "destructive (suppression, formatage, arrêt, déni de service)."
    )


def parse_technique(raw: str) -> dict | None:
    """Premier objet JSON complet de `raw` (prose/fences tolérées), sinon None."""
    if not isinstance(raw, str):
        return None
    try:
        obj, _ = json.JSONDecoder().raw_decode(raw[raw.index("{"):])
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def author_technique(service: str, context: str, llm_invoke) -> Technique | None:
    """Technique tagguée `llm` ou None si illisible / gabarit refusé."""
    d = parse_technique(llm_invoke(build_author_prompt(service, context)))
    if d is None:
        return None
    d["service"] = service
    d["provided_by"] = "llm"
    try:
        tech = _technique_from_dict(d)
    except (KeyError, TypeError):
        return None
    tpl = tech.command_template
    if shell_metachar(tpl) or destructive_match(tpl):
        try:
            from tools.registry import _audit
            _audit("LLM_TECH_REJECTED", f"{tech.id}: {tpl}")
        except Exception:
            pass
        return None
    return tech


def persist_llm_technique(tech: Technique, mission_id: str, root=None) -> Path:
    """Ajoute `tech` à missions/<id>/llm_catalog.yaml (relisible par le loader)."""
    d = mission_dir(mission_id, root)
    d.mkdir(parents=True, exist_ok=True)
    path = d / "llm_catalog.yaml"
    entries = []
    if path.exists():
        entries = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    entry = asdict(tech)
    entry["requires"] = sorted(tech.requires)
    entries.append(entry)
    path.write_text(yaml.safe_dump(entries, allow_unicode=True, sort_keys=False),
                    encoding="utf-8")
    return path


_IP_LITERAL = re.compile(
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b"                      # IPv4
    r"|::[0-9A-Fa-f]{0,4}"                               # IPv6 compressé (::1, fe80::1)
    r"|(?:[0-9A-Fa-f]{1,4}:){4,}[0-9A-Fa-f]{0,4}"        # IPv6 non compressé / MAC (>=4 groupes)
)
# La branche `::` sur-rejette un `::` isolé non-IP (ex. PowerShell [Ns]::Methode,
# pwdump `user:::`) : sur-rejection ASSUMÉE (fail-safe). Resserrer risquerait un
# faux NÉGATIF sur une vraie IPv6 — un trou, lui. On préfère sur-rejeter.

# Jeton à forte entropie : empreinte/hash/clé/token probable. Volontairement
# large (fail-closed) : hex >=16, ou base64 >=20 (couvre une clé de 16 octets,
# ~22 car.). On n'inclut PAS `_`/`-` dans la classe base64 : ils joignent des
# identifiants normaux (ex. NT_STATUS_LOGON_FAILURE) et provoqueraient un
# sur-masquage / sur-rejet. base64url strict non couvert → résiduel assumé.
_HIGH_ENTROPY = re.compile(r"\b[0-9A-Fa-f]{16,}\b|[A-Za-z0-9+/]{20,}={0,2}")

# Flags portant une valeur de credential : leur valeur DOIT être un {placeholder}
# (un nombre est toléré : un port n'est pas un secret). Les formes courtes
# `-p`/`-u` servent aussi de port/URL — `-H` (en-tête ou hash) est EXCLU car un
# vrai hash est déjà capté par l'entropie, ce qui évite de rejeter `curl -H ...`.
_CRED_FLAGS = frozenset({"-p", "--password", "--pass", "-passwd", "-pw",
                         "-hashes", "--hashes", "--hash",
                         "-u", "--user", "--username"})


def _carries_target_data(text: str, forbidden) -> bool:
    """Vrai si `text` porte une donnée de cible : IP littérale, jeton à forte
    entropie (hash/clé/token), ou une chaîne interdite (secret/principal connu,
    comparaison insensible à la casse). Fail-closed : en cas de doute, True."""
    if _IP_LITERAL.search(text) or _HIGH_ENTROPY.search(text):
        return True
    low = text.lower()
    return any(bad and len(bad) >= 3 and bad.lower() in low for bad in forbidden)


def _flag_value_is_literal(template: str) -> bool:
    """Vrai si un flag porteur de credential est suivi d'une valeur LITTÉRALE
    (ni {placeholder} ni nombre/port) — gabarit spécifique à la mission."""
    try:
        argv = tokenize_argv(template)
    except GuardrailError:
        return True  # non tokenisable → fail-closed
    for i in range(len(argv) - 1):
        val = argv[i + 1]
        if argv[i] in _CRED_FLAGS and "{" not in val and not val.isdigit():
            return True
    return False


def promote_techniques_to_rag(techniques, mission_id: str, forbidden=(), store=None) -> int:
    """Promeut les techniques rédigées par l'auteur LLM dans le RAG partagé.

    Fail-closed, invariant code-enforcé : une technique n'est persistée QUE si
    rien de ce qui serait écrit (page_content complet + metadata) ne porte de
    donnée de cible. Est rejetée (skip) toute technique dont ce contenu contient
    une IP littérale, un jeton à forte entropie (hash/clé/token, même inconnu),
    ou une chaîne de `forbidden` (secrets/principals connus, insensible à la
    casse) ; et toute technique dont le `command_template` met une valeur
    LITTÉRALE après un flag de credential (-p/-H/-u/…) au lieu d'un {placeholder}.
    `mission_id` est accepté mais volontairement ABSENT de la metadata (il
    contient l'IP cible). Id stable = hash(service|gabarit) → upsert idempotent.
    `store=None` → import paresseux du vectorstore. Renvoie le nombre promu.

    Résiduel assumé (documenté) : un secret en position exotique — userinfo
    d'URL (user:pass@h), en-tête (-H "Authorization: …"), argument positionnel,
    ou valeur attachée (--password=…) — ou de moins de 3 caractères, n'est pas
    systématiquement capté.
    """
    if not techniques:
        return 0
    texts, metadatas, ids = [], [], []
    for t in techniques:
        reqs = ", ".join(sorted(t.requires)) if t.requires else "aucun"
        text = (
            f"Technique « {t.name} » pour le service {t.service} "
            f"(outil {t.tool or '?'}). Commande : {t.command_template}. "
            f"Signal de succès : {t.success_signal or '?'}. Prérequis : {reqs}. "
            f"Ouvre une session : {t.opens_session}. Source : auteur LLM."
        )
        meta = {"source": "llm_authored", "service": t.service,
                "technique_id": t.id, "tool": t.tool or ""}
        # Scan de TOUT le contenu persisté (page_content + metadata), pas d'un
        # sous-ensemble de champs : aucune donnée de cible ne doit s'y glisser.
        scanned = text + " " + " ".join(str(v) for v in meta.values())
        if _carries_target_data(scanned, forbidden) or _flag_value_is_literal(t.command_template):
            continue  # spécifique à la mission → jamais dans le RAG partagé
        texts.append(text)
        metadatas.append(meta)
        digest = hashlib.sha1(
            f"{t.service}|{t.command_template}".encode("utf-8")).hexdigest()[:16]
        ids.append(f"llm:{digest}")
    if not texts:
        return 0
    if store is None:
        from agents.pirate_agent import vectorstore as store  # import paresseux
    store.add_texts(texts, metadatas=metadatas, ids=ids)
    return len(texts)
