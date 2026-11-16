"""Auteur de catalogue LLM borné : le LLM (injecté) propose une technique,
les garde-fous la valident, puis elle est persistée avec la mission."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

import yaml

from catalog.loader import Technique, _technique_from_dict
from offense.guardrails import destructive_match, shell_metachar
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
        "command_template peut utiliser les placeholders {target} {user} {hash} "
        "{domain} {share}.\n"
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


def promote_techniques_to_rag(techniques, mission_id: str, store=None) -> int:
    """Promeut les techniques rédigées par l'auteur LLM dans le RAG partagé.

    N'embarque QUE le gabarit de chaque technique (name/service/tool/
    command_template/success_signal/requires) — jamais une sortie d'exécution
    ni un credential : aucune donnée de la cible ne persiste dans le RAG. L'id
    est un hash du contenu (service + gabarit), donc une même technique rédigée
    sur deux missions fait un upsert plutôt qu'un doublon. `store=None` →
    import paresseux du vectorstore partagé. Renvoie le nombre promu.
    """
    if not techniques:
        return 0
    texts, metadatas, ids = [], [], []
    for t in techniques:
        reqs = ", ".join(sorted(t.requires)) if t.requires else "aucun"
        texts.append(
            f"Technique « {t.name} » pour le service {t.service} "
            f"(outil {t.tool or '?'}). Commande : {t.command_template}. "
            f"Signal de succès : {t.success_signal or '?'}. Prérequis : {reqs}. "
            f"Ouvre une session : {t.opens_session}. Source : auteur LLM."
        )
        metadatas.append({"source": "llm_authored", "service": t.service,
                          "technique_id": t.id, "tool": t.tool or "",
                          "mission_id": mission_id})
        digest = hashlib.sha1(
            f"{t.service}|{t.command_template}".encode("utf-8")).hexdigest()[:16]
        ids.append(f"llm:{digest}")
    if store is None:
        from agents.pirate_agent import vectorstore as store  # import paresseux
    store.add_texts(texts, metadatas=metadatas, ids=ids)
    return len(texts)
