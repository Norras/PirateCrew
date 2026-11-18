"""Chargement du catalogue d'attaques enfichable de PirateCrew.

Chaque technique est une entrée déclarative (YAML) : quoi lancer sur quel
service, avec quels prérequis, et comment reconnaître un succès.

- `builtin` : énumération standard non sensible, fournie avec le projet.
- `operator` : techniques offensives précises, livrées en **gabarit vide** et
  remplies par l'opérateur dans `catalog/operator/` (non versionné). Voir
  `catalog/operator.example.yaml`.

Le loader ne fait que lire des données ; il n'exécute rien.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class Technique:
    id: str
    name: str
    domain: str            # recon|web|ad|credentials|exploitation|post
    service: str           # ex. "smb", "http", "kerberos", "*" (transverse)
    requires: set[str]     # ex. {"credential"} ou {"session"} ou set()
    tool: str              # binaire/outil attendu
    command_template: str  # gabarit ; placeholders {target} {user} {hash} ...
    success_signal: str    # motif indiquant le succès dans la sortie
    provided_by: str       # "builtin" | "operator"
    opens_session: bool = False  # la réussite ouvre une session (non autorisée par défaut)


def _technique_from_dict(entry: dict) -> Technique:
    return Technique(
        id=entry["id"],
        name=entry.get("name", entry["id"]),
        domain=entry.get("domain", ""),
        service=entry.get("service", ""),
        requires=set([entry["requires"]] if isinstance(entry.get("requires"), str)
                     else (entry.get("requires") or [])),
        tool=entry.get("tool", ""),
        command_template=entry.get("command_template", ""),
        success_signal=entry.get("success_signal", ""),
        provided_by=entry.get("provided_by", "builtin"),
        opens_session=entry.get("opens_session", False),
    )


def _load_dir(path: str) -> list[Technique]:
    """Charge toutes les techniques des `*.yaml` d'un dossier. Dossier absent
    ⇒ liste vide (jamais d'exception)."""
    directory = Path(path)
    if not directory.is_dir():
        return []
    techniques: list[Technique] = []
    for yaml_file in sorted(directory.glob("*.yaml")):
        with open(yaml_file, "r", encoding="utf-8") as fh:
            entries = yaml.safe_load(fh) or []
        for entry in entries:
            techniques.append(_technique_from_dict(entry))
    return techniques


def load_catalog(builtin_dir: str = "catalog/builtin",
                 operator_dir: str = "catalog/operator") -> list[Technique]:
    """Catalogue complet = techniques `builtin` + `operator`.
    `operator_dir` absent ou vide ⇒ seules les `builtin` sont renvoyées."""
    return _load_dir(builtin_dir) + _load_dir(operator_dir)


def techniques_for(catalog: list[Technique], service: str) -> list[Technique]:
    """Techniques déclarées pour un service donné."""
    return [t for t in catalog if t.service == service]


def technique_by_id(catalog: list[Technique], tech_id: str) -> Technique:
    """Technique par identifiant. Lève `KeyError` si inconnue."""
    for t in catalog:
        if t.id == tech_id:
            return t
    raise KeyError(f"technique inconnue : {tech_id}")
