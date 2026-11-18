"""Loading of PirateCrew's pluggable attack catalog.

Each technique is a declarative (YAML) entry: what to run against which
service, with which prerequisites, and how to recognize success.

- `builtin`: standard, non-sensitive enumeration, shipped with the project.
- `operator`: specific offensive techniques, shipped as an **empty template**
  and filled in by the operator in `catalog/operator/` (not versioned). See
  `catalog/operator.example.yaml`.

The loader only reads data; it executes nothing.
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
    service: str           # e.g. "smb", "http", "kerberos", "*" (cross-cutting)
    requires: set[str]     # e.g. {"credential"} or {"session"} or set()
    tool: str              # expected binary/tool
    command_template: str  # template; placeholders {target} {user} {hash} ...
    success_signal: str    # pattern indicating success in the output
    provided_by: str       # "builtin" | "operator"
    opens_session: bool = False  # success opens a session (unauthorized by default)


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
    """Load all techniques from a directory's `*.yaml` files. Missing directory
    ⇒ empty list (never an exception)."""
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
    """Full catalog = `builtin` + `operator` techniques.
    Missing or empty `operator_dir` ⇒ only the `builtin` ones are returned."""
    return _load_dir(builtin_dir) + _load_dir(operator_dir)


def techniques_for(catalog: list[Technique], service: str) -> list[Technique]:
    """Techniques declared for a given service, plus the cross-cutting ones (`service: "*"`)."""
    return [t for t in catalog if t.service in (service, "*")]


def technique_by_id(catalog: list[Technique], tech_id: str) -> Technique:
    """Technique by identifier. Raises `KeyError` if unknown."""
    for t in catalog:
        if t.id == tech_id:
            return t
    raise KeyError(f"unknown technique: {tech_id}")
