"""Identité de mission et persistance sur disque (missions/<id>/world.json)."""
import json
import re
from datetime import datetime
from pathlib import Path

MISSIONS_ROOT = Path(__file__).resolve().parent.parent / "missions"


def new_mission_id(target: str | None = None) -> str:
    """Identifiant de mission : `<cible assainie>-<horodatage>` (ou horodatage seul)."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    if target:
        safe = re.sub(r"[^A-Za-z0-9.]+", "_", target)
        return f"{safe}-{ts}"
    return ts


def mission_dir(mission_id: str, root: Path | None = None) -> Path:
    """Dossier de la mission ; MISSIONS_ROOT résolu à l'appel (monkeypatchable)."""
    root = MISSIONS_ROOT if root is None else root
    return Path(root) / mission_id


def save_world(world, mission_id: str, root: Path | None = None) -> Path:
    """Écrit le WorldModel en world.json et renvoie le chemin."""
    d = mission_dir(mission_id, root)
    d.mkdir(parents=True, exist_ok=True)
    path = d / "world.json"
    path.write_text(
        json.dumps(world.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return path


def _fmt_item(item) -> str:
    """Ligne lisible pour un butin (dict → `clé=valeur`, robuste aux clés absentes)."""
    if isinstance(item, dict):
        return ", ".join(f"{k}={v}" for k, v in item.items()) or "?"
    return str(item)


def _fmt_tool(e) -> str:
    """Ligne lisible pour une demande d'outil manquant."""
    if isinstance(e, dict):
        return f"{e.get('tool', '?')} — {e.get('technique', '?')} @ {e.get('host', '?')}"
    return str(e)


def render_report(world) -> str:
    """Rapport Markdown de fin de mission (credentials en clair, voulu par la spec)."""
    ips = [h.ip for h in world.in_scope_hosts()]
    services = [
        f"{h.ip}:{s.port}/{s.name or '?'}"
        for h in world.in_scope_hosts()
        for s in h.services
    ]
    tools = [e for e in world.evidence if e.get("kind") == "tool_request"]
    L = [
        "# Rapport de mission",
        "",
        f"{len(ips)} hôte(s) in-scope, {len(services)} service(s), "
        f"{len(world.credentials)} credential(s), {len(world.sessions)} session(s), "
        f"{len(world.loot)} butin(s).",
        "",
        "## Hôtes in-scope",
        *[f"- {ip}" for ip in ips],
        "",
        "## Services",
        *[f"- {s}" for s in services],
        "",
        "## Credentials",
        *[f"- {c.principal}:{c.secret} ({c.source})" for c in world.credentials],
        "",
        "## Sessions",
        *[
            f"- {s.host} via {s.channel} — {'autorisée' if s.authorized else 'en attente'}"
            for s in world.sessions
        ],
        "",
        "## Butin",
        *[f"- {_fmt_item(item)}" for item in world.loot],
        "",
        "## Techniques",
        *[
            f"- {h} {svc}:{port} {tech} — {status}"
            for (h, svc, tech, _fp, port), status in world.technique_ledger.items()
        ],
    ]
    if tools:
        L += ["", "## Outils manquants", *[f"- {_fmt_tool(e)}" for e in tools]]
    return "\n".join(L) + "\n"


def save_report(world, mission_id: str, root: Path | None = None) -> Path:
    """Écrit le rapport en rapport.md et renvoie le chemin."""
    d = mission_dir(mission_id, root)
    d.mkdir(parents=True, exist_ok=True)
    path = d / "rapport.md"
    path.write_text(render_report(world), encoding="utf-8")
    return path
