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
