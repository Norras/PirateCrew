"""Catalogue d'attaques enfichable de PirateCrew."""
from catalog.loader import (
    Technique,
    load_catalog,
    techniques_for,
    technique_by_id,
)

__all__ = ["Technique", "load_catalog", "techniques_for", "technique_by_id"]
