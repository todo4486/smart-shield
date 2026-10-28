"""One severity scale for the whole platform: Info < Low < Medium < High < Critical (pure).

"Info" is a UI level only (notices, unavailable data); alerts in the database use low…critical.
Rendering (colour + icon + label) lives in components/severity.py.
"""
from __future__ import annotations

from typing import Iterable, Optional

LEVELS = ("info", "low", "medium", "high", "critical")
_ALIASES = {"normal": "low", "ok": "low", "elevated": "medium", "warn": "medium", "warning": "medium"}


def normalize(level: Optional[str]) -> str:
    """Map any stored severity or risk word onto the five levels (unknown/None → info)."""
    value = (level or "").strip().lower()
    value = _ALIASES.get(value, value)
    return value if value in LEVELS else "info"


def rank(level: Optional[str]) -> int:
    return LEVELS.index(normalize(level))


def highest(levels: Iterable[Optional[str]]) -> Optional[str]:
    """The most severe level, or None when there is nothing to rank."""
    known = [normalize(level) for level in levels if level]
    return max(known, key=LEVELS.index) if known else None
