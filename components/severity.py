"""Severity badges: colour + a distinct shape icon + a text label, never colour alone.

The scale itself (levels, ordering, aliases) is services/severity.py.
"""
from __future__ import annotations

from html import escape
from typing import Optional

from services.severity import LEVELS, highest, normalize, rank  # noqa: F401  (re-exported for views)

ICONS = {"info": "ⓘ", "low": "●", "medium": "▲", "high": "◆", "critical": "✖"}
LABELS = {level: level.title() for level in LEVELS}
COLORS = {"info": "#22D3EE", "low": "#3B82F6", "medium": "#F59E0B", "high": "#F97316", "critical": "#EF4444"}


def badge(level: Optional[str], text: Optional[str] = None) -> str:
    key = normalize(level)
    label = text if text is not None else LABELS[key]
    return (f"<span class='ss-sev ss-sev-{key}' title='Severity: {LABELS[key]}'>"
            f"<span class='ss-sev-icon' aria-hidden='true'>{ICONS[key]}</span>{escape(label)}</span>")


def plain(level: Optional[str]) -> str:
    """Icon + label for places that cannot render HTML (tables, select boxes)."""
    key = normalize(level)
    return f"{ICONS[key]} {LABELS[key]}"
