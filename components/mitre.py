"""MITRE ATT&CK badges for alerts and incidents (mapping in services/mitre.py)."""
from __future__ import annotations

from html import escape
from typing import Iterable

from services import mitre


def _badge(t: mitre.Technique) -> str:
    return (f"<span class='ss-mitre' title='{escape(t.tactic)} ({t.tactic_id}) · {escape(t.technique)} · "
            f"label-level mapping, not a confirmed technique · {escape(t.url)}'>"
            f"{escape(t.tactic)} · <b>{escape(t.technique_id)}</b> {escape(t.technique)}</span>")


_NONE = ("<span class='ss-mitre ss-mitre-none' title='No ATT&amp;CK technique fits this category, so none is "
         "shown rather than a guess.'>ATT&amp;CK: no mapping</span>")


def badges(label: str, *, all_techniques: bool = False) -> str:
    """Tactic · technique badge(s) for one attack-type label; a muted 'no mapping' badge otherwise."""
    found = mitre.techniques_for(label)
    if not found:
        return _NONE
    return "".join(_badge(t) for t in (found if all_techniques else found[:1]))


def incident_badges(labels: Iterable[str]) -> str:
    """One badge per distinct technique across an incident's alerts, in kill-chain order ('' if none)."""
    return "".join(_badge(t) for t in mitre.primaries_for(labels))
