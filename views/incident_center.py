"""Incident Center — placeholder until Phase 6."""
from __future__ import annotations

from components.guard import require_principal
from components.ui import page_header, planned_notice

require_principal()

page_header("Incident Center", "Correlated security and performance incidents.", eyebrow="Monitor")
planned_notice(
    "Phase 6",
    "This page is not built yet",
    "The correlation engine will group related alerts into incidents and explain its reasoning. Congestion alone is never treated as an attack."
    " Nothing on this page is simulated in the meantime.",
    [
        "Combined incidents with related security and congestion alerts",
        "Time window, measured traffic changes and model outputs",
        "Correlation rationale and suggested investigation steps",
        "Incident status tracking",
    ],
)
