"""Bandwidth Management — placeholder until Phase 5."""
from __future__ import annotations

from components.guard import require_principal
from components.ui import page_header, planned_notice

require_principal()

page_header("Bandwidth Management", "Capacity-aware bandwidth recommendations.", eyebrow="Intelligence")
planned_notice(
    "Phase 5",
    "This page is not built yet",
    "Recommendation mode will use deterministic weighted water-filling that never exceeds configured capacity and reports unmet demand."
    " Nothing on this page is simulated in the meantime.",
    [
        "Traffic classes with minimum, maximum and priority weight",
        "Recommended allocation with rationale and unmet demand",
        "Policy and recommendation history",
        "Optional, admin-only, audited and reversible traffic shaping on Linux (off by default)",
    ],
)
