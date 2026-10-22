"""Settings — placeholder until Phase 4."""
from __future__ import annotations

from components.guard import require_principal
from components.ui import page_header, planned_notice

require_principal()

page_header("Settings", "Validated configuration for thresholds, horizons and retention.", eyebrow="Workspace")
planned_notice(
    "Phase 4",
    "This page is not built yet",
    "Settings will be stored in the database, validated, and changed by administrators only, with every change audited."
    " Nothing on this page is simulated in the meantime.",
    [
        "Congestion thresholds and forecast horizons",
        "Link capacity (configured values are labelled as configured)",
        "Alert cooldowns and data retention",
    ],
)
