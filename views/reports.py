"""Reports — placeholder until Phase 8."""
from __future__ import annotations

from components.guard import require_principal
from components.ui import page_header, planned_notice

require_principal()

page_header("Reports", "Reports built from persisted data.", eyebrow="Workspace")
planned_notice(
    "Phase 8",
    "This page is not built yet",
    "Reports will summarise alerts, forecasts, model performance and policy history using only stored data."
    " Nothing on this page is simulated in the meantime.",
    [
        "Security and congestion summaries for a chosen period",
        "Model version and evaluation traceability",
        "Export for project evaluation",
    ],
)
