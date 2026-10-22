"""Smart Shield Security Center — placeholder until Phase 3."""
from __future__ import annotations

from components.guard import require_principal
from components.ui import page_header, planned_notice

require_principal()

page_header("Smart Shield Security Center", "Intrusion detection, anomaly detection and alert triage.", eyebrow="Intelligence")
planned_notice(
    "Phase 3",
    "This page is not built yet",
    "The security center will show alerts produced by real inference with a registered model, never simulated detections."
    " Nothing on this page is simulated in the meantime.",
    [
        "Binary benign-vs-attack classification (Random Forest) on CIC-IDS2017-style flows",
        "Isolation Forest anomaly scores fit on benign training data",
        "Alert severity, acknowledgement, resolution and investigation notes",
        "Potential DDoS indicators with the evidence behind them",
    ],
)
