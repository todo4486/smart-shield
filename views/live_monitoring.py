"""Live Monitoring — placeholder until Phase 7."""
from __future__ import annotations

from components.guard import require_principal
from components.ui import page_header, planned_notice

require_principal()

page_header("Live Monitoring", "Passive capture on authorized interfaces with measured interface counters.", eyebrow="Monitor")
planned_notice(
    "Phase 7",
    "This page is not built yet",
    "Live monitoring will run a passive capture worker in a separate process, so the dashboard stays responsive and reruns never start duplicate workers."
    " Nothing on this page is simulated in the meantime.",
    [
        "Interface selection and start/stop controls (admin-only)",
        "Measured throughput and packet rates from psutil counters",
        "5-tuple flow extraction with documented idle and active timeouts",
        "Feature-compatibility checks before any model is applied to live flows",
        "Clear explanations when capture is unsupported or lacks permission",
    ],
)
