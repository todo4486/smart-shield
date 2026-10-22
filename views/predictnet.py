"""PredictNet Congestion Center — placeholder until Phase 4."""
from __future__ import annotations

from components.guard import require_principal
from components.ui import page_header, planned_notice

require_principal()

page_header("PredictNet Congestion Center", "Congestion forecasting and risk assessment.", eyebrow="Intelligence")
planned_notice(
    "Phase 4",
    "This page is not built yet",
    "PredictNet will forecast utilization from historical telemetry and compare each model against simple baselines."
    " Nothing on this page is simulated in the meantime.",
    [
        "Predicted vs actual utilization charts with the forecast horizon and last update time",
        "Configurable horizons consistent with the sampling interval",
        "Congestion risk from configurable thresholds (defaults: 60 / 75 / 90%)",
        "MAE, RMSE, R² and per-horizon error",
    ],
)
