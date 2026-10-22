"""Overview dashboard — computed only from persisted data."""
from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components.guard import require_principal
from components.theme import COLORS, apply_chart_theme
from components.ui import (
    empty_state, format_bits_rate, format_bytes_rate, format_ratio, format_timestamp,
    kpi_tile, page_header, section_label, step_cards,
)
from services import dashboard_service
from services.authorization import Permission

principal = require_principal()
data = dashboard_service.get_overview(principal)

page_header(
    "Overview",
    "Network health across Smart Shield and PredictNet. Every value shows where it came from: "
    "measured, derived, predicted, configured or unavailable.",
    eyebrow="Network operations",
)

MONITORING_LABELS = {
    "NONE": "Not started", "STOPPED": "Stopped", "STARTING": "Starting",
    "RUNNING": "Running", "STOPPING": "Stopping", "ERROR": "Error",
}
unresolved_total = sum(data.unresolved_alerts.values())
critical_open = data.unresolved_alerts.get("critical", 0) + data.unresolved_alerts.get("high", 0)

if not data.has_any_data:
    empty_state(
        "🛰️",
        "No network data yet",
        "Smart Shield only shows real measurements, model outputs and persisted alerts — nothing on this "
        "dashboard is simulated. It will fill in as telemetry is imported, models are trained and monitoring "
        "sessions run. Here is what happens next:",
    )
    steps = [
        ("Import telemetry", "Upload historical network metrics or a labelled flow dataset (CSV) to "
         "populate traffic rates and throughput.", "Arrives in Phase 2", False),
        ("Train models", "Train the Smart Shield intrusion detector and the PredictNet forecaster, "
         "with evaluation metrics stored in the model registry.", "Arrives in Phases 3–4", False),
        ("Monitor live traffic", "Start passive monitoring on an authorized interface to record measured "
         "throughput, flows and alerts.", "Arrives in Phase 7", False),
    ]
    if principal.has(Permission.MANAGE_USERS):
        steps.insert(0, ("Set up your team", "Invite colleagues to create accounts, then manage their "
                         "roles and review the audit log in Administration.", "Available now", True))
    step_cards(steps)
    st.write("")

# ---------------------------------------------------------------- traffic
section_label("Traffic")
c1, c2, c3, c4 = st.columns(4)
with c1:
    status = data.monitoring
    foot = "No monitoring sessions recorded yet" if status.status == "NONE" else (
        f"{status.interface_name or status.source_type} · since {format_timestamp(status.started_at)}"
    )
    kpi_tile("Monitoring status", MONITORING_LABELS.get(status.status, status.status),
             "measured" if status.status != "NONE" else "unavailable", foot)
with c2:
    v = data.incoming_bps
    kpi_tile("Incoming traffic", format_bytes_rate(v.value), v.provenance,
             f"as of {format_timestamp(v.as_of)}" if v.as_of else "No traffic measurements stored")
with c3:
    v = data.outgoing_bps
    kpi_tile("Outgoing traffic", format_bytes_rate(v.value), v.provenance,
             f"as of {format_timestamp(v.as_of)}" if v.as_of else "No traffic measurements stored")
with c4:
    v = data.throughput_bps
    kpi_tile("Throughput", format_bits_rate(v.value), v.provenance,
             f"as of {format_timestamp(v.as_of)}" if v.as_of else "No throughput measurements stored")

st.write("")
section_label("Security and congestion")
c1, c2, c3, c4 = st.columns(4)
with c1:
    v = data.active_flows
    kpi_tile("Flows (latest session)", None if v.value is None else f"{int(v.value):,}", v.provenance,
             v.note or "No monitoring session recorded")
with c2:
    kpi_tile("Unresolved alerts", f"{unresolved_total:,}", "derived",
             f"{critical_open} high or critical" if unresolved_total else "Counted from stored alerts")
with c3:
    v = data.predicted_utilization
    if v.value is not None:
        horizon = data.forecast_horizon_seconds or 0
        foot = f"{horizon // 60} min horizon · model {data.prediction_model_version}"
    else:
        foot = "No forecasts stored — requires a trained PredictNet model"
    kpi_tile("Forecast utilization", format_ratio(v.value), v.provenance, foot)
with c4:
    risk = data.congestion_risk
    kpi_tile("Congestion risk", risk.title() if risk else None, "predicted" if risk else "unavailable",
             "From the latest stored forecast" if risk else "No congestion forecast available")

if data.utilization.note and data.utilization.value is None and data.counts.get("network_metrics"):
    st.caption(f"ℹ️ {data.utilization.note} Absolute traffic rates are shown instead.")

# ------------------------------------------------------------ throughput
if data.throughput_series:
    st.write("")
    frame = pd.DataFrame(data.throughput_series)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    fig = go.Figure()
    for column, name, color in (
        ("incoming_bytes_per_second", "Incoming (B/s)", COLORS["accent"]),
        ("outgoing_bytes_per_second", "Outgoing (B/s)", "#22D3EE"),
    ):
        series = frame.dropna(subset=[column])
        if not series.empty:
            fig.add_trace(go.Scatter(x=series["timestamp"], y=series[column], name=name, mode="lines",
                                     line=dict(color=color, width=2)))
    fig.update_layout(title="Measured traffic — last 24 hours", yaxis_title="Bytes per second")
    st.plotly_chart(apply_chart_theme(fig), theme=None)
    st.caption("Gaps mean no measurement was recorded; they are not drawn as zero.")

# ------------------------------------------------- recommendations/incidents
if data.latest_recommendation or data.recent_incidents:
    st.write("")
    left, right = st.columns(2)
    with left:
        section_label("Latest bandwidth recommendation")
        rec = data.latest_recommendation
        if rec:
            st.markdown(
                f"**{format_bits_rate(rec['capacity_bps'])}** configured capacity · "
                f"unmet demand **{format_bits_rate(rec['unmet_demand_bps'])}** · status `{rec['status']}`"
            )
            st.caption(rec["rationale"])
        else:
            st.caption("No recommendations stored yet.")
    with right:
        section_label("Recent incidents")
        if data.recent_incidents:
            st.dataframe(
                pd.DataFrame(data.recent_incidents)[["id", "title", "classification", "status", "created_at"]],
                hide_index=True,
            )
        else:
            st.caption("No incidents recorded.")
