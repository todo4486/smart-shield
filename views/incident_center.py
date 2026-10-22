"""Incident Center: correlate security and performance alerts into incidents and investigate them."""
from __future__ import annotations

from html import escape

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components.guard import require_principal
from components.theme import COLORS, SERIES_COLORS, apply_chart_theme
from components.ui import format_bits_rate, format_ratio, format_timestamp, kpi_tile, page_header, section_label
from services import alert_service, incident_correlation_service as correlation
from services.authorization import Permission, PermissionDenied
from services.incident_correlation_service import IncidentError

principal = require_principal()

CLASS_STYLE = {
    "combined": (COLORS["critical"], "Security + congestion"),
    "security": ("#F97316", "Security investigation"),
    "performance": (COLORS["warn"], "Performance warning"),
    "undetermined": (COLORS["muted"], "Undetermined"),
}
TYPE_COLORS = {"security": COLORS["critical"], "anomaly": "#F97316", "congestion": COLORS["warn"],
               "performance": "#A78BFA"}

page_header(
    "Incident Center",
    "Security and performance alerts that happened together are grouped into incidents, each with its time window, "
    "measured traffic changes, model outputs and the reasoning behind the grouping. Congestion is never treated as "
    "an attack by itself.",
    eyebrow="Monitor",
)

open_incidents = correlation.list_incidents(principal, ["open", "investigating"])
unresolved = alert_service.list_alerts(principal, statuses=["open", "acknowledged"])
c1, c2, c3, c4 = st.columns(4)
with c1:
    kpi_tile("Open incidents", f"{len(open_incidents):,}", "derived",
             f"{sum(i['classification'] == 'combined' for i in open_incidents)} combined")
with c2:
    kpi_tile("Unresolved alerts", f"{len(unresolved):,}", "derived", "Security, anomaly, congestion and performance")
with c3:
    kpi_tile("Security alerts", f"{sum(a.alert_type in ('security', 'anomaly') for a in unresolved):,}", "derived",
             "From Smart Shield detections")
with c4:
    kpi_tile("Congestion alerts", f"{sum(a.alert_type in ('congestion', 'performance') for a in unresolved):,}",
             "derived", "From PredictNet forecasts")

incidents_tab, alerts_tab, rules_tab = st.tabs(["Incidents", "All alerts", "How correlation works"])

# ------------------------------------------------------------------ incidents
with incidents_tab:
    if principal.has(Permission.RUN_DETECTION):
        with st.form("correlate_form", border=True):
            c1, c2 = st.columns([2, 1])
            window = c1.slider("Correlation window (minutes)", 1, 240, correlation.DEFAULT_WINDOW_MINUTES,
                               help="Alerts whose network-time windows are within this distance are grouped.")
            run = c2.form_submit_button("Correlate unresolved alerts", type="primary", icon=":material/hub:")
        if run:
            try:
                result = correlation.correlate(principal, window)
            except (IncidentError, PermissionDenied) as exc:
                st.error(str(exc))
            else:
                if not (result.incidents_created or result.incidents_updated):
                    st.info("Every unresolved alert is already part of an incident.")
                else:
                    st.success(f"Linked {result.alerts_linked} alert(s): {len(result.incidents_created)} new "
                               f"incident(s), {len(result.incidents_updated)} updated.")
    statuses = st.multiselect("Status", list(correlation.STATUSES), default=["open", "investigating"])
    incidents = correlation.list_incidents(principal, statuses or None)
    if not incidents:
        st.info("No incidents match. Incidents are created by correlating unresolved alerts. Run detection in the "
                "Security Center or forecasts in the Congestion Center first.")
    else:
        st.dataframe(pd.DataFrame([{
            "ID": i["id"], "Type": CLASS_STYLE.get(i["classification"], ("", i["classification"]))[1],
            "Title": i["title"], "Status": i["status"], "Alerts": i["alert_count"],
            "Window start": format_timestamp(i["window_start"]), "Window end": format_timestamp(i["window_end"]),
        } for i in incidents]), hide_index=True)
        by_id = {i["id"]: i for i in incidents}
        incident_id = st.selectbox("Investigate incident", list(by_id),
                                   format_func=lambda i: f"#{i} · {by_id[i]['title']}")
        incident = correlation.get_incident(principal, incident_id)
        color, label = CLASS_STYLE.get(incident.classification, (COLORS["muted"], incident.classification))
        st.markdown(
            f"<div class='ss-card' style='border-left:4px solid {color}'><h4>#{incident.id} · {escape(label)} · "
            f"{escape(incident.status)}</h4><p>{escape(incident.rationale)}</p></div>",
            unsafe_allow_html=True,
        )
        st.caption(f"Time window (network time): {format_timestamp(incident.window_start)} → "
                   f"{format_timestamp(incident.window_end)}")

        # Timeline: measured throughput around the window with each alert's interval.
        data = correlation.timeline(principal, incident)
        fig = go.Figure()
        metrics = pd.DataFrame(data["metrics"])
        if not metrics.empty and metrics["throughput_bps"].notna().any():
            metrics["timestamp"] = pd.to_datetime(metrics["timestamp"], utc=True, format="ISO8601")
            for n, (interface, part) in enumerate(metrics.groupby(metrics["interface_name"].fillna("(unnamed)"))):
                fig.add_trace(go.Scatter(x=part["timestamp"], y=part["throughput_bps"], mode="lines",
                                         name=f"Measured throughput · {interface} (bit/s, right axis)", yaxis="y2",
                                         line=dict(width=1.5, color=SERIES_COLORS[(n + 1) % len(SERIES_COLORS)]),
                                         connectgaps=False))
        for i, event in enumerate(data["events"]):
            fig.add_trace(go.Scatter(
                x=[event["start"], event["end"]], y=[i, i], mode="lines+markers",
                line=dict(width=8, color=TYPE_COLORS.get(event["type"], COLORS["accent"])),
                name=f"#{event['alert_id']} {event['category']}", showlegend=False,
                hovertemplate=f"Alert #{event['alert_id']} · {escape(event['category'])} · {event['severity']}"
                              f"<br>{event['basis']}<extra></extra>",
            ))
        fig.add_vrect(x0=incident.window_start, x1=incident.window_end, fillcolor=COLORS["accent"], opacity=0.08,
                      line_width=0)
        fig.update_layout(
            title="Incident timeline · UTC (bars = alert intervals, shaded = incident window)",
            yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            yaxis2=dict(overlaying="y", side="right", showgrid=False, tickformat=".2s"),
            legend=dict(orientation="h", x=0, xanchor="left", y=-0.12, yanchor="top"), margin=dict(b=60, r=60),
        )
        st.plotly_chart(apply_chart_theme(fig, height=340), theme=None)
        if metrics.empty:
            st.caption("No stored telemetry covers this window, so only the alert intervals are shown.")

        left, right = st.columns(2)
        with left:
            section_label("Measured traffic changes")
            changes = incident.measured_changes
            st.markdown(f"**Summary:** {changes.get('summary', 'unavailable')}")
            rows = [{"Interface": name, "Trend": c["trend"],
                     "Mean throughput": format_bits_rate(c["mean_throughput_bps"]) or "—",
                     "Previous window": format_bits_rate(c["baseline_mean_throughput_bps"]) or "—",
                     "Change": "—" if c["change"] is None else f"{c['change']:+.0%}",
                     "Peak utilization": format_ratio(c["peak_utilization"]) or "unavailable",
                     "Provenance": ", ".join(c["provenance"])}
                    for name, c in changes.get("interfaces", {}).items()]
            if rows:
                st.dataframe(pd.DataFrame(rows), hide_index=True)
            section_label("Model outputs")
            outputs = incident.model_outputs
            st.markdown("Alert models: " + (", ".join(f"`{m}`" for m in outputs.get("alert_models", [])) or "none"))
            forecasts = outputs.get("forecasts_in_window", [])
            if forecasts:
                st.dataframe(pd.DataFrame([{
                    "Data up to": format_timestamp(f["timestamp"]), "Interface": f["interface_name"] or "—",
                    "Horizon": f"{f['forecast_horizon_seconds'] // 60} min",
                    "Predicted utilization": format_ratio(f["predicted_utilization_ratio"]) or "—",
                    "Risk": f["congestion_risk"], "Model": f["model_version"]} for f in forecasts]), hide_index=True)
            st.caption(outputs.get("note", ""))
        with right:
            section_label("Suggested investigation steps")
            st.markdown("\n".join(f"{n}. {step}" for n, step in enumerate(incident.steps, start=1)))
            section_label("Related alerts")
            st.dataframe(pd.DataFrame([{
                "ID": a.id, "Type": a.alert_type, "Severity": a.severity, "Category": a.category,
                "Status": a.status, "Model": a.model_version or "—"} for a in incident.alerts]), hide_index=True)
            if principal.has(Permission.TRIAGE_ALERTS):
                options = sorted(correlation.TRANSITIONS[incident.status])
                if options:
                    with st.form(f"incident_status_{incident.id}", border=True):
                        target = st.radio("Change status to", options, horizontal=True)
                        note = st.text_area("Note (optional)", max_chars=2000, height=80)
                        if st.form_submit_button("Update incident", type="primary"):
                            try:
                                correlation.change_status(principal, incident.id, target, note)
                            except (IncidentError, PermissionDenied) as exc:
                                st.error(str(exc))
                            else:
                                st.rerun()
                with st.form(f"incident_note_{incident.id}", border=True, clear_on_submit=True):
                    extra = st.text_area("Add investigation note", max_chars=2000, height=80)
                    if st.form_submit_button("Add note"):
                        try:
                            correlation.add_note(principal, incident.id, extra)
                        except (IncidentError, PermissionDenied) as exc:
                            st.error(str(exc))
                        else:
                            st.rerun()
            if incident.notes:
                st.text(incident.notes)

# ----------------------------------------------------------------- all alerts
with alerts_tab:
    f1, f2, f3 = st.columns(3)
    statuses = f1.multiselect("Status ", list(alert_service.STATUSES), default=["open", "acknowledged"])
    types = f2.multiselect("Type", list(alert_service.TYPES), default=list(alert_service.TYPES))
    severities = f3.multiselect("Severity", list(alert_service.SEVERITIES), default=list(alert_service.SEVERITIES))
    alerts = alert_service.list_alerts(principal, statuses=statuses or None, types=types or None,
                                       severities=severities or None)
    if not alerts:
        st.info("No alerts match these filters.")
    else:
        st.dataframe(pd.DataFrame([{
            "ID": a.id, "Type": a.alert_type, "Severity": a.severity, "Category": a.category, "Status": a.status,
            "Source": "Smart Shield" if a.alert_type in ("security", "anomaly") else "PredictNet",
            "Model": a.model_version or "—", "Raised": format_timestamp(a.created_at), "Reason": a.reason}
            for a in alerts]), hide_index=True)
        st.caption("Triage security alerts in the Security Center. Every alert's history is kept.")

# ---------------------------------------------------------------------- rules
with rules_tab:
    st.markdown(f"""
**Event times.** Each alert is placed on the network timeline:
- detections use the time window of the flows they flagged;
- forecasts use the data time they were made from, up to the longest horizon;
- an alert with neither uses its creation time, and the incident says so.

**Grouping.** Alerts whose windows are within the correlation window of each other are grouped. A group that overlaps an
open incident is added to it.

**Classification** (in this order):

| Incident | When | Meaning |
| --- | --- | --- |
| Security + congestion | Smart Shield security/anomaly alerts **and** PredictNet congestion/performance alerts in the same window | Both kinds of evidence are present. The steps help decide whether the attack causes the load |
| Performance warning | Only congestion or performance alerts | **Not an attack.** For example, a large legitimate transfer. A bandwidth recommendation is suggested |
| Security investigation | Only security or anomaly alerts | Security evidence without congestion. An anomaly with normal traffic means "unusual", not "malicious" |

**Measured traffic change** compares stored throughput inside the window with the window of the same length just before
it: a sharp rise is ≥ {correlation.SHARP_RISE:.0%}, and normal is within ±{correlation.NORMAL_BAND:.0%}. Without stored
telemetry it is *unavailable*.

**Limitation.** Smart Shield alerts from datasets do not identify a network interface, so they are linked to congestion by
time only.
""")
