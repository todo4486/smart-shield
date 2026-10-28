"""Incident Center: correlate security and performance alerts into incidents and investigate them."""
from __future__ import annotations

from html import escape

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import mitre, severity
from components.guard import require_principal
from components.theme import COLORS, MONO_FONT, SERIES_COLORS, apply_chart_theme, palette
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
NEW_GROUPS_KEY = "incident_center_new_groups"


def _lane_chart(lanes: dict, incidents: list, new_ids: set, selected_id) -> go.Figure:
    """Security and congestion swimlanes on one network-time axis, with incident brackets."""
    fig = go.Figure()
    lane_y = {"security": 1, "congestion": 0}
    for lane, items in lanes.items():
        for level in severity.LEVELS:
            part = [a for a in items if severity.normalize(a["severity"]) == level]
            if not part:
                continue
            xs, ys, texts = [], [], []
            for a in part:
                xs += [a["start"], a["end"], None]
                ys += [lane_y[lane]] * 2 + [None]
                group = f"incident #{a['incident_id']}" if a["incident_id"] else "not grouped yet"
                texts += [f"Alert #{a['alert_id']} · {a['category']} · {severity.plain(a['severity'])}<br>"
                          f"{a['type']} · {group} · {a['basis']}"] * 2 + [None]
            fig.add_trace(go.Scatter(
                x=xs, y=ys, mode="lines+markers", line=dict(width=10, color=severity.COLORS[level]),
                marker=dict(size=9, symbol={"info": "circle", "low": "circle", "medium": "triangle-up",
                                            "high": "diamond", "critical": "x"}[level], color=severity.COLORS[level]),
                name=severity.plain(level), legendgroup=level, showlegend=lane == "security" or not lanes["security"],
                text=texts, hovertemplate="%{text}<extra></extra>", connectgaps=False))
    for incident in incidents:
        is_new, is_selected = incident["id"] in new_ids, incident["id"] == selected_id
        color = COLORS["cyan"] if is_new else (COLORS["accent"] if is_selected else palette()["muted"])
        fig.add_shape(type="rect", x0=incident["window_start"], x1=incident["window_end"], y0=-0.45, y1=1.45,
                      line=dict(color=color, width=3 if (is_new or is_selected) else 1.2,
                                dash="solid" if (is_new or is_selected) else "dot"),
                      fillcolor=color, opacity=0.14 if is_new else 0.07, layer="below")
        label = f"Incident #{incident['id']}" + (" · NEW" if is_new else "")
        if incident["classification"] == "performance":
            label += " · Not an attack"
        fig.add_annotation(x=incident["window_start"], y=1.62, text=label, showarrow=False, xanchor="left",
                           font=dict(size=11, color=color, family=MONO_FONT))
    fig.update_layout(
        title="Security vs congestion alerts · network time (UTC) · brackets = incidents",
        yaxis=dict(tickvals=[0, 1], ticktext=["Congestion", "Security"], range=[-0.8, 1.9], showgrid=False),
        hovermode="closest", legend=dict(orientation="h", x=0, xanchor="left", y=-0.18, yanchor="top"),
        margin=dict(b=70, l=96))
    return fig


def _triage(incident) -> None:
    if not principal.has(Permission.TRIAGE_ALERTS):
        st.button("Acknowledge", disabled=True, help="Your role cannot triage incidents.")
        return
    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Acknowledge", icon=":material/visibility:", width="stretch",
                     disabled=incident.status != "open",
                     help="Picks the incident up: open → investigating." if incident.status == "open"
                     else "Only open incidents can be acknowledged."):
            _run(lambda: correlation.acknowledge(principal, incident.id))
    with c2:
        users = correlation.assignable_users(principal)
        by_uid = {None: "Unassigned", **{u["id"]: f"{u['name']} ({u['email']})" for u in users}}
        options = list(by_uid)
        current = incident.assigned_to if incident.assigned_to in by_uid else None
        choice = st.selectbox("Assign to", options, index=options.index(current), format_func=lambda u: by_uid[u],
                              key=f"assign_{incident.id}", label_visibility="collapsed",
                              disabled=incident.status == "closed")
        if choice != current:
            _run(lambda: correlation.assign(principal, incident.id, choice))
    with c3:
        resolvable = "resolved" in correlation.TRANSITIONS[incident.status]
        if st.button("Resolve", icon=":material/task_alt:", type="primary", width="stretch", disabled=not resolvable,
                     help="Marks the incident resolved." if resolvable else "Already resolved or closed."):
            _run(lambda: correlation.change_status(principal, incident.id, "resolved"))
    others = sorted(correlation.TRANSITIONS[incident.status] - {"investigating", "resolved"})
    if others:
        with st.popover("More status changes"):
            for target in others:
                if st.button(f"Move to {target}", key=f"status_{incident.id}_{target}"):
                    _run(lambda t=target: correlation.change_status(principal, incident.id, t))


def _run(action) -> None:
    try:
        action()
    except (IncidentError, PermissionDenied) as exc:
        st.error(str(exc))
    else:
        st.rerun()


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
                st.session_state[NEW_GROUPS_KEY] = set(result.incidents_created) | set(result.incidents_updated)
                if not (result.incidents_created or result.incidents_updated):
                    st.info("Every unresolved alert is already part of an incident.")
                else:
                    st.success(f"Linked {result.alerts_linked} alert(s): {len(result.incidents_created)} new "
                               f"incident(s), {len(result.incidents_updated)} updated. They are highlighted below.")
    statuses = st.multiselect("Status", list(correlation.STATUSES), default=["open", "investigating"])
    incidents = correlation.list_incidents(principal, statuses or None)

    # Permalink: ?incident=42 selects that incident (still behind sign-in).
    linked = st.query_params.get("incident")
    linked_id = int(linked) if linked and linked.isdigit() else None
    if linked_id is not None and all(i["id"] != linked_id for i in incidents):
        try:
            extra = correlation.get_incident(principal, linked_id)
        except IncidentError:
            st.warning(f"Incident #{linked_id} from the link does not exist.")
        else:
            incidents = [{"id": extra.id, "title": extra.title, "classification": extra.classification,
                          "status": extra.status, "alert_count": len(extra.alerts),
                          "window_start": extra.window_start, "window_end": extra.window_end,
                          "assigned_email": extra.assigned_email,
                          "top_severity": severity.highest(a.severity for a in extra.alerts)}] + incidents

    lanes = correlation.swimlanes(principal)
    if lanes["range"] is None:
        st.info("No alerts yet. Run detection in the Security Center or forecasts in PredictNet, then correlate.")
    else:
        new_ids = st.session_state.get(NEW_GROUPS_KEY, set())
        st.plotly_chart(apply_chart_theme(_lane_chart(lanes["lanes"], lanes["incidents"], new_ids, linked_id),
                                          height=330), theme=None, key="incident_lanes")
        st.caption("Each bar is one alert's interval in network time; brackets show which alerts the correlation "
                   "engine grouped. Congestion-only incidents are labelled **Not an attack**.")

    if not incidents:
        st.info("No incidents match. Incidents are created by correlating unresolved alerts.")
    else:
        by_id = {i["id"]: i for i in incidents}
        st.dataframe(pd.DataFrame([{
            "ID": i["id"], "Severity": severity.plain(i.get("top_severity")),
            "Type": CLASS_STYLE.get(i["classification"], ("", i["classification"]))[1]
            + (" · Not an attack" if i["classification"] == "performance" else ""),
            "Title": i["title"], "Status": i["status"], "Assigned": i.get("assigned_email") or "—",
            "Source": "DATASET REPLAY" if i.get("is_replay") else "Captured / imported",
            "Alerts": i["alert_count"], "Window start": format_timestamp(i["window_start"]),
        } for i in incidents]), hide_index=True)
        ids = list(by_id)
        incident_id = st.selectbox("Investigate incident", ids, index=ids.index(linked_id) if linked_id in by_id else 0,
                                   format_func=lambda i: f"#{i} · {by_id[i]['title']}")
        if st.query_params.get("incident") != str(incident_id):
            st.query_params["incident"] = str(incident_id)
        incident = correlation.get_incident(principal, incident_id)
        color, label = CLASS_STYLE.get(incident.classification, (COLORS["muted"], incident.classification))
        top = severity.highest(a.severity for a in incident.alerts)
        strength = correlation.evidence_strength(incident.alerts)
        badges = severity.badge(top) if top else ""
        if incident.not_an_attack:
            badges += " <span class='ss-src ss-src-counters'>NOT AN ATTACK</span>"
        if incident.is_replay:
            badges += " <span class='ss-src ss-src-replay'>DATASET REPLAY</span>"
        attack_labels = [a.category for a in incident.alerts if a.alert_type == "security"]
        techniques = mitre.incident_badges(attack_labels)
        st.markdown(
            f"<div class='ss-card' style='border-left:4px solid {color}'><h4>#{incident.id} · {escape(label)} · "
            f"{escape(incident.status)} {badges}</h4><p>{escape(incident.rationale)}</p>"
            + (f"<div style='margin-top:.5rem'>{techniques}</div>" if techniques else "") + "</div>",
            unsafe_allow_html=True,
        )
        st.caption(f"Time window (network time): {format_timestamp(incident.window_start)} → "
                   f"{format_timestamp(incident.window_end)} · Share this incident: copy the page address "
                   f"(…?incident={incident.id}); it opens after sign-in.")

        c1, c2, c3, c4 = st.columns(4)
        security_alerts = [a for a in incident.alerts if a.alert_type in correlation.SECURITY_TYPES]
        with c1:
            kpi_tile("Member alerts", f"{len(incident.alerts):,}", "derived",
                     f"{len(security_alerts)} security · {len(incident.alerts) - len(security_alerts)} congestion")
        with c2:
            kpi_tile("Highest severity", severity.plain(top) if top else None, "derived" if top else "unavailable",
                     "Most severe member alert")
        with c3:
            kpi_tile("Evidence strength", strength["level"].title(), "derived", "Rule-based, not a probability")
        with c4:
            hosts = correlation.affected_hosts(incident.alerts)
            kpi_tile("Affected hosts", f"{len(hosts):,}" if hosts else None, "measured" if hosts else "unavailable",
                     ", ".join(hosts[:3]) if hosts else "Alerts name no hosts")
        st.caption(" ".join(strength["reasons"]))

        section_label("Triage")
        st.caption(f"Assigned to: **{incident.assigned_email or 'nobody'}**. Acknowledge → assign → resolve; "
                   "every step is recorded in the history and the audit log.")
        _triage(incident)

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
            section_label("Affected hosts and links")
            interfaces = sorted({str(a.evidence.get("interface")) for a in incident.alerts
                                 if a.evidence.get("interface") not in (None, "(all)")})
            st.markdown("**Hosts:** " + (", ".join(f"`{h}`" for h in hosts[:12]) or "none named in the evidence"))
            st.markdown("**Links:** " + (", ".join(f"`{i}`" for i in interfaces) or "none named in the evidence"))
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
            section_label("Member alerts")
            st.dataframe(pd.DataFrame([{
                "ID": a.id, "Type": a.alert_type, "Severity": severity.plain(a.severity), "Category": a.category,
                "Status": a.status, "Model": a.model_version or "—"} for a in incident.alerts]), hide_index=True)
            section_label("Analyst notes and history")
            history = correlation.events(principal, incident.id)
            if not history:
                st.caption("No triage activity yet.")
            for event in history:
                who = event["user_email"] or "system"
                when = format_timestamp(event["created_at"])
                if event["event_type"] == "note":
                    with st.chat_message("user", avatar=":material/person:"):
                        st.markdown(f"**{who}** · {when}")
                        st.text(event["note"])
                elif event["event_type"] == "assignment":
                    st.caption(f"{when} · {who} assigned it to **{event['assigned_email'] or 'nobody'}**")
                else:
                    st.caption(f"{when} · {who} moved it {event['from_status']} → **{event['to_status']}**"
                               + (f": {event['note']}" if event["note"] else ""))
            if principal.has(Permission.TRIAGE_ALERTS):
                with st.form(f"incident_note_{incident.id}", border=True, clear_on_submit=True):
                    extra = st.text_area("Add an analyst note", max_chars=2000, height=80)
                    if st.form_submit_button("Add note", icon=":material/edit_note:"):
                        _run(lambda: correlation.add_note(principal, incident.id, extra))
            if incident.notes and not any(e["event_type"] == "note" for e in history):
                st.caption("Notes recorded before the history was added:")
                st.text(incident.notes)

# ----------------------------------------------------------------- all alerts
with alerts_tab:
    f1, f2, f3 = st.columns(3)
    statuses = f1.multiselect("Status ", list(alert_service.STATUSES), default=["open", "acknowledged"])
    types = f2.multiselect("Type", list(alert_service.TYPES), default=list(alert_service.TYPES))
    severities = f3.multiselect("Severity", list(alert_service.SEVERITIES), default=list(alert_service.SEVERITIES),
                                 format_func=severity.plain)
    alerts = alert_service.list_alerts(principal, statuses=statuses or None, types=types or None,
                                       severities=severities or None)
    if not alerts:
        st.info("No alerts match these filters.")
    else:
        st.dataframe(pd.DataFrame([{
            "ID": a.id, "Type": a.alert_type, "Severity": severity.plain(a.severity), "Category": a.category, "Status": a.status,
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
