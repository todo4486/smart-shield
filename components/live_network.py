"""The live NOC panel: link totals and per-host bandwidth. A fragment, so only this panel refreshes."""
from __future__ import annotations

from html import escape

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import mitigation_panel
from components.theme import COLORS, apply_chart_theme
from components.ui import format_bits_rate, format_ratio, format_timestamp, kpi_tile, section_label, source_badge
from services import live_monitor_service, live_network_service, mitigation_service, settings_service, simulation_service
from services.authorization import Permission, Principal
from services.host_telemetry import OTHER

REFRESH_SECONDS = 2
STATUS_LABELS = {"normal": "● Normal", "suspicious": "▲ Suspicious", "restricted": "■ Restricted"}
# Bottom to top of the stack. Blue and cyan are ordinary traffic; amber and red carry the same meaning as everywhere else.
ALLOCATION_SERIES = (("critical", "Critical applications", COLORS["accent"]), ("normal", "Normal users", COLORS["cyan"]),
                     ("suspicious", "Suspicious hosts", COLORS["warn"]), ("restricted", "Restricted traffic", COLORS["critical"]))
AVAILABLE_COLOR = "#64748B"
ACTION_LABELS = {"rate_limit": "Limit its bandwidth", "block": "Block it", "isolate": "Isolate it"}


def _allocation_chart(principal: Principal, live, simulated: bool) -> None:
    settings = settings_service.get_mitigation_settings()
    if not settings.adaptive_enabled:
        st.caption("Adaptive allocation is off, so no allocation is being calculated. Turn it on in Allocation controls.")
        return
    history = mitigation_service.allocation_history(principal, live.session_id)
    if not history:
        st.caption("No allocation yet: it needs a configured link capacity, and packet capture with a compatible model. "
                   "Shares of an unknown capacity are never guessed." if not simulated else "No allocation has been calculated yet.")
        return
    times = pd.to_datetime([h["timestamp"] for h in history], utc=True, format="ISO8601")
    fig = go.Figure()
    for name, label, color in ALLOCATION_SERIES:
        fig.add_trace(go.Scatter(x=times, y=[h["classes"][name]["allocated_bps"] for h in history], name=label, mode="lines",
                                 stackgroup="allocation", line=dict(width=1.5, color=color),
                                 hovertemplate=label + ": %{y:.3s}bit/s<extra></extra>"))
    fig.add_trace(go.Scatter(x=times, y=[h["available_bps"] for h in history], name="Available", mode="lines",
                             stackgroup="allocation", line=dict(width=1, color=AVAILABLE_COLOR),
                             hovertemplate="Available: %{y:.3s}bit/s<extra></extra>"))
    fig.update_layout(title=f"Bandwidth allocation ({'simulated' if simulated else 'calculated from measured demand'}, bit/s)",
                      xaxis=dict(tickformat="%H:%M:%S"), yaxis=dict(tickformat=".2s", rangemode="tozero"), hovermode="x unified",
                      legend=dict(orientation="h", x=0, y=-0.14, yanchor="top", traceorder="normal"), margin=dict(b=70))
    st.plotly_chart(apply_chart_theme(fig, height=300), theme=None, key="live_allocation_history")
    if not history[-1]["enforced"]:
        st.caption("This is the calculated plan. No limit is in force, so the link itself is still a plain shared queue.")


def _allocated_cell(row) -> str:
    """A plan only covers senders, so a host with no share in an existing plan is only receiving."""
    if row["allocated_bps"] is not None:
        return format_bits_rate(row["allocated_bps"])
    return "Only receiving" if row["has_allocation"] else "Unavailable"


def _status_cell(row) -> str:
    return STATUS_LABELS.get(row["status"], row["status"]) + (" · dry run" if row["dry_run"] else "")


def _manage_host(principal: Principal, session_id: int, rows, interface_note: str) -> None:
    """One host at a time, chosen by address, so the choice survives the table re-sorting itself at each refresh."""
    manageable = [r for r in rows if r["host"] != OTHER]
    if not manageable:
        return
    by_host = {r["host"]: r for r in manageable}
    section_label("Manage a host")
    host = st.selectbox("Host", list(by_host), key="manage_host",
                        format_func=lambda h: f"{h} · {by_host[h]['action']} · {STATUS_LABELS.get(by_host[h]['status'], '')}")
    row = by_host[host]
    if row["incident_id"]:
        st.page_link("views/incident_center.py", label=f"Investigate in incident #{row['incident_id']}",
                     icon=":material/crisis_alert:", query_params={"incident": str(row["incident_id"])})
    if row["active_id"]:
        st.caption(f"Action #{row['active_id']} is active on this host. Roll it back before choosing another.")
        if principal.has(Permission.APPLY_TRAFFIC_POLICY) and st.button("Roll back", key=f"manage_rollback_{row['active_id']}",
                                                                        icon=":material/undo:"):
            mitigation_panel.attempt(mitigation_service.rollback, principal, row["active_id"], reason="Rolled back from the host table")
        return
    if not principal.has(Permission.APPLY_TRAFFIC_POLICY):
        st.caption("Only an administrator can act on a host.")
        return
    with st.form("manage_host_form"):
        c1, c2, c3 = st.columns(3)
        action = c1.selectbox("Action", list(ACTION_LABELS), format_func=ACTION_LABELS.get)
        limit = c2.number_input("Limit (Mbit/s)", min_value=0.008, value=5.0, step=1.0, help="Only used when limiting.")
        minutes = c3.number_input("For how long (minutes)", min_value=1, max_value=1440, value=15)
        reason = st.text_input("Reason", key="manage_reason", placeholder="Why, at least 5 characters")
        confirm = st.text_input(f"To block or isolate, type {host} to confirm", placeholder=host)
        st.caption(interface_note)
        if st.form_submit_button("Apply", type="primary"):
            mitigation_panel.attempt(
                mitigation_service.request_action, principal, session_id, action, target=host,
                limit_bps=limit * 1e6 if action == "rate_limit" else None, duration_minutes=minutes, reason=reason,
                confirm_target=confirm)


def _panel(principal: Principal) -> None:
    status = live_monitor_service.get_monitor().status
    simulation = simulation_service.status_copy()
    live = live_network_service.snapshot(principal, live_running=status.running, live_session_id=status.session_id,
                                         live_active_flows=status.active_flows,
                                         simulation_session_id=simulation.session_id if simulation.running else None)
    simulated = live.provenance == "simulated"
    state = (("Simulating now" if live.running else "Not simulating") if simulated else
             ("Capturing now" if live.running else "Not capturing"))
    where = f" on {live.interface}" if live.interface else ""
    as_of = f" · last sample {format_timestamp(live.as_of)}" if live.as_of else ""
    st.markdown(f"{source_badge(live.source)} <span style='color:var(--ss-muted);font-size:.8rem'>"
                f"{escape(state + where + as_of)}</span>", unsafe_allow_html=True)
    for note in live.notes:
        st.caption(note)
    if live.session_id is None:
        st.page_link("views/live_monitoring.py", label="Open Live Monitoring", icon=":material/monitor_heart:")
        return

    measured = live.provenance if live.as_of else "unavailable"
    known = ("simulated" if simulated else "derived") if live.capacity_bps else "unavailable"
    origin = "calculated by the link model" if simulated else "interface counters"
    rows = mitigation_service.host_rows(principal, live.session_id, live.hosts)
    allocation = mitigation_service.latest_allocation(principal, live.session_id)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kpi_tile("Link capacity", format_bits_rate(live.capacity_bps), "configured" if live.capacity_bps else "unavailable",
                 "set when the capture starts")
    with c2:
        kpi_tile("Incoming traffic", format_bits_rate(live.incoming_bps), measured, origin)
    with c3:
        kpi_tile("Outgoing traffic", format_bits_rate(live.outgoing_bps), measured, origin)
    with c4:
        kpi_tile("Utilization", format_ratio(live.utilization), known, "of the configured capacity")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kpi_tile("Available bandwidth", format_bits_rate(live.available_bps), known, "capacity minus traffic")
    with c2:
        kpi_tile("Allocated bandwidth", format_bits_rate(allocation["total_allocated_bps"]) if allocation else None,
                 "derived" if allocation else "unavailable", "the engine's latest plan")
    with c3:
        hosts = len(live.hosts) if live.mode == "packets" and live.as_of else None
        kpi_tile("Active hosts", None if hosts is None else f"{hosts:,}", measured if hosts is not None else "unavailable",
                 f"{live_network_service.HOST_WINDOW_SECONDS} s window"
                 + (f" · {live.active_connections:,} open connections" if live.active_connections is not None else ""))
    with c4:
        kpi_tile("Restricted hosts", None if hosts is None else f"{sum(r['status'] == 'restricted' for r in rows):,}",
                 "derived" if hosts is not None else "unavailable", "with a limit in force")

    history = pd.DataFrame(live.history)
    if not history.empty:
        history["timestamp"] = pd.to_datetime(history["timestamp"], utc=True, format="ISO8601")
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=history["timestamp"], y=history["incoming_bps"], name="Incoming", mode="lines",
                                 line=dict(color=COLORS["accent"], width=2)))
        fig.add_trace(go.Scatter(x=history["timestamp"], y=history["outgoing_bps"], name="Outgoing", mode="lines",
                                 line=dict(color=COLORS["cyan"], width=2)))
        if live.capacity_bps:
            fig.add_hline(y=live.capacity_bps, line_dash="dash", line_color=COLORS["warn"],
                          annotation_text="Configured capacity")
        fig.update_layout(title=f"Link traffic ({'simulated' if simulated else 'measured'}, bit/s)", xaxis=dict(tickformat="%H:%M:%S"),
                          yaxis=dict(tickformat=".2s", rangemode="tozero"),
                          legend=dict(orientation="h", x=0, y=-0.14, yanchor="top"), margin=dict(b=60))
        st.plotly_chart(apply_chart_theme(fig, height=280), theme=None, key="live_network_history")
    _allocation_chart(principal, live, simulated)

    section_label("Hosts")
    if not live.hosts:
        st.caption("No per-host data." if live.mode != "packets" else "No packets seen in the last few seconds.")
        return
    st.dataframe(pd.DataFrame([{
        "Status": _status_cell(r), "Host": r["kind"], "IP address": r["host"],
        "Current usage": format_bits_rate(r["usage_bps"]), "Allocated": _allocated_cell(r),
        "Received": format_bits_rate(r["received_bps"]), "Sent": format_bits_rate(r["sent_bps"]),
        "Connections": r["active_connections"], "Traffic": r["traffic"] or "—",
        "Model flagged": f"{r['flagged_flows']} · {r['top_category']}" if r["flagged_flows"] else "—", "Action": r["action"],
    } for r in rows]), hide_index=True, key="live_network_hosts")
    rates_note = ("Rates are calculated from synthetic traffic." if simulated else "Rates are measured from captured packets.")
    st.caption(f"{rates_note} Traffic is the most common well-known destination port of "
               "the host's finished flows, not proof of the application. Suspicious means the models flagged a flow "
               "from this source in the last 5 minutes; it is a model verdict, not proof of an attack. Allocated is the "
               "engine's plan for what the host sends.")
    if live.running:
        if simulated:
            note = "This acts on the simulated link only."
        elif mitigation_service.enforcement_status(principal).enforcing:
            note = f"This changes real traffic on {live.interface}."
        else:
            note = "Dry run: this is recorded with its commands, but nothing on the network changes."
        _manage_host(principal, live.session_id, rows, note)


def render(principal: Principal) -> None:
    running = live_monitor_service.get_monitor().status.running or simulation_service.status_copy().running
    st.fragment(_panel, run_every=REFRESH_SECONDS if running else None)(principal)
