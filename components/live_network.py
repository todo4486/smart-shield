"""The live NOC panel: link totals and per-host bandwidth. A fragment, so only this panel refreshes."""
from __future__ import annotations

from html import escape

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components.theme import COLORS, apply_chart_theme
from components.ui import format_bits_rate, format_ratio, format_timestamp, kpi_tile, section_label, source_badge
from services import live_monitor_service, live_network_service, simulation_service
from services.authorization import Principal

REFRESH_SECONDS = 2
STATUS_LABELS = {"normal": "● Normal", "suspicious": "▲ Suspicious"}


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
    c1, c2, c3 = st.columns(3)
    with c1:
        kpi_tile("Incoming traffic", format_bits_rate(live.incoming_bps), measured, origin)
    with c2:
        kpi_tile("Outgoing traffic", format_bits_rate(live.outgoing_bps), measured, origin)
    with c3:
        kpi_tile("Link capacity", format_bits_rate(live.capacity_bps), "configured" if live.capacity_bps else "unavailable",
                 "set when the capture starts")
    c1, c2, c3 = st.columns(3)
    with c1:
        kpi_tile("Available bandwidth", format_bits_rate(live.available_bps), known, "capacity minus traffic")
    with c2:
        kpi_tile("Utilization", format_ratio(live.utilization), known, "of the configured capacity")
    with c3:
        hosts = len(live.hosts) if live.mode == "packets" and live.as_of else None
        kpi_tile("Active hosts", None if hosts is None else f"{hosts:,}", measured if hosts is not None else "unavailable",
                 f"{live_network_service.HOST_WINDOW_SECONDS} s window"
                 + (f" · {live.active_connections:,} open connections" if live.active_connections is not None else ""))

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
        fig.update_layout(title=f"Link traffic ({'simulated' if simulated else 'measured'}, bit/s)", yaxis=dict(tickformat=".2s", rangemode="tozero"),
                          legend=dict(orientation="h", x=0, y=-0.2))
        st.plotly_chart(apply_chart_theme(fig, height=280), theme=None, key="live_network_history")

    section_label("Hosts")
    if not live.hosts:
        st.caption("No per-host data." if live.mode != "packets" else "No packets seen in the last few seconds.")
        return
    st.dataframe(pd.DataFrame([{
        "Status": STATUS_LABELS.get(h.status, h.status), "Host": h.host, "Where": h.kind,
        "Received": format_bits_rate(h.received_bps), "Sent": format_bits_rate(h.sent_bps),
        "Packets/s": round(h.sent_pps + h.received_pps, 1), "Connections": h.active_connections,
        "Traffic": h.traffic or "—", "Model flagged": f"{h.flagged_flows} · {h.top_category}" if h.flagged_flows else "—",
    } for h in live.hosts]), hide_index=True, key="live_network_hosts")
    rates_note = ("Rates are calculated from synthetic traffic." if simulated else "Rates are measured from captured packets.")
    st.caption(f"{rates_note} Traffic is the most common well-known destination port of "
               "the host's finished flows, not proof of the application. Suspicious means the models flagged a flow "
               "from this source in the last 5 minutes; it is a model verdict, not proof of an attack.")


def render(principal: Principal) -> None:
    running = live_monitor_service.get_monitor().status.running or simulation_service.status_copy().running
    st.fragment(_panel, run_every=REFRESH_SECONDS if running else None)(principal)
