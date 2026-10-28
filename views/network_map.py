"""Network Map: hosts and links from stored flows, with risk, severity and incidents on one picture."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from components import network_map, severity
from components.guard import require_principal
from components.theme import apply_chart_theme
from components.ui import (
    SOURCE_LABELS, empty_state, format_bits_rate, format_ratio, format_timestamp, kpi_tile, page_header,
    section_label, source_badge,
)
from services import live_monitor_service, network_map_service
from services.authorization import Permission
from services.network_map_service import OTHERS, MapError, MapFilters

principal = require_principal()
SELECTED_KEY = "network_map_selected_host"

page_header("Network Map", "Hosts and the links between them, built from stored flows. Thickness is throughput, "
            "colour is link risk, rings show the most severe open alert, and hosts in open incidents pulse.",
            eyebrow="Monitor")

sessions = network_map_service.flow_sessions(principal)
if not sessions:
    empty_state("🗺️", "No flows captured yet",
                "The map needs flow records with IP addresses. Run detection on a registered dataset in the Security "
                "Center, import flow records, or start live packet capture. Interface-counter monitoring has no flows.")
    st.stop()

live = live_monitor_service.get_monitor().status
by_id = {s["id"]: s for s in sessions}
f1, f2, f3 = st.columns([2, 1, 1])
session_id = f1.selectbox(
    "Flow source", list(by_id),
    format_func=lambda i: f"#{i} · {SOURCE_LABELS.get(by_id[i]['source_type'], by_id[i]['source_type'])} · "
                          f"{by_id[i]['flow_count']:,} flows · {format_timestamp(by_id[i]['started_at'])}")
window = f2.selectbox("Time window", [5, 15, 60, 360, 1440, 10080], index=2,
                      format_func=lambda m: f"Last {m} min" if m < 60 else f"Last {m // 60} h" if m < 1440
                      else f"Last {m // 1440} day(s)",
                      help="Ends at the newest flow in the source. Datasets are historical, so this is not 'now'.")
top_n = f3.slider("Hosts shown", 5, 80, network_map_service.DEFAULT_TOP_N,
                  help="The busiest hosts are drawn; the rest are merged into one 'Others' node.")
g1, g2, g3 = st.columns([2, 1, 1])
protocols = g1.multiselect("Protocols", network_map_service.session_protocols(principal, session_id),
                           placeholder="All protocols")
min_sev = g2.selectbox("Minimum alert severity", [None, "low", "medium", "high", "critical"],
                       format_func=lambda s: "Any (all hosts)" if s is None else f"{severity.plain(s)} or worse")
only_incidents = g3.toggle("Only hosts with incidents")


@st.fragment(run_every=5 if live.running and live.session_id == session_id else None)
def render_map() -> None:
    status = live_monitor_service.get_monitor().status
    try:
        network = network_map_service.build_map(
            principal, MapFilters(session_id, window, tuple(protocols), min_sev, only_incidents, top_n),
            live_running=status.running, live_mode=status.mode)
    except MapError as exc:
        st.error(str(exc))
        return
    st.markdown(
        f"{source_badge(network.source)} <span style='color:var(--ss-muted);font-size:.8rem'>"
        f"{network.flows_in_window:,} flows · {network.hosts_total:,} hosts · window "
        f"{format_timestamp(network.window_start)} → {format_timestamp(network.window_end)} · capacity "
        f"{format_bits_rate(network.capacity_bps) + ' (configured)' if network.capacity_bps else 'unknown'}</span>",
        unsafe_allow_html=True)
    if not network.nodes:
        st.info("No hosts match these filters in this window.")
        return
    if network.truncated:
        st.warning(f"Only the newest {network_map_service.MAX_FLOWS:,} flows in the window are drawn. "
                   "Narrow the window for a complete picture.")
    selected = st.session_state.get(SELECTED_KEY)
    fig = network_map.figure(network, reduce_motion=st.session_state.get("reduce_motion", False), selected=selected)
    event = st.plotly_chart(apply_chart_theme(fig, height=560), theme=None, on_select="rerun",
                            selection_mode="points", key="network_map_chart",
                            config={"scrollZoom": True, "displaylogo": False})
    points = (event or {}).get("selection", {}).get("points", []) if event else []
    clicked = next((p.get("customdata") for p in points if p.get("customdata")), None)
    if clicked and clicked != OTHERS and clicked != selected:
        st.session_state[SELECTED_KEY] = clicked
        st.rerun()
    # Same choice without the mouse (keyboard users, touch screens, or if the click is missed).
    hosts = [n.id for n in network.nodes if n.id != OTHERS]
    picked = st.selectbox("Or pick a host", [None] + hosts, index=([None] + hosts).index(selected)
                          if selected in hosts else 0, format_func=lambda h: "—" if h is None else h)
    if picked != selected and (picked is not None or selected in hosts):
        st.session_state[SELECTED_KEY] = picked
        st.rerun()
    with st.expander("How to read the map"):
        st.markdown("\n".join(f"- {row}" for row in network_map.legend_rows()))


left, right = st.columns([3, 2])
with left:
    render_map()
with right:
    host = st.session_state.get(SELECTED_KEY)
    section_label("Host details")
    if not host:
        st.caption("Click a host on the map to see its flows, alerts, incidents, forecast and risk score.")
    elif not principal.has(Permission.VIEW_ALERTS):
        st.caption("Your role cannot view host details.")
    else:
        detail = network_map_service.host_detail(principal, session_id, host, window)
        st.markdown(f"### `{host}`")
        if st.button("Clear selection", icon=":material/close:"):
            st.session_state.pop(SELECTED_KEY, None)
            st.rerun()
        c1, c2 = st.columns(2)
        with c1:
            kpi_tile("Host risk score", f"{detail['risk_score']} / 100", "derived",
                     "Formula below")
        with c2:
            kpi_tile("Flows in window", f"{detail['flow_count']:,}", "measured" if detail["flow_count"] else "unavailable",
                     "flagged share " + (format_ratio(detail["flagged_share"]) or "unavailable"))
        st.caption("Risk score = 40 per open critical alert naming the host, 20 per high, 8 per medium, 3 per low, "
                   "+ 30 × flagged share of its flows, + 15 if it is in an open incident (max 100).")
        tabs = st.tabs(["Flows", "Alerts", "Incidents", "Forecast"])
        with tabs[0]:
            if detail["flows"]:
                peers = pd.DataFrame([{"Peer": f["dst_ip"] if f["src_ip"] == host else f["src_ip"],
                                       "Bytes": int(f["byte_count"] or 0), "Flagged": bool(f["intrusion_prediction"])}
                                      for f in detail["flows"]])
                links = peers.groupby("Peer").agg(Flows=("Bytes", "size"), Bytes=("Bytes", "sum"),
                                                  Flagged=("Flagged", "sum")).sort_values("Bytes", ascending=False)
                st.caption("Links (newest 200 flows of this host)")
                st.dataframe(links.reset_index(), hide_index=True, height=160)
                st.dataframe(pd.DataFrame([{
                    "Time": format_timestamp(f["timestamp"]), "Source": f"{f['src_ip']}:{f['src_port'] or ''}",
                    "Destination": f"{f['dst_ip']}:{f['dst_port'] or ''}", "Protocol": f["protocol"],
                    "Bytes": f["byte_count"], "Detection": f["intrusion_prediction"] or "—"}
                    for f in detail["flows"]]), hide_index=True, height=260)
            else:
                st.caption("No flows for this host in the window.")
        with tabs[1]:
            if detail["alerts"]:
                st.dataframe(pd.DataFrame([{
                    "ID": a["id"], "Severity": severity.plain(a["severity"]), "Type": a["alert_type"],
                    "Category": a["category"], "Status": a["status"], "Raised": format_timestamp(a["created_at"])}
                    for a in detail["alerts"]]), hide_index=True)
            else:
                st.caption("No unresolved alerts name this host.")
        with tabs[2]:
            if detail["incidents"]:
                for i in detail["incidents"]:
                    st.markdown(f"- **#{i['id']}** {i['title']} · {i['status']}"
                                + (" · *Not an attack*" if i["classification"] == "performance" else ""))
                st.page_link("views/incident_center.py", label="Open the Incident Center",
                             icon=":material/crisis_alert:")
            else:
                st.caption("Not part of any incident.")
        with tabs[3]:
            f = detail["forecast"]
            if f:
                value = format_ratio(f["predicted_utilization_ratio"]) or format_bits_rate(f["predicted_throughput_bps"])
                st.markdown(f"Link `{detail['interface'] or '(unnamed)'}`: **{value}** predicted "
                            f"{f['forecast_horizon_seconds'] // 60} min after {format_timestamp(f['timestamp'])} · "
                            f"risk **{f['congestion_risk']}** · model `{f['model_version']}` (predicted, not measured).")
            else:
                st.caption("No stored forecast for this host's link. Forecasts are per link, not per host.")
