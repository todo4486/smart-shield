"""Live capture panel on the Live Monitoring page: capability, start/stop, live status and rates."""
from __future__ import annotations

import streamlit as st

from components import charts
from components.ui import (
    format_bits_rate, format_bytes_rate, format_ratio, format_timestamp, kpi_tile, section_label, source_badge,
)
from services import data_source, interface_counters, live_monitor_service, settings_service, telemetry_view_service
from services.authorization import Permission, PermissionDenied, Principal
from services.live_monitor_service import MODES, MonitorError

STATE_PROVENANCE = {"RUNNING": "measured", "STARTING": "measured", "STOPPING": "measured", "STOPPED": "measured",
                    "ERROR": "measured"}


@st.cache_resource(show_spinner=False)
def monitor() -> live_monitor_service.LiveMonitor:
    """One monitor per server process: reruns and other browser tabs share it, so no duplicate workers."""
    return live_monitor_service.get_monitor()


def render(principal: Principal) -> None:
    live = monitor()
    capability = live_monitor_service.capture_capability()
    settings = settings_service.get_monitoring_settings()
    present = {i["name"]: i for i in interface_counters.list_interfaces()}
    allowed = [name for name in settings.allowed_interfaces if name in present]

    section_label("Live capture (passive)")

    @st.fragment(run_every=3 if live.status.running else None)
    def status_panel() -> None:
        status = live.status
        source = data_source.classify("live_capture" if status.session_id else None, live_running=status.running,
                                      live_mode=status.mode)
        st.markdown(source_badge(source), unsafe_allow_html=True)
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            kpi_tile("Capture state", status.state.title() if status.session_id else "Not started", "measured" if
                     status.session_id else "unavailable",
                     f"{status.interface} · {status.mode}" if status.session_id else "No live capture in this run")
        with c2:
            kpi_tile("Counter samples", f"{status.samples:,}", "measured" if status.samples else "unavailable",
                     f"since {format_timestamp(status.started_at)}" if status.started_at else "—")
        with c3:
            kpi_tile("Flows stored", f"{status.flows_stored:,}", "measured" if status.flows_stored else "unavailable",
                     f"{status.active_flows or 0} active · {status.flows_not_stored:,} over the storage limit"
                     if status.mode == "packets" else "Packet capture not enabled")
        with c4:
            kpi_tile("Flagged flows", f"{status.flagged:,}" if status.detection.get("enabled") else None,
                     "predicted" if status.detection.get("enabled") else "unavailable",
                     status.detection.get("model_version") or "Live detection off")
        if status.last_error:
            st.error(status.last_error)
        if status.detection.get("reason") and status.mode == "packets":
            (st.success if status.detection.get("enabled") else st.warning)(status.detection["reason"])
        if status.dropped_packets:
            st.warning(f"{status.dropped_packets:,} captured packets were discarded because flow processing fell "
                       "behind, so some stored flows are incomplete. Capture on a quieter interface or use "
                       "interface-counter mode.")
        if status.dropped_messages:
            st.warning(f"{status.dropped_messages:,} worker messages were dropped because the app fell behind "
                       "(bounded queue). Increase the sampling interval if this keeps happening.")
        if status.session_id and status.samples:
            # Only the newest rows: this fragment reruns every 3 s, so never load the whole capture.
            recent = telemetry_view_service.recent_metrics(principal, status.session_id, limit=200)
            if not recent.empty:
                latest = recent.iloc[-1]
                na = "unavailable"
                utilization = format_ratio(latest["utilization_ratio"])
                latency = latest["latency_ms"]
                st.caption(f"Latest measured: in {format_bytes_rate(latest['incoming_bytes_per_second']) or na} · out "
                           f"{format_bytes_rate(latest['outgoing_bytes_per_second']) or na} · throughput "
                           f"{format_bits_rate(latest['throughput_bps']) or na} (derived) · utilization "
                           + (f"{utilization} (derived)" if utilization else "unavailable (no configured capacity)")
                           + " · latency " + ("unavailable (no target configured)" if latency is None or latency != latency
                                              else f"{latency:.1f} ms"))
                charts.time_series(recent, [("incoming_bytes_per_second", "Incoming"),
                                            ("outgoing_bytes_per_second", "Outgoing")],
                                   title=f"Live traffic on {status.interface}", y_title="Bytes per second", height=280)

    status_panel()

    with st.expander("What this server can capture", icon=":material/policy:", expanded=not capability.packets):
        st.markdown(f"- **Interface counters:** {'available' if capability.counters else 'unavailable'}. They use "
                    "psutil and need no special permission.\n"
                    f"- **Packet capture:** {'available' if capability.packets else 'not available'}.")
        for reason in capability.reasons:
            st.markdown(f"  - {reason}")
        st.markdown("Monitoring is **passive**: it only observes. It never sends, injects, scans or blocks traffic. "
                    "Imported telemetry and datasets keep working whether or not capture is available.")

    if not principal.has(Permission.CONTROL_MONITORING):
        st.caption("Only administrators can start or stop live capture.")
        return
    if live.status.running:
        if st.button("Stop capture", type="primary", icon=":material/stop_circle:"):
            try:
                live.stop(principal)
            except (MonitorError, PermissionDenied) as exc:
                st.error(str(exc))
            st.rerun()
        return
    if not allowed:
        st.info("No network interface is authorised for monitoring yet. Authorise one in **Settings → Monitoring**. "
                "Only monitor networks you are allowed to observe.")
        return
    with st.form("start_capture", border=True):
        c1, c2 = st.columns(2)
        interface = c1.selectbox("Authorised interface", allowed,
                                 format_func=lambda n: f"{n} ({', '.join(present[n]['addresses'][:2]) or 'no address'})")
        modes = [m for m in MODES if m == "counters" or capability.packets]
        mode = c2.radio("Mode", modes, format_func=MODES.get)
        c3, c4, c5 = st.columns(3)
        interval = c3.number_input("Counter interval (s)", 1, 60, settings.default_interval_seconds)
        capacity = c4.number_input("Link capacity (Mbit/s, optional)", 0.0, 400_000.0, 0.0, step=10.0,
                                   help="Configured, not measured. Without it, utilization stays unavailable.")
        detect = c5.checkbox("Live detection", value=True, disabled="packets" not in modes,
                             help="Scores finished flows with the active intrusion classifier if it is live-compatible.")
        start = st.form_submit_button("Start capture", type="primary", icon=":material/play_circle:")
    if start:
        try:
            live.start(principal, interface, mode=mode, interval_seconds=int(interval),
                       capacity_bps=capacity * 1e6 if capacity > 0 else None, live_detection=detect)
        except (MonitorError, PermissionDenied) as exc:
            st.error(str(exc))
        else:
            st.rerun()
