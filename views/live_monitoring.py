"""Network monitoring: passive live capture, session history and the telemetry each session recorded."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from components import charts, live_capture
from components.guard import require_principal
from components.ui import (
    SOURCE_LABELS, empty_state, format_bits_rate, format_bytes_rate, format_timestamp, kpi_tile, page_header, section_label,
)
from services import monitoring_service, telemetry_view_service
from services.authorization import Permission, PermissionDenied

principal = require_principal()

page_header(
    "Live Monitoring",
    "Every telemetry source is recorded as a monitoring session. Review what each session measured, how "
    "complete it is, and where values were derived rather than measured.",
    eyebrow="Monitor",
)
live_capture.render(principal)
st.write("")

sessions = monitoring_service.list_sessions(principal)
if not sessions:
    empty_state(
        "📡", "No monitoring sessions yet",
        "Start a live capture above, import a historical telemetry CSV, or register a timestamped flow dataset in "
        "the ML Laboratory. Each becomes a session you can explore here.",
    )
    st.page_link("views/ml_lab.py", label="Go to ML Laboratory → Data sources", icon=":material/upload:")
    st.stop()

section_label("Session history")
st.dataframe(
    pd.DataFrame([
        {"ID": s.id, "Source": SOURCE_LABELS.get(s.source_type, s.source_type),
         "File": s.configuration.get("filename", "—"), "Interface": s.interface_name or "—", "Status": s.status,
         "Started": format_timestamp(s.started_at), "Ended": format_timestamp(s.ended_at),
         "Measurements": s.metric_count, "Flows": s.flow_count, "By": s.user_email or "—",
         "Message": s.status_message or ""}
        for s in sessions
    ]),
    hide_index=True,
)

by_id = {s.id: s for s in sessions}
with_data = [s.id for s in sessions if s.metric_count or s.flow_count]
selected_id = st.selectbox(
    "Explore session", list(by_id), index=list(by_id).index(with_data[0]) if with_data else 0,
    format_func=lambda i: f"#{i} · {SOURCE_LABELS.get(by_id[i].source_type, by_id[i].source_type)} · "
                          f"{by_id[i].configuration.get('filename', '')} · {by_id[i].status}",
)
session = by_id[selected_id]

if session.status == "ERROR":
    st.error(f"This session failed: {session.status_message or 'no details recorded'}")

# ------------------------------------------------------------------ metrics
if session.metric_count:
    telemetry = telemetry_view_service.session_telemetry(principal, session.id)
    interfaces = [i for i in telemetry.interfaces]
    if len(interfaces) > 1:
        choice = st.radio("Interface", ["All"] + [i or "(unnamed)" for i in interfaces], horizontal=True)
        if choice != "All":
            telemetry = telemetry_view_service.session_telemetry(
                principal, session.id, "" if choice == "(unnamed)" else choice
            )
    frame = telemetry.metrics
    sampling = {s["interface"]: s for s in session.configuration.get("sampling", [])}
    medians = [s["median_interval_seconds"] for s in sampling.values() if s.get("median_interval_seconds")]

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kpi_tile("Measurements", f"{len(frame):,}", "measured", f"{len(telemetry.interfaces)} interface(s)")
    with c2:
        kpi_tile("Time span", f"{(frame['timestamp'].max() - frame['timestamp'].min()).total_seconds() / 3600:,.1f} h",
                 "derived", f"{format_timestamp(frame['timestamp'].min().isoformat())} → "
                            f"{format_timestamp(frame['timestamp'].max().isoformat())}")
    with c3:
        kpi_tile("Sampling interval", f"{min(medians):,.0f} s" if medians else None, "derived" if medians else "unavailable",
                 "Median spacing between samples")
    with c4:
        peak = telemetry.stats.get("throughput_bps", {}).get("max")
        kpi_tile("Peak throughput", format_bits_rate(peak), "derived" if peak is not None else "unavailable",
                 "Max of stored throughput values" if peak is not None else "No throughput values")

    plot_columns = ["incoming_bytes_per_second", "outgoing_bytes_per_second", "throughput_bps",
                    "utilization_ratio", "latency_ms", "packet_loss_ratio",
                    "incoming_packets_per_second", "outgoing_packets_per_second"]
    plotted = telemetry_view_service.break_gaps(frame[["timestamp", "interface_name"] + plot_columns], plot_columns)
    plotted, bucket = telemetry_view_service.downsample(plotted, plot_columns)
    if bucket:
        st.caption(f"Charts show values aggregated as {bucket} (derived) to keep them readable. "
                   "Empty buckets stay empty.")
    split = len(telemetry.interfaces) > 1 and plotted["interface_name"].nunique() > 1

    rates_tab, util_tab, perf_tab, quality_tab = st.tabs(
        ["Traffic rates", "Throughput & utilization", "Latency & loss", "Data quality"]
    )
    with rates_tab:
        charts.time_series(plotted, [("incoming_bytes_per_second", "Incoming"), ("outgoing_bytes_per_second", "Outgoing")],
                           title="Measured traffic rate", y_title="Bytes per second", split_by_interface=split)
        if plotted[["incoming_packets_per_second", "outgoing_packets_per_second"]].notna().any().any():
            charts.time_series(plotted, [("incoming_packets_per_second", "Incoming"),
                                         ("outgoing_packets_per_second", "Outgoing")],
                               title="Measured packet rate", y_title="Packets per second", split_by_interface=split)
    with util_tab:
        tp = telemetry.provenance_counts.get("throughput_provenance", {})
        st.caption("Throughput provenance: " + ", ".join(f"{k} {v:,}" for k, v in tp.items()))
        charts.time_series(plotted, [("throughput_bps", "Throughput")], title="Throughput",
                           y_title="Bits per second", split_by_interface=split)
        if frame["utilization_ratio"].notna().any():
            up = telemetry.provenance_counts.get("utilization_provenance", {})
            st.caption("Utilization provenance: " + ", ".join(f"{k} {v:,}" for k, v in up.items()))
            charts.time_series(plotted, [("utilization_ratio", "Utilization")], title="Link utilization",
                               y_title="Utilization", split_by_interface=split, y_format=".0%")
        else:
            st.info("Utilization is **unavailable** for this session: the data has no utilization values and no "
                    "configured link capacity. Absolute rates are shown instead; no percentage is invented.")
    with perf_tab:
        has_latency = frame["latency_ms"].notna().any()
        has_loss = frame["packet_loss_ratio"].notna().any()
        if has_latency:
            charts.time_series(plotted, [("latency_ms", "Latency")], title="Measured latency", y_title="Milliseconds",
                               split_by_interface=split)
        if has_loss:
            charts.time_series(plotted, [("packet_loss_ratio", "Packet loss")], title="Measured packet loss",
                               y_title="Loss", split_by_interface=split, y_format=".1%")
        if not (has_latency or has_loss):
            st.info("This session has no latency or packet-loss measurements. They are shown as unavailable, not zero.")
    with quality_tab:
        left, right = st.columns([1, 1])
        with left:
            charts.coverage_bars({k: v for k, v in telemetry.coverage.items()}, title="Share of rows with a value")
        with right:
            section_label("Summary statistics")
            units = {"incoming_bytes_per_second": format_bytes_rate, "outgoing_bytes_per_second": format_bytes_rate,
                     "throughput_bps": format_bits_rate}
            rows = []
            for name, stat in telemetry.stats.items():
                if not stat["count"]:
                    continue
                fmt = units.get(name, lambda v: f"{v:,.4g}")
                rows.append({"Metric": name, "Values": stat["count"], "Min": fmt(stat["min"]),
                             "Mean": fmt(stat["mean"]), "95th pct": fmt(stat["p95"]), "Max": fmt(stat["max"])})
            st.dataframe(pd.DataFrame(rows), hide_index=True)
            if sampling:
                section_label("Gaps")
                st.dataframe(pd.DataFrame([
                    {"Interface": name, "Median interval": f"{s['median_interval_seconds'] or 0:,.0f} s",
                     "Gaps (> 2× interval)": s["gaps"]}
                    for name, s in sampling.items()
                ]), hide_index=True)

# -------------------------------------------------------------------- flows
if session.flow_count:
    st.write("")
    section_label("Flows")
    flows = telemetry_view_service.flow_summary(principal, session.id)
    left, right = st.columns(2)
    with left:
        charts.bar([p["protocol"] for p in flows.protocols], [p["flows"] for p in flows.protocols],
                   title="Flows by protocol", y_title="Flows")
    with right:
        charts.bar([str(p["dst_port"]) for p in flows.top_ports], [p["flows"] for p in flows.top_ports],
                   title="Top destination ports", horizontal=True, height=360)
    if flows.per_minute:
        per_minute = pd.DataFrame(flows.per_minute)
        per_minute["timestamp"] = pd.to_datetime(per_minute["minute"] + ":00Z", utc=True, format="ISO8601")
        per_minute["interface_name"] = None
        charts.time_series(per_minute, [("flows", "Flows started")], title="Flows per minute", y_title="Flows")
    if flows.dataset_labels:
        labels = list(flows.dataset_labels)[:15]
        charts.bar(labels, [flows.dataset_labels[l] for l in labels], horizontal=True,
                   title="Dataset labels (ground truth from the dataset, not detections)",
                   height=max(260, 30 * len(labels) + 90))

if not session.metric_count and not session.flow_count and session.status != "ERROR":
    st.info("This session recorded no measurements or flows.")

# ------------------------------------------------------------------- delete
if principal.has(Permission.DELETE_DATA) and session.status in ("STOPPED", "ERROR"):
    with st.expander("Delete this session", icon=":material/delete:"):
        st.write(f"Removes session #{session.id} with its {session.metric_count:,} measurements and "
                 f"{session.flow_count:,} flows. The action is recorded in the audit log.")
        confirm = st.checkbox("I understand this cannot be undone", key=f"confirm_delete_{session.id}")
        if st.button("Delete session", disabled=not confirm, key=f"delete_{session.id}"):
            try:
                monitoring_service.delete_session(principal, session.id)
            except (PermissionDenied, monitoring_service.InvalidTransition, monitoring_service.SessionNotFound) as exc:
                st.error(str(exc))
            else:
                st.toast(f"Session #{session.id} deleted.")
                st.rerun()
