"""Replay / demo mode: play a labelled dataset through the real pipeline, clearly labelled DATASET REPLAY."""
from __future__ import annotations

from html import escape

import streamlit as st

from components.guard import require_principal
from components.ui import empty_state, format_timestamp, kpi_tile, page_header, section_label, source_badge
from services import data_source, dataset_service, replay_service
from services.authorization import Permission, PermissionDenied
from services.replay_service import ReplayError

principal = require_principal()
engine = replay_service.get_engine()

page_header("Replay / demo mode", "Play a labelled dataset back through the real detection pipeline, as if its "
            "traffic were arriving now. Every screen is marked DATASET REPLAY, and replay data is kept apart from "
            "captured data.", eyebrow="Monitor")


def _run(action, *args) -> None:
    try:
        action(principal, *args)
    except (ReplayError, PermissionDenied) as exc:
        st.error(str(exc))
    else:
        st.rerun()


@st.fragment(run_every=1 if engine.status.running else None)
def render_status() -> None:
    status = replay_service.status_copy()
    if status.session_id is None:
        st.caption("Nothing is replaying.")
        return
    state = ("Paused" if status.paused else f"Playing at {status.speed}×") if status.running else \
        ("Finished" if status.finished else "Stopped")
    st.markdown(f"{source_badge(data_source.classify('replay'))} &nbsp;**{escape(state)}** · "
                f"'{escape(status.scenario_title or '')}' from {escape(status.dataset_name or '')}"
                + (" · <b>synthetic sample data</b>" if status.synthetic else ""), unsafe_allow_html=True)
    st.progress(min(1.0, status.progress), text=f"{status.rows_done:,} of {status.rows_total:,} rows · replay clock "
                f"{format_timestamp(status.replay_time)} (dataset time {format_timestamp(status.dataset_start)} → "
                f"{format_timestamp(status.dataset_end)})")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kpi_tile("Rows / second", None if status.rows_per_second is None or not status.running
                 else f"{status.rows_per_second:,.0f}", "measured" if status.running else "unavailable",
                 "wall clock, at the chosen speed")
    with c2:
        kpi_tile("Flagged flows", f"{status.flagged:,}", "predicted", "classifier or anomaly detector")
    with c3:
        kpi_tile("Alerts raised", f"{len(status.alerts):,}", "derived",
                 f"one per category per {replay_service.ALERT_WINDOW_SECONDS // 60} min of dataset time")
    with c4:
        kpi_tile("Incidents", f"{len(status.incidents):,}", "derived", "replay alerts correlate only with each other")
    if status.forecast_note:
        st.caption(f"PredictNet: {status.forecast_note}")
    if status.last_error:
        st.error(status.last_error)
    if status.running and status.paused:
        st.caption("Paused: the replay clock is stopped; resume to continue from the same row.")


datasets = [d for d in dataset_service.list_datasets(principal, kind="intrusion_flows") if d.has_timestamps]
status = engine.status
can_run = principal.has(Permission.RUN_DETECTION)

section_label("Now playing")
render_status()
if status.running and can_run:
    b1, b2, b3, b4 = st.columns([1, 2, 1, 1])
    if status.paused:
        if b1.button("Resume", icon=":material/play_arrow:", type="primary", width="stretch"):
            _run(engine.resume)
    elif b1.button("Pause", icon=":material/pause:", width="stretch"):
        _run(engine.pause)
    speed = b2.segmented_control("Speed", replay_service.SPEEDS, default=status.speed, key="replay_speed_live",
                                 format_func=lambda s: f"{s}×", label_visibility="collapsed")
    if speed and speed != status.speed:
        _run(engine.set_speed, speed)
    if b3.button("Restart", icon=":material/replay:", width="stretch"):
        _run(engine.restart)
    if b4.button("Stop", icon=":material/stop:", width="stretch"):
        _run(engine.stop)
    l1, l2 = st.columns(2)
    l1.page_link("views/network_map.py", label="Watch the Network Map", icon=":material/hub:")
    l2.page_link("views/incident_center.py", label="Watch the Incident Center", icon=":material/crisis_alert:")
elif status.session_id is not None and can_run and not status.running:
    if st.button("Play it again", icon=":material/replay:"):
        _run(engine.restart)

section_label("Start a replay")
if not datasets:
    empty_state("▶", "No dataset to replay",
                "Replay needs a registered intrusion dataset with labels and timestamps (CIC-IDS2017 format). Register "
                "one in the ML Laboratory, train and activate a classifier, then come back.")
elif not can_run:
    st.info("Your role cannot start replays.")
elif status.running:
    st.caption("Stop the current replay to start another.")
else:
    by_id = {d.id: d for d in datasets}
    dataset_id = st.selectbox("Labelled dataset", list(by_id),
                              format_func=lambda i: f"#{i} · {by_id[i].name} · {by_id[i].row_count:,} rows")
    keys = {s.key: s for s in replay_service.scenarios(principal, dataset_id)}
    c1, c2 = st.columns([2, 1])
    scenario_key = c1.selectbox("Scenario", list(keys), format_func=lambda k: keys[k].title)
    speed = c2.segmented_control("Speed", replay_service.SPEEDS, default=10, format_func=lambda s: f"{s}×",
                                 key="replay_speed_new")
    st.caption(keys[scenario_key].description)
    if "brute_force" not in keys:
        st.caption("No brute-force scenario: this dataset has no Patator / brute-force rows. Register a dataset that "
                   "contains them (for example SSH-Patator) to replay one.")
    capacity_mbps = st.number_input("Link capacity for the replayed traffic (Mbit/s, optional)", min_value=0.0,
                                    value=0.0, step=10.0,
                                    help="Only used to turn replayed throughput into utilization for PredictNet. "
                                         "Leave 0 to keep utilization unavailable.")
    if "synthetic" in by_id[dataset_id].name.lower():
        st.warning("This is a synthetic sample dataset. Replayed results show how the pipeline behaves, not real "
                   "network activity.")
    if st.button("Start replay", icon=":material/play_arrow:", type="primary"):
        try:
            engine.start(principal, dataset_id, scenario_key, speed=speed or 10,
                         capacity_bps=capacity_mbps * 1e6 if capacity_mbps else None)
        except (ReplayError, PermissionDenied) as exc:
            st.error(str(exc))
        else:
            st.rerun()

section_label("Replay data")
counts = replay_service.replay_counts(principal)
st.caption(f"Stored replay data: {counts['sessions']:,} session(s), {counts['flows']:,} flows, {counts['metrics']:,} "
           f"throughput samples, {counts['alerts']:,} alerts, {counts['incidents']:,} incidents, "
           f"{counts['predictions']:,} forecasts. Real captured and imported data is never included.")
if principal.has(Permission.DELETE_DATA):
    with st.popover("Clear replay data", icon=":material/delete:", disabled=not any(counts.values())):
        st.markdown("This deletes **every** replay session with its flows, samples, alerts, incidents and "
                    "forecasts, and stops a running replay. Captured and imported data stay. It is audited.")
        if st.button("Yes, clear replay data", type="primary"):
            try:
                cleared = replay_service.clear_replay_data(principal)
            except (ReplayError, PermissionDenied) as exc:
                st.error(str(exc))
            else:
                st.toast(f"Cleared {cleared['flows']:,} replayed flows and {cleared['alerts']:,} alerts.")
                st.rerun()
else:
    st.caption("Only an administrator can clear replay data.")

with st.expander("How replay works"):
    st.markdown(f"""
- Rows are read from the registered dataset and played in **their own timestamp order**. The replay clock moves through
  the dataset's time at the chosen speed, so 1 minute of recorded traffic takes 2 seconds at 30×. Timestamps are not
  rewritten to "now".
- Each row goes through the **active, hash-verified** classifier and anomaly detector, exactly as in dataset detection.
- Flagged rows are grouped into one alert per category per {replay_service.ALERT_WINDOW_SECONDS // 60} minutes of dataset
  time, raised when that window has fully played. New alerts are correlated into incidents straight away.
- Throughput samples for PredictNet are **derived** from the bytes of the replayed flow records per
  {replay_service.METRIC_INTERVAL_SECONDS} s. Utilization is only shown if you give a capacity.
- All of it is stored under sessions of type **replay**, so it never mixes with captured data and can be cleared.
""")
