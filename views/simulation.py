"""Simulation mode: synthetic traffic in memory, sent through the real flow extractor and models."""
from __future__ import annotations

from html import escape

import streamlit as st

from components import mitigation_panel
from components.guard import require_principal
from components.ui import format_bits_rate, format_ratio, kpi_tile, page_header, section_label, source_badge
from services import data_source, simulation_service
from services.authorization import Permission, PermissionDenied
from services.simulation_service import SCENARIOS, SimulationError

principal = require_principal()
engine = simulation_service.get_engine()

page_header("Simulation", "Create synthetic traffic and attacks in memory, and watch the real flow extractor and models "
            "respond. No packet is ever sent, so it is safe on any network. Everything is labelled SIMULATION and stored "
            "apart from real data.", eyebrow="Monitor")


@st.fragment(run_every=1 if engine.status.running else None)
def render_status() -> None:
    s = simulation_service.status_copy()
    if s.session_id is None:
        st.caption("Nothing is simulating.")
        return
    state = "Running" if s.running else ("Finished" if s.finished else "Stopped")
    st.markdown(f"{source_badge(data_source.classify('simulation'))} &nbsp;**{escape(state)}** · "
                f"'{escape(s.scenario_title or '')}' · {s.elapsed_seconds:.0f} of {s.duration_seconds:.0f} s · "
                f"{escape(simulation_service.elapsed_note(s))}", unsafe_allow_html=True)
    st.progress(min(1.0, s.elapsed_seconds / max(1.0, s.duration_seconds)))
    c1, c2, c3 = st.columns(3)
    with c1:
        kpi_tile("Offered traffic", format_bits_rate(s.offered_bps), "simulated", "what the sources try to send")
    with c2:
        kpi_tile("Carried by the link", format_bits_rate(s.throughput_bps), "simulated",
                 f"capacity {format_bits_rate(s.capacity_bps)} (configured)")
    with c3:
        kpi_tile("Dropped by the full link", format_ratio(s.loss_ratio), "simulated", "equal cut for every source")
    c1, c2, c3 = st.columns(3)
    with c1:
        kpi_tile("Flows scored", f"{s.flows_scored:,}", "simulated", f"model {s.model_version}"
                 + ("" if s.model_active else " (not the active model)"))
    with c2:
        top = ", ".join(f"{k} {v:,}" for k, v in sorted(s.by_category.items(), key=lambda kv: -kv[1])[:3])
        kpi_tile("Flagged by the models", f"{s.flagged:,}", "predicted", top or "real model verdicts, not scripted")
    with c3:
        kpi_tile("Alerts · incidents", f"{len(s.alerts):,} · {len(s.incidents):,}", "derived", "alerts every 10 s of flagged flows")
    if s.last_error:
        st.error(s.last_error)


can_run = principal.has(Permission.RUN_DETECTION)
section_label("Now running")
render_status()
status = engine.status

if status.running and can_run:
    if st.button("Stop", icon=":material/stop:"):
        try:
            engine.stop(principal)
        except (SimulationError, PermissionDenied) as exc:
            st.error(str(exc))
        else:
            st.rerun()
    l1, l2, l3 = st.columns(3)
    l1.page_link("views/bandwidth.py", label="Watch hosts in Bandwidth Management", icon=":material/tune:")
    l2.page_link("views/network_map.py", label="Watch the Network Map", icon=":material/hub:")
    l3.page_link("views/incident_center.py", label="Watch the Incident Center", icon=":material/crisis_alert:")



@st.fragment(run_every=2 if engine.status.running else None)
def render_mitigation() -> None:
    session_id = simulation_service.status_copy().session_id
    if session_id is not None:
        mitigation_panel.render_session(principal, session_id)


section_label("Threat mitigation")
mitigation_panel.render_policy(principal)
render_mitigation()

section_label("Start a simulation")
if not can_run:
    st.info("Your role cannot start simulations.")
elif status.running:
    st.caption("Stop the current simulation to start another.")
else:
    classifier, detector = simulation_service.live_compatible_model(principal)
    if classifier is None:
        st.warning("**No live-compatible model yet.** Simulated flows carry only features computable from packets, and "
                   "features are never zero-filled. In the ML Laboratory, train Smart Shield models with the "
                   "**live-compatible** feature set, then come back. It does not have to be the active model.")
        st.page_link("views/ml_lab.py", label="Open the ML Laboratory", icon=":material/science:")
    else:
        st.caption(f"Models: {classifier.name} {classifier.version}"
                   + (" (active)" if classifier.is_active else " (registered, not active)")
                   + (" with its anomaly detector." if detector else ", no anomaly detector."))
        c1, c2 = st.columns([2, 1])
        scenario = c1.selectbox("Scenario", list(SCENARIOS), format_func=lambda k: SCENARIOS[k][0])
        capacity = c2.number_input("Simulated link capacity (Mbit/s)", 1.0, 10_000.0, 100.0, step=10.0)
        st.caption(SCENARIOS[scenario][1])
        c1, c2 = st.columns(2)
        delay = c1.slider("Normal traffic before the attack (s)", 0, 120, simulation_service.DEFAULT_ATTACK_DELAY_SECONDS)
        duration = c2.slider("Run for (s)", 30, 600, 180, step=30)
        if st.button("Start simulation", type="primary", icon=":material/play_arrow:"):
            try:
                engine.start(principal, scenario, capacity_bps=capacity * 1e6, attack_delay_seconds=delay,
                             duration_seconds=duration)
            except (SimulationError, PermissionDenied) as exc:
                st.error(str(exc))
            else:
                st.rerun()

section_label("Simulation data")
counts = simulation_service.data_counts(principal)
st.caption(f"Stored: {counts['sessions']:,} session(s), {counts['flows']:,} flows, {counts['metrics']:,} link samples, "
           f"{counts['host_samples']:,} host samples, {counts['alerts']:,} alerts, {counts['incidents']:,} incidents. "
           "Captured, imported and replayed data is never included.")
if principal.has(Permission.DELETE_DATA):
    with st.popover("Clear simulation data", icon=":material/delete:", disabled=not any(counts.values())):
        st.markdown("Deletes **every** simulation session with its data, and stops a running simulation. It is audited.")
        if st.button("Yes, clear simulation data", type="primary"):
            try:
                cleared = simulation_service.clear_simulation_data(principal)
            except (SimulationError, PermissionDenied) as exc:
                st.error(str(exc))
            else:
                st.toast(f"Cleared {cleared['flows']:,} simulated flows and {cleared['alerts']:,} alerts.")
                st.rerun()
else:
    st.caption("Only an administrator can clear simulation data.")

with st.expander("What is real and what is simulated"):
    st.markdown(f"""
- **Simulated:** the hosts (documentation address ranges), the traffic volumes and the link. Rates are calculated by a
  simple model and labelled *Simulated*. If traffic exceeds the capacity, every source is cut by the same share.
- **Mitigation:** decisions, records and audit entries are real, but enforcement here is the link model reading the active
  limits, so its effect is simulated. Nothing touches a real network adapter. A limit on outgoing traffic frees the link;
  a limit on a flood from outside only stops it reaching the host, because it has already filled the link.
- **Real:** the flow extractor, the features, and the verdicts of your registered, hash-verified models. No verdict is
  scripted, so a scenario can be missed or misnamed by the model, and that is shown as it is.
- **Sampling:** each source contributes exact bandwidth totals, but only a few representative flows per second go through
  the models, so stored flows are a sample. {simulation_service.SAMPLE_NOTE}
- **Never on a network:** this code opens no sockets and creates no packets on any interface.
""")
