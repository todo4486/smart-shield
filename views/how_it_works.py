"""How it works: one real stored flow walked through the pipeline, stage by stage."""
from __future__ import annotations

import streamlit as st

from components import pipeline
from components.guard import require_principal
from components.ui import page_header
from services import how_it_works_service, live_monitor_service

principal = require_principal()
STEP_KEY, OFFSET_KEY = "how_step", "how_flow_offset"

page_header("How it works", "Follow one flow from passive capture to an incident and a report. Every value below is "
            "stored data for that flow, not an illustration.", eyebrow="Learn")

c1, c2, c3 = st.columns([2, 1, 1])
flagged_only = c1.toggle("Prefer a flagged flow", value=True,
                         help="Show a flow the models flagged, so every stage has something to show.")
if c2.button("Another flow", icon=":material/shuffle:", width="stretch"):
    st.session_state[OFFSET_KEY] = st.session_state.get(OFFSET_KEY, 0) + 1
    st.session_state[STEP_KEY] = 0
if c3.button("Start over", icon=":material/restart_alt:", width="stretch"):
    st.session_state[STEP_KEY] = 0

status = live_monitor_service.get_monitor().status
trace = how_it_works_service.sample_trace(principal, flagged_only=flagged_only,
                                          offset=st.session_state.get(OFFSET_KEY, 0), live_running=status.running)
stages = trace["stages"]
step = min(st.session_state.get(STEP_KEY, 0), len(stages) - 1)

if trace["flow_id"] is None:
    st.info("No flows are stored yet, so the stages are explained without data. Start a replay (Monitor → Replay / "
            "demo), run detection on a dataset, or start live capture, then come back.")
else:
    st.caption(f"Flow #{trace['flow_id']} · one of {trace['candidates']:,} "
               f"{'flagged ' if trace.get('flagged_only') else ''}flows in the newest session with flows.")

pipeline.render(stages, step)
b1, b2, _ = st.columns([1, 1, 4])
if b1.button("Back", icon=":material/arrow_back:", disabled=step == 0, width="stretch"):
    st.session_state[STEP_KEY] = step - 1
    st.rerun()
if b2.button("Next", icon=":material/arrow_forward:", type="primary", disabled=step == len(stages) - 1,
             width="stretch"):
    st.session_state[STEP_KEY] = step + 1
    st.rerun()
if step == len(stages) - 1:
    l1, l2, l3 = st.columns(3)
    l1.page_link("views/incident_center.py", label="Open the Incident Center", icon=":material/crisis_alert:")
    l2.page_link("views/reports.py", label="Export a report", icon=":material/description:")
    l3.page_link("views/replay.py", label="Try a replay", icon=":material/play_circle:")
