"""Bandwidth what-if sandbox: change capacity, classes, demands and weights and watch the allocation refill."""
from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import waterfill
from components.guard import require_principal
from components.theme import COLORS, apply_chart_theme
from components.ui import format_bits_rate, kpi_tile, page_header, section_label
from services import bandwidth_service, what_if_service
from services.authorization import Permission, PermissionDenied
from services.what_if_service import SimClass, WhatIfError

principal = require_principal()
ROWS_KEY, START_KEY = "what_if_rows", "what_if_start"
M = 1e6

page_header("What-if simulator", "Try a link capacity, traffic classes, demands and weights and see how the same "
            "water-filling algorithm used for recommendations would share the link. This is a sandbox: nothing is "
            "saved and no traffic is shaped.", eyebrow="Intelligence")
st.info("**Simulation only.** Moving these sliders never touches the network. The only way out is the admin-only "
        "*Propose as shaping policy…* button, which creates a proposal that still has to be accepted and applied "
        "in Bandwidth Management.", icon=":material/science:")

policies = bandwidth_service.list_policies(principal)
starts = ["Four-class template"] + [p.name for p in policies]
c1, c2 = st.columns([2, 1])
start = c1.selectbox("Start from", starts, help="A saved policy (its classes, with demand set to zero) or the "
                     "editable four-class template.")
if st.session_state.get(START_KEY) != start or ROWS_KEY not in st.session_state:
    capacity_bps, interface, rows = what_if_service.starting_point(
        principal, None if start == starts[0] else start, capacity_bps=100 * M)
    st.session_state[START_KEY] = start
    st.session_state[ROWS_KEY] = pd.DataFrame([{"Class": r.name, "Minimum (Mbit/s)": r.minimum_bps / M,
                                                "Maximum (Mbit/s)": r.maximum_bps / M} for r in rows])
    st.session_state["what_if_capacity"] = capacity_bps / M
    st.session_state["what_if_interface"] = interface or ""
    for r in rows:
        st.session_state[f"what_if_weight_{r.name}"] = float(r.priority_weight)
        st.session_state[f"what_if_demand_{r.name}"] = round(min(r.maximum_bps / M / 2, capacity_bps / M), 1)
if c2.button("Reset to start", icon=":material/restart_alt:", width="stretch"):
    st.session_state.pop(START_KEY, None)
    st.rerun()

c1, c2 = st.columns(2)
capacity = c1.number_input("Link capacity (Mbit/s)", 0.1, 400_000.0, key="what_if_capacity", step=10.0,
                           help="Hypothetical: shown as configured, never as measured.")
margin = c2.slider("Safety margin (% kept free)", 0, 50, 10, key="what_if_margin")

section_label("Traffic classes")
table = st.data_editor(st.session_state[ROWS_KEY], num_rows="dynamic", hide_index=True, key="what_if_editor",
                       column_config={
                           "Class": st.column_config.TextColumn(required=True, max_chars=40),
                           "Minimum (Mbit/s)": st.column_config.NumberColumn(min_value=0.0, format="%.2f"),
                           "Maximum (Mbit/s)": st.column_config.NumberColumn(min_value=0.0, format="%.2f")})
st.caption("Add or remove rows to add or remove applications. Minimums are reserved first; maximums cap a class.")

rows = [r for r in table.to_dict("records") if str(r.get("Class") or "").strip()]
classes = []
if rows:
    section_label("Demand and priority per class")
    for r in rows:
        name = str(r["Class"]).strip()
        maximum = float(r.get("Maximum (Mbit/s)") or 0)
        a, b, c = st.columns([1, 2, 2])
        a.markdown(f"**{name}**")
        top = max(1.0, float(capacity) * 1.5)
        demand_key, weight_key = f"what_if_demand_{name}", f"what_if_weight_{name}"
        st.session_state.setdefault(demand_key, min(maximum, capacity / 4))
        st.session_state[demand_key] = min(float(st.session_state[demand_key]), top)
        st.session_state.setdefault(weight_key, 1.0)
        demand = b.slider(f"Demand · {name} (Mbit/s)", 0.0, top, key=demand_key)
        weight = c.slider(f"Weight · {name}", 0.1, 10.0, key=weight_key, step=0.1)
        classes.append(SimClass(name, float(r.get("Minimum (Mbit/s)") or 0) * M, maximum * M, weight, demand * M))

if not classes:
    st.info("Add at least one traffic class.")
    st.stop()
try:
    result = what_if_service.simulate(principal, capacity * M, margin / 100, classes)
except WhatIfError as exc:
    st.error(f"This scenario is not feasible: {exc}")
    st.stop()

k1, k2, k3, k4 = st.columns(4)
with k1:
    kpi_tile("Usable capacity", format_bits_rate(result.usable_bps), "configured", f"after a {margin}% margin")
with k2:
    kpi_tile("Allocated", format_bits_rate(result.total_allocated_bps), "derived", "never above usable capacity")
with k3:
    kpi_tile("Demand", format_bits_rate(result.total_demand_bps), "configured", "your hypothetical demand")
with k4:
    kpi_tile("Unmet demand", format_bits_rate(result.unmet_demand_bps), "derived",
             "reported, never hidden" if result.unmet_demand_bps else "everything fits")

section_label("Water-filling (replays every time you change something)")
waterfill.render(result, replay=hash(tuple((c.name, c.demand_bps, c.priority_weight) for c in classes)))
fig = go.Figure()
names = [a.name for a in result.allocations]
fig.add_trace(go.Bar(name="Allocated", x=names, y=[a.allocated_bps for a in result.allocations],
                     marker_color=COLORS["accent"]))
fig.add_trace(go.Bar(name="Demand", x=names, y=[a.demand_bps for a in result.allocations],
                     marker_color=COLORS["muted"]))
fig.update_layout(title="Allocated vs demand per class (simulation)", barmode="group", yaxis_title="bit/s",
                  transition=dict(duration=300, easing="cubic-out"))
st.plotly_chart(apply_chart_theme(fig, height=320), theme=None, key="what_if_bars")
st.dataframe(pd.DataFrame([{"Class": a.name, "Weight": a.priority_weight, "Demand": format_bits_rate(a.demand_bps),
                            "Allocated": format_bits_rate(a.allocated_bps), "Unmet": format_bits_rate(a.unmet_demand_bps),
                            "Limited by": a.limited_by} for a in result.allocations]), hide_index=True)
with st.expander("Why this split"):
    st.markdown("\n".join(f"- {line}" for line in result.rationale))
    st.markdown("\n".join(f"- {'✅' if ok else '❌'} {name}" for name, ok in result.invariants.items()))

section_label("Turn this into a real policy")
can_propose = principal.has(Permission.APPLY_TRAFFIC_POLICY)
with st.popover("Propose as shaping policy…", icon=":material/policy:", disabled=not can_propose,
                help=None if can_propose else "Admin only"):
    st.markdown("Saves this scenario as a bandwidth **policy** and a **proposed** recommendation. Nothing is "
                "enforced: an administrator still accepts it and applies it, with a typed confirmation, in "
                "Bandwidth Management → Enforcement. Saving a policy with an existing name replaces it.")
    name = st.text_input("Policy name", value="what-if scenario", max_chars=60)
    interface = st.text_input("Interface (optional)", key="what_if_interface", max_chars=64)
    if st.button("Save as proposal", type="primary"):
        try:
            rid = what_if_service.propose(principal, name=name, interface=interface or None,
                                          capacity_bps=capacity * M, safety_margin=margin / 100, classes=classes)
        except (WhatIfError, PermissionDenied) as exc:
            st.error(str(exc))
        else:
            st.success(f"Saved as proposed recommendation #{rid}. Review it in Bandwidth Management → History.")
if not can_propose:
    st.caption("Only administrators can turn a simulation into a proposal.")
