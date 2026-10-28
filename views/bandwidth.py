"""Bandwidth Management: policies, recommendations, history and optional (opt-in) enforcement."""
from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import waterfill
from components.guard import require_principal
from components.theme import COLORS, apply_chart_theme
from components.ui import format_bits_rate, format_timestamp, kpi_tile, page_header, section_label
from services import bandwidth_service, monitoring_service, traffic_shaping_service
from services.authorization import Permission, PermissionDenied
from services.bandwidth_service import BandwidthError
from services.traffic_shaping_service import ShapingError

principal = require_principal()
can_configure = principal.has(Permission.MANAGE_SETTINGS)
can_recommend = principal.has(Permission.GENERATE_RECOMMENDATIONS)
can_enforce = principal.has(Permission.APPLY_TRAFFIC_POLICY)

page_header(
    "Bandwidth Management",
    "Recommend how a link's capacity should be shared between traffic classes, using a deterministic, documented "
    "algorithm. Total allocations never exceed capacity, and unmet demand is reported, never hidden.",
    eyebrow="Intelligence",
)
st.info("**Recommendation mode.** Changing numbers on this page does not change real bandwidth. Enforcement is a "
        "separate, optional, admin-only step that is off by default (see *Enforcement*).", icon=":material/info:")

policies = bandwidth_service.list_policies(principal)
policy_tab, recommend_tab, history_tab, enforce_tab = st.tabs(
    ["Policies", "Recommend", "History", "Enforcement (advanced)"]
)

# ------------------------------------------------------------------ policies
with policy_tab:
    by_name = {p.name: p for p in policies}
    options = (["➕ New policy"] if can_configure else []) + list(by_name)
    if not options:
        st.info("No bandwidth policies exist yet. An administrator creates one here.")
    else:
        choice = st.selectbox("Policy", options)
        editing = by_name.get(choice)
        if editing is None:
            c1, c2 = st.columns(2)
            capacity_mbps = c1.number_input("Configured link capacity (Mbit/s)", 0.1, 400_000.0, 1000.0, step=10.0,
                                            help="Provided by you; it is shown as a configured value, never as measured.")
            if c2.button("Start from the four-class template", help="Critical / interactive / standard / background. "
                         "The shares are suggestions to edit, not standards."):
                st.session_state["policy_template"] = bandwidth_service.template_policy(capacity_mbps * 1e6)
            editing = st.session_state.get("policy_template")
        rows = [{"traffic_class": c.traffic_class, "minimum_mbps": c.minimum_bps / 1e6, "maximum_mbps": c.maximum_bps / 1e6,
                 "priority_weight": c.priority_weight, "dscp": c.dscp, "enabled": c.enabled}
                for c in (editing.classes if editing else [])] or [
            {"traffic_class": "", "minimum_mbps": 0.0, "maximum_mbps": 0.0, "priority_weight": 1.0, "dscp": None,
             "enabled": True}]
        with st.form("policy_form", border=True):
            c1, c2, c3 = st.columns(3)
            name = c1.text_input("Policy name", value=(editing.name if editing else ""), max_chars=60,
                                 disabled=not can_configure)
            interface = c2.text_input("Interface (optional)", value=(editing.interface_name or "") if editing else "",
                                      max_chars=64, disabled=not can_configure,
                                      help="Links this policy to telemetry and forecasts for that interface.")
            capacity = c3.number_input("Capacity (Mbit/s)", 0.1, 400_000.0,
                                       float(editing.capacity_bps / 1e6) if editing else 1000.0, step=10.0,
                                       disabled=not can_configure)
            table = st.data_editor(
                pd.DataFrame(rows), num_rows="dynamic" if can_configure else "fixed", hide_index=True,
                disabled=not can_configure, key=f"classes_{choice}",
                column_config={
                    "traffic_class": st.column_config.TextColumn("Traffic class", required=True, max_chars=40),
                    "minimum_mbps": st.column_config.NumberColumn("Minimum (Mbit/s)", min_value=0.0, format="%.2f"),
                    "maximum_mbps": st.column_config.NumberColumn("Maximum (Mbit/s)", min_value=0.0, format="%.2f"),
                    "priority_weight": st.column_config.NumberColumn("Priority weight", min_value=0.01, format="%.2f"),
                    "dscp": st.column_config.NumberColumn("DSCP (optional)", min_value=0, max_value=63, step=1,
                                                          help="Only used to classify packets if enforcement is enabled."),
                    "enabled": st.column_config.CheckboxColumn("Enabled"),
                },
            )
            c1, c2 = st.columns([1, 1])
            save = c1.form_submit_button("Save policy", type="primary", disabled=not can_configure)
            remove = c2.form_submit_button("Delete policy", disabled=not can_configure or choice not in by_name)
        if not can_configure:
            st.caption("Only administrators can change policies.")
        if save:
            try:
                bandwidth_service.save_policy(principal, bandwidth_service.policy_from_entries(
                    name, interface or None, capacity * 1e6, table.to_dict("records")))
            except (BandwidthError, PermissionDenied) as exc:
                st.error(str(exc))
            else:
                st.session_state.pop("policy_template", None)
                st.toast(f"Policy '{name}' saved.")
                st.rerun()
        if remove:
            try:
                bandwidth_service.delete_policy(principal, choice)
            except (BandwidthError, PermissionDenied) as exc:
                st.error(str(exc))
            else:
                st.rerun()

# ----------------------------------------------------------------- recommend
with recommend_tab:
    if not policies:
        st.info("Create a policy first.")
    elif not can_recommend:
        st.info("Your role cannot generate recommendations.")
    else:
        by_name = {p.name: p for p in policies}
        policy = by_name[st.selectbox("Policy", list(by_name), key="recommend_policy")]
        enabled = [c for c in policy.classes if c.enabled]
        c1, c2 = st.columns(2)
        with c1:
            kpi_tile("Configured capacity", format_bits_rate(policy.capacity_bps), "configured",
                     policy.interface_name or "No interface linked")
        mode = c2.radio("Demand estimate", list(bandwidth_service.DEMAND_MODES),
                        format_func={"manual": "Enter per class", "measured": "Scale to latest measured throughput",
                                     "forecast": "Scale to latest PredictNet forecast"}.get,
                        captions=["Labelled configured (your estimate)", "Labelled derived from measurement",
                                  "Labelled derived from forecast"])
        session_id = None
        if mode == "measured":
            sessions = [s for s in monitoring_service.list_sessions(principal) if s.metric_count]
            if sessions:
                sid = {s.id: s for s in sessions}
                session_id = st.selectbox("Telemetry session", list(sid),
                                          format_func=lambda i: f"#{i} · {sid[i].configuration.get('filename', '')}")
            else:
                st.warning("No telemetry sessions exist.")
        st.caption("Per-class demand is not measured by any data source yet. In the scaled modes your entries set the "
                   "split between classes and the total comes from measurement or forecast.")
        with st.form("recommend_form", border=True):
            label = "Demand (Mbit/s)" if mode == "manual" else "Relative demand (any unit)"
            demand_table = st.data_editor(
                pd.DataFrame([{"traffic_class": c.traffic_class, "demand": 0.0} for c in enabled]),
                hide_index=True, disabled=["traffic_class"], key=f"demand_{policy.name}_{mode}",
                column_config={"traffic_class": "Traffic class",
                               "demand": st.column_config.NumberColumn(label, min_value=0.0, format="%.2f")},
            )
            margin = st.slider("Safety margin (% of capacity kept free)", 0, 50, 10)
            generate = st.form_submit_button("Generate recommendation", type="primary", icon=":material/tune:")
        if generate:
            scale = 1e6 if mode == "manual" else 1.0
            demand = {r["traffic_class"]: float(r["demand"] or 0) * scale for r in demand_table.to_dict("records")}
            try:
                rec = bandwidth_service.recommend(principal, policy.name, demand, safety_margin=margin / 100,
                                                  demand_mode=mode, session_id=session_id)
            except (BandwidthError, PermissionDenied) as exc:
                st.error(str(exc))
            else:
                result = rec.result
                st.success(f"Recommendation #{rec.id} saved as *proposed*. Demand estimate: **{rec.demand_provenance}**.")
                c1, c2, c3, c4 = st.columns(4)
                with c1:
                    kpi_tile("Usable capacity", format_bits_rate(result.usable_bps), "derived",
                             f"after a {result.safety_margin:.0%} safety margin")
                with c2:
                    kpi_tile("Recommended total", format_bits_rate(result.total_allocated_bps), "derived")
                with c3:
                    kpi_tile("Estimated demand", format_bits_rate(result.total_demand_bps),
                             "configured" if mode == "manual" else "derived")
                with c4:
                    kpi_tile("Unmet demand", format_bits_rate(result.unmet_demand_bps), "derived",
                             "Reported, never hidden" if result.unmet_demand_bps else "All demand fits")
                section_label("How the capacity was shared (water-filling)")
                waterfill.render(result)
                st.caption("Each tank is as tall as the class maximum or demand. Minimums are reserved first; then the "
                           "leftover is shared by weight, and classes that need little fill up first.")
                fig = go.Figure()
                names = [a.name for a in result.allocations]
                fig.add_trace(go.Bar(name="Recommended", x=names, y=[a.allocated_bps for a in result.allocations],
                                     marker_color=COLORS["accent"]))
                fig.add_trace(go.Bar(name="Estimated demand", x=names, y=[a.demand_bps for a in result.allocations],
                                     marker_color=COLORS["muted"]))
                fig.add_trace(go.Scatter(name="Maximum", x=names, y=[a.maximum_bps for a in result.allocations],
                                         mode="markers", marker=dict(symbol="line-ew-open", size=28, color=COLORS["warn"])))
                fig.add_trace(go.Scatter(name="Minimum", x=names, y=[a.minimum_bps for a in result.allocations],
                                         mode="markers", marker=dict(symbol="line-ew-open", size=28, color=COLORS["ok"])))
                fig.update_layout(title="Recommended allocation per class", barmode="group", yaxis_title="bit/s")
                st.plotly_chart(apply_chart_theme(fig, height=360), theme=None)
                st.dataframe(pd.DataFrame([{
                    "Class": a.name, "Weight": a.priority_weight, "Minimum": format_bits_rate(a.minimum_bps),
                    "Maximum": format_bits_rate(a.maximum_bps), "Demand": format_bits_rate(a.demand_bps),
                    "Recommended": format_bits_rate(a.allocated_bps), "Unmet": format_bits_rate(a.unmet_demand_bps),
                    "Limited by": a.limited_by} for a in result.allocations]), hide_index=True)
                left, right = st.columns(2)
                with left:
                    section_label("Why")
                    st.markdown("\n".join(f"- {line}" for line in result.rationale))
                with right:
                    section_label("Expected effect")
                    st.markdown("\n".join(f"- {line}" for line in rec.expected_effect))
                    section_label("Constraint checks")
                    st.markdown("\n".join(f"- {'✅' if ok else '❌'} {name}" for name, ok in result.invariants.items()))
                if rec.demand_context.get("throughput_bps"):
                    st.caption(f"Total demand source: {format_bits_rate(rec.demand_context['throughput_bps'])} "
                               f"({rec.demand_provenance}, {rec.demand_context.get('basis', 'latest measurement')}, "
                               f"{format_timestamp(rec.demand_context.get('timestamp'))}).")

# ------------------------------------------------------------------- history
with history_tab:
    history = bandwidth_service.list_recommendations(principal)
    if not history:
        st.info("No recommendations yet.")
    else:
        st.dataframe(pd.DataFrame([{
            "ID": h["id"], "When": format_timestamp(h["timestamp"]), "Policy": h["payload"]["policy_name"],
            "Interface": h["interface_name"] or "—", "Capacity": format_bits_rate(h["capacity_bps"]),
            "Demand estimate": h["payload"]["demand_provenance"], "Unmet": format_bits_rate(h["unmet_demand_bps"]),
            "Status": h["status"], "By": h["created_by_email"] or "—"} for h in history]), hide_index=True)
        if can_enforce:
            reviewable = {h["id"]: h for h in history if h["status"] == "proposed"}
            if reviewable:
                with st.form("review_form", border=True):
                    rid = st.selectbox("Review proposal", list(reviewable),
                                       format_func=lambda i: f"#{i} · {reviewable[i]['payload']['policy_name']}")
                    decision = st.radio("Decision", ["accepted", "rejected"], horizontal=True)
                    st.caption("Accepting only marks the recommendation as approved. It changes nothing on the network.")
                    if st.form_submit_button("Save decision", type="primary"):
                        try:
                            bandwidth_service.set_recommendation_status(principal, rid, decision)
                        except (BandwidthError, PermissionDenied) as exc:
                            st.error(str(exc))
                        else:
                            st.rerun()

# --------------------------------------------------------------- enforcement
with enforce_tab:
    state = traffic_shaping_service.availability()
    if not state.available:
        st.warning("**Enforcement is not available on this server**, so recommendations stay advisory:\n\n"
                   + "\n".join(f"- {r}" for r in state.reasons))
        with st.expander("How to set up a supported test environment"):
            st.markdown("""
1. Use an **isolated Linux lab** (a VM or a spare box). Never use a production link.
2. Run Smart Shield with permission to manage queueing (`CAP_NET_ADMIN` or root), and check that `tc` is installed (`iproute2`).
3. In `.env`, set `SMART_SHIELD_TC_ENABLED=true` and `SMART_SHIELD_TC_INTERFACES=<lab interface>`, then restart the app.
4. Mark traffic with DSCP values that match your policy's classes. Unmatched traffic goes to a default class.
5. Apply an **accepted** recommendation here. Use *Rollback* to restore the previous state, or *Emergency disable* to remove shaping entirely.

Recovery without the app: `sudo tc qdisc del dev <interface> root` removes everything Smart Shield configured.
""")
    if not can_enforce:
        st.caption("Only administrators can enforce policies.")
    elif state.available:
        accepted = [h for h in bandwidth_service.list_recommendations(principal) if h["status"] == "accepted"]
        interface = st.selectbox("Interface (allow-listed)", list(state.interfaces))
        try:
            st.code(traffic_shaping_service.current_state(principal, interface), language="text")
        except ShapingError as exc:
            st.caption(f"Current state unavailable: {exc}")
        if accepted:
            by_id = {h["id"]: h for h in accepted}
            rid = st.selectbox("Accepted recommendation", list(by_id),
                               format_func=lambda i: f"#{i} · {by_id[i]['payload']['policy_name']}")
            try:
                commands = traffic_shaping_service.preview_apply(principal, rid, interface)
                st.markdown("**Exactly these commands will run** (fixed operations, no shell):")
                st.code("\n".join(" ".join(c) for c in commands), language="bash")
            except ShapingError as exc:
                st.error(str(exc))
            with st.form("apply_form", border=True):
                confirm = st.text_input(f"Type `{interface}` to confirm applying recommendation #{rid}")
                if st.form_submit_button("Apply policy", type="primary"):
                    try:
                        traffic_shaping_service.apply_recommendation(principal, rid, interface, confirm_interface=confirm)
                    except (ShapingError, PermissionDenied) as exc:
                        st.error(str(exc))
                    else:
                        st.success("Applied. The previous state was recorded for rollback.")
        else:
            st.info("Accept a recommendation in History before it can be applied.")
        with st.form("rollback_form", border=True):
            confirm_rb = st.text_input(f"Type `{interface}` to roll back to the previous state")
            if st.form_submit_button("Roll back"):
                try:
                    traffic_shaping_service.rollback(principal, interface, confirm_interface=confirm_rb)
                except (ShapingError, PermissionDenied) as exc:
                    st.error(str(exc))
                else:
                    st.success("Rolled back.")
        if st.button("Emergency disable: remove shaping from all allow-listed interfaces", type="secondary"):
            try:
                traffic_shaping_service.emergency_disable(principal)
            except (ShapingError, PermissionDenied) as exc:
                st.error(str(exc))
            else:
                st.success("Shaping removed.")
    actions = traffic_shaping_service.action_history(principal)
    section_label("Policy action history")
    if actions:
        st.dataframe(pd.DataFrame([{
            "When": format_timestamp(a["executed_at"]), "Action": a["action_type"], "Interface": a["target_interface"],
            "Recommendation": a["recommendation_id"] or "—", "Status": a["status"], "By": a["executed_by_email"] or "—",
            "Error": a["error_message"] or ""} for a in actions]), hide_index=True)
    else:
        st.caption("No enforcement actions have been taken.")
