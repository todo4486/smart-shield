"""The mitigation engine for one session: policy level, current allocation, decisions, and before and after."""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, Mapping, Optional

import pandas as pd
import streamlit as st

from components.ui import format_bits_rate, format_ratio, format_timestamp, kpi_tile, provenance_chip, section_label
from services import mitigation_service, settings_service
from services.authorization import Permission, PermissionDenied, Principal
from services.mitigation_service import MitigationError
from services.settings_service import MITIGATION_POLICIES, SettingsError

POLICY_LABELS = {"off": "Off", "recommend": "Recommend", "auto_rate_limit": "Auto rate-limit"}
POLICY_HELP = {
    "off": "The engine proposes and applies nothing. You can still act by yourself.",
    "recommend": "The engine proposes actions and an administrator decides each one.",
    "auto_rate_limit": "The engine may apply a rate limit by itself when confidence, severity, repetition and "
                       "false-positive risk all qualify. It always expires. Blocking and isolation still need an administrator.",
}
CLASS_LABELS = {"critical": "Critical", "normal": "Normal", "suspicious": "Suspicious", "restricted": "Restricted"}
RECOVERY_LABELS = {"pending": "Checking…", "recovered": "Recovered", "partial": "Partly recovered",
                   "not_recovered": "Not recovered", "unavailable": "Unavailable", "not_applied": "Not applied"}


def render_policy(principal: Principal) -> None:
    settings = settings_service.get_mitigation_settings()
    if not principal.has(Permission.MANAGE_SETTINGS):
        st.markdown(f"Mitigation policy: **{POLICY_LABELS[settings.policy]}**. {POLICY_HELP[settings.policy]} "
                    "Only an administrator can change it.")
        return
    chosen = st.radio("Mitigation policy", MITIGATION_POLICIES, index=MITIGATION_POLICIES.index(settings.policy),
                      format_func=POLICY_LABELS.get, horizontal=True, key="mitigation_policy")
    st.caption(POLICY_HELP[chosen])
    if chosen != settings.policy:
        try:
            settings_service.update_mitigation_settings(principal, replace(settings, policy=chosen))
        except (SettingsError, PermissionDenied) as exc:
            st.error(str(exc))
        else:
            st.toast(f"Mitigation policy: {POLICY_LABELS[chosen]}")


def _allocation_rows(allocation: Mapping[str, Any]) -> pd.DataFrame:
    return pd.DataFrame([{
        "Class": CLASS_LABELS[name], "Wants": format_bits_rate(grant["demand_bps"]),
        "Allocated": format_bits_rate(float(grant["allocated_bps"])), "Unmet": format_bits_rate(float(grant["unmet_bps"])),
    } for name, grant in allocation["classes"].items()])


def _render_allocation(principal: Principal, session_id: int) -> None:
    allocation = mitigation_service.latest_allocation(principal, session_id)
    if allocation is None:
        st.caption("No allocation has been calculated for this session yet.")
        return
    state = ("Limits are being enforced on this simulated link." if allocation["enforced"]
             else "Calculated only: no mitigation is active, so the link is still a plain shared queue.")
    st.caption(f"{state} Available: {format_bits_rate(allocation['available_bps'])} of "
               f"{format_bits_rate(allocation['capacity_bps'])}.")
    st.dataframe(_allocation_rows(allocation), hide_index=True, width="stretch")


def _evidence(m: Mapping[str, Any]) -> str:
    if m["confidence"] is None:
        return "Requested by an administrator."
    basis = "tree votes" if m["confidence_basis"] == "classifier_votes" else "share of flows flagged"
    parts = [f"**{m['category']}**", f"severity {m['severity']}", f"confidence {m['confidence']:.2f} ({basis}, not a probability)",
             f"seen in {m['repetition']} window(s)", f"false-positive risk {m['false_positive_risk']:.2f} (heuristic)"]
    if m["traffic_bps"] is not None:
        parts.append(f"using {format_bits_rate(m['traffic_bps'])}")
    return " · ".join(parts)


def _render_proposal(principal: Principal, m: Dict[str, Any]) -> None:
    with st.container(border=True):
        st.markdown(f"**#{m['id']} · {m['description'].capitalize()}**")
        st.caption(_evidence(m))
        if m["upstream_required"]:
            st.warning("A flood from outside fills the link before it reaches this controller. This can contain it, but "
                       "the link only recovers if it is filtered upstream (ISP or scrubbing service).")
        if not principal.has(Permission.APPLY_TRAFFIC_POLICY):
            st.caption("Only an administrator can decide this.")
            return
        high_impact = m["action_type"] in mitigation_service.HIGH_IMPACT
        reason = st.text_input("Reason", key=f"mitigation_reason_{m['id']}", placeholder="Why, at least 5 characters")
        confirm = st.text_input(f"Type {m['target']} to confirm", key=f"mitigation_confirm_{m['id']}") if high_impact else None
        c1, c2 = st.columns(2)
        if c1.button("Approve", key=f"mitigation_approve_{m['id']}", type="primary"):
            _attempt(mitigation_service.approve, principal, m["id"], reason=reason, confirm_target=confirm)
        if c2.button("Reject", key=f"mitigation_reject_{m['id']}"):
            _attempt(mitigation_service.reject, principal, m["id"], reason=reason)


def _attempt(function, *args, **kwargs) -> None:
    try:
        result = function(*args, **kwargs)
    except (MitigationError, PermissionDenied) as exc:
        st.error(str(exc))
        return
    if isinstance(result, dict) and result.get("status") == "failed":
        st.error(f"It could not be applied: {result['failure_reason']}")
        return
    st.rerun()


def _compare_rows(before: Optional[Mapping[str, Any]], after: Optional[Mapping[str, Any]], target_kind: str) -> pd.DataFrame:
    before, after = before or {}, after or {}
    bits = format_bits_rate

    def cell(value: Optional[str]) -> str:
        return value if value is not None else "Unavailable"

    rows = [("Carried by the link", bits(before.get("throughput_bps")), bits(after.get("throughput_bps"))),
            ("Link utilization", format_ratio(before.get("utilization")), format_ratio(after.get("utilization"))),
            ("Dropped by the link", format_ratio(before.get("loss_ratio")), format_ratio(after.get("loss_ratio"))),
            ("Other traffic delivered", bits(before.get("other_bps")), bits(after.get("other_bps")))]
    if target_kind != "link":
        rows.insert(0, ("Target's traffic", bits(before.get("target_bps")), bits(after.get("target_bps"))))
    latency = (before.get("latency_ms"), after.get("latency_ms"))
    rows.append(("Latency", *(f"{v:,.1f} ms" if v is not None else None for v in latency)))
    return pd.DataFrame([{"": label, "Before": cell(b), "After": cell(a)} for label, b, a in rows])


def _render_action(principal: Principal, m: Dict[str, Any]) -> None:
    with st.container(border=True):
        who = "the engine" if m["decided_by"] is None and m["initiated_by"] == "engine" else "an administrator"
        st.markdown(f"**#{m['id']} · {m['description'].capitalize()}** · {m['status'].replace('_', ' ')}, by {who}")
        if m["status"] == "failed":
            st.error(m["failure_reason"] or "It could not be applied.")
            return
        # A simulated link has no command to time: the limit simply takes effect at the next interval.
        speed = "effective from the next interval" if m["adapter"] == "simulated-link" else f"in {m['execution_ms'] or 0:,.1f} ms"
        st.caption(f"{_evidence(m)}  \nApplied {format_timestamp(m['applied_at'])}, {speed} · "
                   f"expires {format_timestamp(m['expires_at'])} · recovery: **{RECOVERY_LABELS[m['recovery_status']]}**")
        if m["recovery_note"]:
            st.markdown(m["recovery_note"])
        if m["before"]:
            st.dataframe(_compare_rows(m["before"], m["after"], m["target_kind"]), hide_index=True, width="stretch")
        if m["status"] == "active" and principal.has(Permission.APPLY_TRAFFIC_POLICY):
            if st.button("Roll back", key=f"mitigation_rollback_{m['id']}", icon=":material/undo:"):
                _attempt(mitigation_service.rollback, principal, m["id"], reason="Rolled back from the dashboard")


def render_session(principal: Principal, session_id: int, *, provenance: str = "simulated") -> None:
    actions = mitigation_service.list_for_session(principal, session_id)
    proposed = [m for m in actions if m["status"] == "proposed"]
    active = [m for m in actions if m["status"] == "active"]
    done = [m for m in actions if m["status"] not in ("proposed", "active", "rejected") and m["applied_at"]]
    c1, c2, c3 = st.columns(3)
    with c1:
        kpi_tile("Waiting for a decision", f"{len(proposed):,}", "derived")
    with c2:
        kpi_tile("Active now", f"{len(active):,}", "derived")
    with c3:
        kpi_tile("Finished", f"{len(done):,}", "derived")
    section_label("Bandwidth allocation")
    st.markdown(provenance_chip(provenance), unsafe_allow_html=True)
    _render_allocation(principal, session_id)
    if proposed:
        section_label("Waiting for a decision")
        for m in proposed:
            _render_proposal(principal, m)
    if active:
        section_label("Active")
        for m in active:
            _render_action(principal, m)
    if done:
        section_label("Finished")
        for m in done[:5]:
            _render_action(principal, m)
    if not actions:
        st.caption("No action yet. Only flows the models flag start one: a busy link alone never does.")
