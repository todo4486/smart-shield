"""How Smart Shield responded: an animated before and after, and the full record of each action.

Every figure comes from samples stored before and after the action. A figure that was not stored is shown as Unavailable,
and a check that has not run yet says so. Nothing here is estimated to fill a gap. Simulated actions are labelled.
"""
from __future__ import annotations

import math
from html import escape
from typing import Any, Dict, List, Mapping, Optional, Sequence

import pandas as pd
import streamlit as st

from components import mitigation_panel
from components.mitigation_panel import RECOVERY_LABELS
from components.theme import COLORS
from components.ui import format_bits_rate, format_timestamp, kpi_tile, provenance_chip, section_label
from services import enforcement_service, mitigation_service
from services.authorization import Principal

CLASS_LABELS = {"critical": "Critical applications", "normal": "Normal users", "suspicious": "Suspicious hosts",
                "restricted": "Restricted traffic"}
ACTION_LABELS = {"rate_limit": "Rate limit", "prioritize": "Traffic prioritization", "block": "Temporary block", "isolate": "Host isolation"}
MAX_WIDTH = 12.0
FLOW_COLORS = {"target": COLORS["critical"], "legitimate": COLORS["ok"], "link": COLORS["accent"], "missing": COLORS["muted"]}


def _rate(value: Optional[float]) -> str:
    return format_bits_rate(value) or "Unavailable"


def _width(value: float, top: float) -> float:
    return 1.5 + (MAX_WIDTH - 1.5) * math.sqrt(value / top) if top > 0 else 1.5


def _flow(x1: int, y1: int, x2: int, y2: int, value: Optional[float], top: float, kind: str) -> str:
    """A line as wide as its rate. Moving dots mean traffic is passing; a missing or zero rate gets no motion."""
    if value is None or value <= 0:
        return (f"<line x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}' stroke='{FLOW_COLORS['missing']}' stroke-width='1.5' "
                "stroke-dasharray='2 6' opacity='.6'/>")
    color, width = FLOW_COLORS[kind], _width(value, top)
    return (f"<line x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}' stroke='{color}' stroke-width='{width:.1f}' opacity='.28'/>"
            f"<line class='ss-net-flow' x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}' stroke='{color}' stroke-width='{max(2.0, width / 3):.1f}'/>")


def _node(x: int, y: int, label: str, sub: str = "", anchor: str = "start") -> str:
    """Labels start at the node's left edge (or end at its right), so they never run off the picture."""
    edge = x - 9 if anchor == "start" else x + 9
    return (f"<circle cx='{x}' cy='{y}' r='9' fill='{COLORS['card']}' stroke='{COLORS['muted']}' stroke-width='1.5'/>"
            f"<text x='{edge}' y='{y - 15}' text-anchor='{anchor}' font-size='12' fill='var(--ss-text)'>{escape(label)}</text>"
            + (f"<text x='{edge}' y='{y + 24}' text-anchor='{anchor}' font-size='12' fill='var(--ss-muted)'>{escape(sub)}</text>" if sub else ""))


def scene(title: str, condition: Optional[Mapping[str, Any]], target_label: str, top: float, marker: str = "") -> str:
    """Suspicious traffic and legitimate traffic passing the controller onto the link."""
    condition = condition or {}
    target, other = condition.get("target_bps"), condition.get("other_bps")
    label = escape(f"{title} · {condition.get('samples', 0) or 0} sample(s)")
    return (
        f"<svg class='ss-net-scene' viewBox='0 0 320 185' role='img' aria-label='{label}: suspicious {escape(_rate(target))}, "
        f"legitimate {escape(_rate(other))}'>"
        f"<text x='0' y='13' font-size='13' font-weight='600' fill='var(--ss-text)'>{escape(title)}</text>"
        + _flow(20, 55, 160, 100, target, top, "target") + _flow(20, 145, 160, 100, other, top, "legitimate")
        + _flow(160, 100, 300, 100, None if target is None and other is None else (target or 0) + (other or 0), top, "link")
        + _node(20, 55, target_label, _rate(target)) + _node(20, 145, "Legitimate traffic", _rate(other))
        + f"<rect x='145' y='84' width='30' height='32' rx='6' fill='{COLORS['card']}' stroke='{COLORS['accent']}' stroke-width='1.5'/>"
        + "<text x='160' y='78' text-anchor='middle' font-size='11' fill='var(--ss-muted)'>Controller</text>"
        + marker + _node(300, 100, "Link", _rate(condition.get("throughput_bps")), anchor="end") + "</svg>")


def _marker(m: Mapping[str, Any]) -> str:
    """What the action does, drawn on the controller."""
    text = {"rate_limit": f"≤ {_rate(m['limit_bps'])}", "block": "blocked", "isolate": "isolated"}.get(m["action_type"], "by class")
    return (f"<text x='160' y='104' text-anchor='middle' font-size='11' fill='{COLORS['critical']}'>■</text>"
            f"<text x='160' y='132' text-anchor='middle' font-size='11' fill='var(--ss-text)'>{escape(text)}</text>")


def render_comparison(principal: Principal, m: Dict[str, Any]) -> None:
    simulated = m["origin"] == "simulation"
    dry_run = m["adapter"] == enforcement_service.DRY_RUN
    if dry_run:
        st.info("Dry run: nothing on the network was changed, so there is no after to compare.", icon=":material/science:")
    before, after = m["before"] or {}, m["after"] or {}
    who = f"Source {m['target']}" if m["target_kind"] == "source" else f"To {m['target']}" if m["target_kind"] == "destination" else "All senders"
    values = [before.get(k) or 0 for k in ("throughput_bps", "target_bps", "other_bps")] + [after.get(k) or 0 for k in ("throughput_bps", "target_bps", "other_bps")]
    top = max(values) if values else 0
    left, right = st.columns(2)
    with left:
        st.markdown(scene("Before", before, who, top), unsafe_allow_html=True)
    with right:
        if after.get("samples"):
            st.markdown(scene("After", after, who, top, _marker(m)), unsafe_allow_html=True)
        elif dry_run:
            st.caption("No after: this was a dry run.")
        elif m["recovery_status"] == "pending":
            st.caption(f"The action is in force. The after picture appears once samples have been stored, about "
                       f"{mitigation_service.VERIFY_AFTER_SECONDS} seconds after it was applied.")
        else:
            st.caption("No samples were stored after this action, so there is no after picture.")
    st.markdown(provenance_chip("simulated" if simulated else "measured")
                + (" <span style='color:var(--ss-muted);font-size:.8rem'>Calculated by the simulated link. No packets exist.</span>"
                   if simulated else " <span style='color:var(--ss-muted);font-size:.8rem'>From stored samples of this capture.</span>"),
                unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    with c1:
        kpi_tile("Limit", {"rate_limit": _rate(m["limit_bps"]), "block": "Blocked", "isolate": "Isolated"}.get(m["action_type"], "By class"),
                 "configured", "previously no limit")
    with c2:
        if m["adapter"] == "simulated-link":
            kpi_tile("Execution time", None, "unavailable", "no command runs: effective from the next interval")
        elif dry_run:
            kpi_tile("Execution time", None, "unavailable", "dry run, nothing ran")
        else:
            kpi_tile("Execution time", f"{m['execution_ms'] or 0:,.1f} ms", "measured", f"{m['adapter']} on {m['interface_name']}")
    with c3:
        kpi_tile("Recovery", RECOVERY_LABELS.get(m["recovery_status"], m["recovery_status"]), "derived",
                 "from samples after the action")
    if m["recovery_note"]:
        st.markdown(m["recovery_note"])
    if before.get("samples"):
        st.dataframe(mitigation_panel.compare_rows(before, after, m["target_kind"]), hide_index=True, width="stretch")
    rows = _allocation_rows(m)
    if rows:
        section_label("Allocation")
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
        st.caption("The engine's plan just before the action, and what the same demand gets with it.")


def _allocation_rows(m: Mapping[str, Any]) -> List[Dict[str, str]]:
    previous, new = m["previous_allocation"] or {}, m["new_allocation"] or {}
    if not previous:
        return []
    rows = []
    for name, label in CLASS_LABELS.items():
        was = (previous.get("classes") or {}).get(name)
        now = (new.get("classes") or {}).get(name)
        rows.append({"Class": label, "Before": _rate(None if was is None else float(was["allocated_bps"])),
                     "After": _rate(None if now is None else float(now["allocated_bps"]))})
    rows.append({"Class": "Available", "Before": _rate(previous.get("available_bps")), "After": _rate(new.get("available_bps"))})
    return rows


def _panel(principal: Principal) -> None:
    actions = mitigation_service.list_recent_applied(principal)
    if not actions:
        st.caption("No action has been applied yet. Run a scenario in Monitor → Simulation and approve what the engine proposes, "
                   "or approve one on a live capture. This page never shows example figures.")
        st.page_link("views/simulation.py", label="Open Simulation", icon=":material/experiment:")
        return
    by_id = {m["id"]: m for m in actions}
    chosen = st.selectbox("Action", list(by_id), key="attack_response_action",
                          format_func=lambda i: f"#{i} · {by_id[i]['description']} · {by_id[i]['status'].replace('_', ' ')}"
                          + (" · simulated" if by_id[i]["origin"] == "simulation" else ""))
    render_comparison(principal, by_id[chosen])


def render(principal: Principal) -> None:
    pending = any(m["recovery_status"] == "pending" or m["status"] == "active" for m in mitigation_service.list_recent_applied(principal))
    st.fragment(_panel, run_every=2 if pending else None)(principal)


def _record(m: Mapping[str, Any], models: Sequence[str]) -> pd.DataFrame:
    confidence = "Unavailable" if m["confidence"] is None else (
        f"{m['confidence']:.2f} ({'tree votes' if m['confidence_basis'] == 'classifier_votes' else 'share of flows flagged'}, not a probability)")
    rows = [("Detected", format_timestamp(m["created_at"])), ("Source IP", m["source_ip"] or "Several or unknown"),
            ("Destination IP", m["destination_ip"] or "Unknown"), ("Attack category", m["category"] or "None: an administrator's decision"),
            ("Model prediction", ", ".join(models) if m["category"] and models else "Unavailable"), ("Confidence", confidence),
            ("Traffic volume", _rate(m["traffic_bps"])), ("Severity", m["severity"] or "Unavailable"),
            ("Mitigation action", f"{ACTION_LABELS[m['action_type']]}: {m['description']}"),
            ("Mitigation status", m["status"].replace("_", " ")), ("Who decided", "The engine" if m["decided_by"] is None and m["decided_at"] else "An administrator" if m["decided_at"] else "Nobody yet"),
            ("Reason", m["reason"]), ("Recovery verification", RECOVERY_LABELS.get(m["recovery_status"], m["recovery_status"]))]
    if m["end_reason"]:
        rows.append(("How it ended", m["end_reason"]))
    if m["failure_reason"]:
        rows.append(("Failure", m["failure_reason"]))
    return pd.DataFrame(rows, columns=["", "Value"])


def render_incident(principal: Principal, incident_id: int, alerts: Sequence[Any]) -> None:
    """Refreshes itself only while something can change by itself: a recovery check, or an action ending."""
    actions = mitigation_service.list_for_incident(principal, incident_id)
    section_label("Mitigation")
    if not actions:
        st.caption("No mitigation has been proposed or applied for this incident.")
        return
    changing = any(m["status"] in ("active", "proposed") for m in actions)
    st.fragment(_incident_actions, run_every=2 if changing else None)(principal, incident_id, alerts)


def _incident_actions(principal: Principal, incident_id: int, alerts: Sequence[Any]) -> None:
    """Each action on this incident, with its record, its decision or reversal, and its before and after."""
    actions = mitigation_service.list_for_incident(principal, incident_id)
    models = sorted({f"{a.category} ({a.model_version})" for a in alerts if a.model_version})
    for m in actions:
        if m["status"] == "proposed":
            mitigation_panel.render_proposal(principal, m)
        else:
            mitigation_panel.render_action(principal, m, key_prefix="incident")
        with st.expander(f"Full record of action #{m['id']}"):
            st.dataframe(_record(m, models), hide_index=True, width="stretch")
            if m["applied_at"]:
                render_comparison(principal, m)
