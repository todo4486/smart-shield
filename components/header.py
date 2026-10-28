"""Header strip on every page: health ring, live counters, data-source badge, incident toasts.

It runs as a fragment that refreshes on its own every few seconds, so the rest of the page
never reruns (no flicker, scroll position and selections are kept).
"""
from __future__ import annotations

from html import escape

import streamlit as st

from components import severity
from components.ui import format_ratio, format_timestamp, source_badge
from services import header_service, live_monitor_service
from services.authorization import Principal

REFRESH_SECONDS = 10
LAST_TOAST_KEY = "header_last_incident_toasted"
RING_COLORS = {"ok": "#22C55E", "warn": "#F59E0B", "critical": "#EF4444", "unavailable": "#8B97AD"}
RING_WORDS = {"ok": "Healthy", "warn": "Degraded", "critical": "At risk", "unavailable": "No data yet"}


def _ring(score, level: str) -> str:
    radius, circumference = 15.5, 97.39
    filled = 0 if score is None else circumference * score / 100
    color = RING_COLORS[level]
    value = "—" if score is None else str(score)
    tooltip = ("Health score: 100 minus open critical (−25 each, max −50), high (−10, max −30) and medium (−3, max −15) "
               "alerts, minus a penalty for the most utilized link (critical −25, high −15, elevated −5), "
               "minus 10 if monitoring is in error.")
    return (f"<div class='ss-strip-cell ss-ring' title='{escape(tooltip)}'>"
            f"<svg width='40' height='40' viewBox='0 0 40 40' role='img' aria-label='Network health {escape(value)}'>"
            f"<circle cx='20' cy='20' r='{radius}' fill='none' stroke='var(--ss-border)' stroke-width='4'/>"
            f"<circle cx='20' cy='20' r='{radius}' fill='none' stroke='{color}' stroke-width='4' stroke-linecap='round' "
            f"stroke-dasharray='{circumference}' stroke-dashoffset='{circumference - filled:.2f}' "
            f"transform='rotate(-90 20 20)'/>"
            f"<text x='20' y='24' text-anchor='middle' font-size='11' font-weight='700' fill='var(--ss-text)' "
            f"font-family='JetBrains Mono, monospace'>{escape(value)}</text></svg>"
            f"<div class='ss-ring-text'><b>{RING_WORDS[level]}</b><span>Network health</span></div></div>")


def _cell(label: str, value, title: str = "") -> str:
    if value is None:
        body = "<div class='ss-strip-value ss-na'>Unavailable</div>"
    else:
        body = f"<div class='ss-strip-value'>{value}</div>"
    return (f"<div class='ss-strip-cell' title='{escape(title)}'><div class='ss-strip-label'>{escape(label)}</div>"
            f"{body}</div>")


def _strip_html(data: header_service.HeaderData) -> str:
    flows = None if data.flows_per_second is None else escape(f"{data.flows_per_second:,.1f}")
    flows_title = ("Flows finished per second over the last minute (live packet capture)."
                   if flows is not None else "Needs live packet capture.")
    incidents = escape(str(data.active_incidents))
    if data.top_incident_severity:
        incidents += " " + severity.badge(data.top_incident_severity)
    link = None
    if data.top_link_utilization is not None:
        link = (f"{escape(format_ratio(data.top_link_utilization))} "
                f"<span style='font-size:.7rem;color:var(--ss-muted)'>{escape(data.top_link or '')}</span>")
    link_title = (f"Highest latest stored utilization, as of {format_timestamp(data.top_link_as_of)}."
                  if data.top_link_as_of else "No link with a configured capacity has utilization data.")
    if data.models_active:
        mark = "✓" if data.models_verified == data.models_active else "✗"
        models = escape(f"{data.models_active}/{data.models_total_families} {mark}")
        models_title = (f"{data.models_verified} of {data.models_active} active models match their registered "
                        "SHA-256.")
    else:
        models, models_title = None, "No active models. Train and activate one in the ML Laboratory."
    source = (f"<div class='ss-strip-cell' title='{escape(data.source.description)}'>"
              f"<div class='ss-strip-label'>Data source</div><div>{source_badge(data.source)}</div></div>")
    return ("<div class='ss-strip'>" + _ring(data.health, data.health_level)
            + _cell("Flows / sec", flows, flows_title)
            + _cell("Active incidents", incidents, "Open or investigating incidents and their most severe alert.")
            + _cell("Highest link risk", link, link_title)
            + _cell("Models loaded", models, models_title)
            + source + "</div>")


def _toast_new_incidents(data: header_service.HeaderData) -> None:
    last_seen = st.session_state.get(LAST_TOAST_KEY)
    newest = max((i.id for i in data.incidents), default=None)
    if last_seen is None:
        # First render in this tab: remember where we are, don't replay old incidents as new.
        st.session_state[LAST_TOAST_KEY] = newest or 0
        return
    for incident in header_service.new_high_incidents(data.incidents, last_seen):
        icon = ":material/crisis_alert:" if incident.severity == "critical" else ":material/warning:"
        st.toast(f"{severity.plain(incident.severity)} incident #{incident.id}: {incident.title}", icon=icon)
    if newest is not None and newest > last_seen:
        st.session_state[LAST_TOAST_KEY] = newest


@st.fragment(run_every=REFRESH_SECONDS)
def render_header(principal: Principal) -> None:
    status = live_monitor_service.get_monitor().status
    data = header_service.get_header(principal, live_running=status.running, live_mode=status.mode,
                                     live_session_id=status.session_id)
    if data.source.kind == "replay":
        st.markdown("<div class='ss-banner-replay'>▶ DATASET REPLAY · recorded, labelled data is being replayed. "
                    "Nothing on screen is live traffic.</div>", unsafe_allow_html=True)
    st.markdown(_strip_html(data), unsafe_allow_html=True)
    _toast_new_incidents(data)
