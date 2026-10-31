"""PredictNet's outlook for a link, and what it recommends doing before the link fills. Every figure here is a prediction."""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

import pandas as pd
import streamlit as st

from components.ui import format_bits_rate, format_ratio, format_timestamp, kpi_tile, section_label
from services import live_monitor_service, monitoring_service, preventive_service, settings_service, simulation_service, telemetry_view_service
from services.authorization import Permission, PermissionDenied, Principal
from services.preventive_service import Outlook, PreventiveError

CLASS_LABELS = {"critical": "Critical applications", "normal": "Normal users", "suspicious": "Suspicious hosts",
                "restricted": "Restricted traffic"}
STRENGTH = {"likely": "Likely", "possible": "Possible: only with typical forecast error"}
OUTLOOK_KEY = "preventive_outlook"


def _model_section(status) -> None:
    st.caption(f"Forecaster {status.version} · {status.target} · one sample every {status.interval_seconds} s. "
               "Validated means machine learning beat the simple baselines, on data it did not train on.")
    st.dataframe(pd.DataFrame([{
        "Horizon": f"{h.minutes} min", "Available": "Yes" if h.available else "No", "Uses": (h.chosen or "—").replace("_", " "),
        "Validated": "Yes" if h.validated else "No", "Why": h.why} for h in status.horizons]), hide_index=True, width="stretch")


def _choose_source(principal: Principal) -> tuple:
    sessions = [s for s in monitoring_service.list_sessions(principal) if s.metric_count]
    if not sessions:
        return None, None
    live = live_monitor_service.get_monitor().status
    simulation = simulation_service.status_copy()
    running = live.session_id if live.running else simulation.session_id if simulation.running else None
    by_id = {s.id: s for s in sessions}
    ids = list(by_id)
    c1, c2 = st.columns(2)
    session_id = c1.selectbox("Source", ids, index=ids.index(running) if running in by_id else 0, key="preventive_session",
                              format_func=lambda i: f"#{i} · {by_id[i].source_type.replace('_', ' ')} · {by_id[i].status.lower()}")
    interfaces = telemetry_view_service.session_interfaces(principal, session_id) or [""]
    interface = c2.selectbox("Interface", interfaces, key="preventive_interface", format_func=lambda i: i or "(unnamed)")
    return session_id, interface


def _tiles(outlook: Outlook) -> None:
    by_minutes = {f.horizon_seconds // 60: f for f in outlook.forecasts}
    columns = st.columns(len(preventive_service.WANTED_MINUTES))
    for column, minutes in zip(columns, preventive_service.WANTED_MINUTES):
        forecast = by_minutes.get(minutes)
        with column:
            if forecast is None:
                kpi_tile(f"In {minutes} min", None, "unavailable", "the model has no such horizon")
            else:
                value = format_ratio(forecast.predicted_utilization) or format_bits_rate(forecast.predicted_throughput_bps)
                kpi_tile(f"In {minutes} min", value, "predicted", f"{forecast.risk.level} risk · uses {forecast.model_kind.replace('_', ' ')}")


def _outlook_section(principal: Principal, session_id: int, interface: Optional[str]) -> None:
    can_run = principal.has(Permission.RUN_DETECTION)
    if st.button("Forecast now", icon=":material/query_stats:", disabled=not can_run, key="preventive_run",
                 help=None if can_run else "Your role cannot run forecasts."):
        st.session_state[OUTLOOK_KEY] = (session_id, interface, preventive_service.run(principal, session_id, interface))
    stored = st.session_state.get(OUTLOOK_KEY)
    if stored is None or stored[:2] != (session_id, interface):  # never show one source's forecast under another's name
        return
    outlook: Outlook = stored[2]
    if outlook.run is None:
        st.warning(outlook.reason)
        return
    _tiles(outlook)
    st.caption(f"From data up to {format_timestamp(outlook.run.base_time)}, which may not be now for a stored source. "
               f"Model {outlook.run.model_version}.")
    for warning in outlook.run.warnings:
        st.caption(warning)
    if not outlook.available:
        st.warning(outlook.reason)
    elif outlook.status == "clear":
        threshold = settings_service.get_mitigation_settings().preventive_threshold
        st.success(f"No forecast reaches {threshold:.0%}, so nothing is recommended.")


def _allocation_rows(m: Mapping[str, Any]) -> list:
    rows = []
    for name, label in CLASS_LABELS.items():
        now, then = (m["current_allocation"] or {}).get("classes", {}).get(name), m["projected_allocation"]["classes"][name]
        rows.append({"Class": label, "Plan now": format_bits_rate(float(now["allocated_bps"])) if now else "Unavailable",
                     "At the forecast": format_bits_rate(float(then["allocated_bps"])),
                     "Would go unmet": format_bits_rate(float(then["unmet_bps"]))})
    return rows


def _card(principal: Principal, m: Dict[str, Any]) -> None:
    with st.container(border=True):
        where = m["interface_name"] or "(unnamed)"
        st.markdown(f"**#{m['id']} · {m['source_name']} · {where}: {m['predicted_utilization']:.0%} predicted in "
                    f"{m['horizon_seconds'] // 60} min** · {STRENGTH[m['strength']]}")
        upper = f", up to {m['upper_utilization']:.0%} with typical error" if m["upper_utilization"] is not None else ""
        st.caption(f"Threshold {m['threshold']:.0%}{upper} · {m['risk']} risk · model {m['model_version']}, "
                   f"{'validated' if m['model_validated'] else 'not validated'} for this horizon · "
                   f"{'simulated source' if m['origin'] == 'simulation' else 'replayed dataset' if m['origin'] == 'replay' else 'from stored telemetry'}")
        st.markdown("\n".join(f"- {action}" for action in m["actions"]))
        if m["projected_allocation"]:
            st.dataframe(pd.DataFrame(_allocation_rows(m)), hide_index=True, width="stretch")
            st.caption("Predicted, assuming every host grows in proportion. Forecasts are per link, not per host.")
        if m["automatic_note"]:
            st.caption(m["automatic_note"])
        if not principal.has(Permission.APPLY_TRAFFIC_POLICY):
            st.caption("Only an administrator can decide this.")
            return
        reason = st.text_input("Reason", key=f"preventive_reason_{m['id']}", placeholder="Why, at least 5 characters")
        c1, c2 = st.columns(2)
        if m["origin"] == "simulation" and c1.button("Prioritize critical traffic", key=f"preventive_apply_{m['id']}", type="primary"):
            _attempt(preventive_service.apply, principal, m["id"], reason=reason)
        if c2.button("Dismiss", key=f"preventive_dismiss_{m['id']}"):
            _attempt(preventive_service.dismiss, principal, m["id"], reason=reason)


def _attempt(function, *args, **kwargs) -> None:
    try:
        function(*args, **kwargs)
    except (PreventiveError, PermissionDenied) as exc:
        st.error(str(exc))
    else:
        st.rerun()


def _recommendations(principal: Principal) -> None:
    recent = preventive_service.list_recent(principal)
    waiting = [m for m in recent if m["status"] == "open"]
    section_label("Preventive recommendations")
    if not waiting:
        st.caption("Nothing is waiting. A recommendation appears when a forecast reaches the threshold set in Allocation controls.")
    for m in waiting:
        _card(principal, m)
    done = [m for m in recent if m["status"] != "open"]
    if done:
        with st.expander(f"Earlier recommendations ({len(done)})"):
            st.dataframe(pd.DataFrame([{
                "ID": m["id"], "Source": m["source_name"], "Predicted": f"{m['predicted_utilization']:.0%}",
                "In": f"{m['horizon_seconds'] // 60} min", "Status": m["status"], "Note": m["decision_note"] or "—",
                "Updated": format_timestamp(m["updated_at"])} for m in done]), hide_index=True, width="stretch")


def _links(principal: Principal) -> None:
    links = preventive_service.links_approaching(principal)
    if not links:
        return
    section_label("Links")
    st.dataframe(pd.DataFrame([{
        "Link": f"{l['source_name']} · {l['interface'] or '(unnamed)'}", "Worst forecast": format_ratio(l["predicted_utilization"]) or "Unavailable",
        "In": f"{l['horizon_minutes']} min" if l["horizon_minutes"] else "—", "Risk": l["risk"],
        "Approaching capacity": "Yes" if l["approaching"] else "No", "Data up to": format_timestamp(l["base_time"])}
        for l in links]), hide_index=True, width="stretch")


def _panel(principal: Principal) -> None:
    live, simulation = live_monitor_service.get_monitor().status, simulation_service.status_copy()
    note = live.forecast_note if live.running else simulation.forecast_note if simulation.running else None
    if note:
        st.caption(f"Latest automatic forecast: {note}")
    _recommendations(principal)
    _links(principal)


def render(principal: Principal) -> None:
    status = preventive_service.model_status(principal)
    if not status.available:
        st.warning(status.reason)
        st.page_link("views/ml_lab.py", label="Open the ML Laboratory", icon=":material/science:")
        return
    _model_section(status)
    session_id, interface = _choose_source(principal)
    if session_id is None:
        st.caption("No session has telemetry to forecast from yet. Start a capture, or import telemetry in the ML Laboratory.")
    else:
        _outlook_section(principal, session_id, interface)
    running = live_monitor_service.get_monitor().status.running or simulation_service.status_copy().running
    st.fragment(_panel, run_every=5 if running else None)(principal)
