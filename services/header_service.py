"""Data for the header strip shown on every page. Read-only; every value is real or "unavailable".

Network health score (0–100), documented here and shown in the ring's tooltip:

    100
    − 25 per open critical alert   (at most −50)
    − 10 per open high alert       (at most −30)
    −  3 per open medium alert     (at most −15)
    − link penalty from the most utilized link's latest stored value:
        ≥ critical threshold −25, ≥ high threshold −15, ≥ elevated threshold −5
    − 10 when live monitoring is in the ERROR state
    clamped to 0–100.

When nothing has ever been stored (no alerts, no metrics, no sessions) the score is
unavailable rather than a reassuring 100.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, List, Optional

from repositories import dashboard_repository
from services import data_source, database_service, model_registry_service, settings_service, severity
from services.authorization import Permission, Principal, require_permission
from services.timeutil import to_iso, utc_now

FLOW_RATE_WINDOW_SECONDS = 60


@dataclass(frozen=True)
class IncidentNotice:
    id: int
    title: str
    severity: Optional[str]
    classification: str


@dataclass
class HeaderData:
    health: Optional[int]
    health_level: str  # ok / warn / critical / unavailable
    source: data_source.DataSource
    flows_per_second: Optional[float]
    active_incidents: int
    top_incident_severity: Optional[str]
    top_link: Optional[str]
    top_link_utilization: Optional[float]
    top_link_as_of: Optional[str]
    models_active: int
    models_verified: int
    models_total_families: int
    open_alerts: Dict[str, int] = field(default_factory=dict)
    incidents: List[IncidentNotice] = field(default_factory=list)
    flows_basis: Optional[str] = None  # "live" (finished flows/s) or "replay" (replayed rows/s, wall clock)


def health_score(open_alerts: Dict[str, int], top_utilization: Optional[float], thresholds: Dict[str, float],
                 *, monitoring_error: bool = False, has_any_data: bool = True) -> Optional[int]:
    """Pure scoring rule (see module docstring). None when there is no data to judge."""
    if not has_any_data:
        return None
    score = 100.0
    score -= min(50, 25 * open_alerts.get("critical", 0))
    score -= min(30, 10 * open_alerts.get("high", 0))
    score -= min(15, 3 * open_alerts.get("medium", 0))
    if top_utilization is not None:
        if top_utilization >= thresholds["critical"]:
            score -= 25
        elif top_utilization >= thresholds["high"]:
            score -= 15
        elif top_utilization >= thresholds["elevated"]:
            score -= 5
    if monitoring_error:
        score -= 10
    return int(max(0, min(100, round(score))))


def health_level(score: Optional[int]) -> str:
    if score is None:
        return "unavailable"
    return "ok" if score >= 80 else "warn" if score >= 50 else "critical"


def new_high_incidents(incidents: List[IncidentNotice], last_seen_id: Optional[int]) -> List[IncidentNotice]:
    """High/critical incidents newer than the last one this browser tab was told about."""
    return [i for i in incidents
            if (last_seen_id is None or i.id > last_seen_id) and i.severity in ("high", "critical")]


def get_header(principal: Principal, *, live_running: bool = False, live_mode: Optional[str] = None,
               live_session_id: Optional[int] = None, replay_running: bool = False,
               replay_flows_per_second: Optional[float] = None) -> HeaderData:
    """`live_*` describe the in-process capture (from the live monitor) and `replay_flows_per_second` the running
    replay (from the replay engine): the database cannot know either."""
    require_permission(principal, Permission.VIEW_DASHBOARD, action="dashboard.view")
    thresholds = settings_service.get_predictnet_settings().thresholds()
    with database_service.session() as conn:
        counts = dashboard_repository.table_counts(conn)
        open_alerts = dashboard_repository.unresolved_alerts_by_severity(conn)
        session_row = dashboard_repository.latest_monitoring_session(conn)
        utilization = dashboard_repository.latest_utilization_by_interface(conn)
        incident_rows = dashboard_repository.active_incident_summaries(conn)
        flows_recent = None
        if live_running and live_mode == "packets" and live_session_id is not None:
            since = to_iso(utc_now() - timedelta(seconds=FLOW_RATE_WINDOW_SECONDS))
            flows_recent = dashboard_repository.flows_since(conn, live_session_id, since)
    source = data_source.classify(
        session_row["source_type"] if session_row else None, live_running=live_running, live_mode=live_mode,
        detail=session_row["interface_name"] if session_row else None)
    if replay_running and source.kind not in (data_source.LIVE, data_source.COUNTERS):
        # A replay in progress is what changes on screen, even if a dataset was scored after it started.
        source = data_source.classify("replay")
    top = max(utilization, key=lambda r: r["utilization_ratio"], default=None)
    top_utilization = float(top["utilization_ratio"]) if top is not None else None
    incidents = [IncidentNotice(r["id"], r["title"], r["top_severity"], r["classification"]) for r in incident_rows]
    has_any_data = any(counts[t] for t in ("alerts", "network_metrics", "monitoring_sessions", "incidents"))
    score = health_score(open_alerts, top_utilization, thresholds,
                         monitoring_error=bool(session_row and session_row["status"] == "ERROR"),
                         has_any_data=has_any_data)
    active = [r for r in (model_registry_service.active_model(principal, f) for f in model_registry_service.FAMILIES) if r]
    flows_per_second, flows_basis = None, None
    if flows_recent is not None:
        flows_per_second, flows_basis = flows_recent / FLOW_RATE_WINDOW_SECONDS, "live"
    elif replay_running and source.kind == data_source.REPLAY and replay_flows_per_second is not None:
        flows_per_second, flows_basis = replay_flows_per_second, "replay"
    return HeaderData(
        health=score, health_level=health_level(score), source=source, flows_basis=flows_basis,
        flows_per_second=flows_per_second,
        active_incidents=len(incidents), top_incident_severity=severity.highest(i.severity for i in incidents),
        top_link=(top["interface_name"] or "(unnamed)") if top is not None else None,
        top_link_utilization=top_utilization, top_link_as_of=top["timestamp"] if top is not None else None,
        models_active=len(active), models_verified=sum(1 for r in active if model_registry_service.is_verified(r)),
        models_total_families=len(model_registry_service.FAMILIES), open_alerts=open_alerts, incidents=incidents,
    )
