"""Overview dashboard data, computed only from persisted rows.

Every value carries its provenance. Missing data is ``None`` with provenance
``unavailable`` — never a fabricated 0.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, List, Optional

from repositories import dashboard_repository
from services import database_service
from services.authorization import Permission, Principal, require_permission
from services.timeutil import to_iso, utc_now

UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class LabeledValue:
    value: Optional[float]
    provenance: str
    unit: str = ""
    as_of: Optional[str] = None
    note: Optional[str] = None

    @classmethod
    def unavailable(cls, unit: str = "", note: Optional[str] = None) -> "LabeledValue":
        return cls(value=None, provenance=UNAVAILABLE, unit=unit, note=note)


@dataclass(frozen=True)
class MonitoringStatus:
    status: str  # STOPPED / STARTING / RUNNING / STOPPING / ERROR, or NONE when no session exists
    source_type: Optional[str] = None
    interface_name: Optional[str] = None
    started_at: Optional[str] = None
    message: Optional[str] = None


@dataclass
class OverviewData:
    monitoring: MonitoringStatus
    incoming_bps: LabeledValue
    outgoing_bps: LabeledValue
    throughput_bps: LabeledValue
    utilization: LabeledValue
    active_flows: LabeledValue
    unresolved_alerts: Dict[str, int]
    predicted_utilization: LabeledValue
    congestion_risk: Optional[str]
    forecast_horizon_seconds: Optional[int]
    prediction_model_version: Optional[str]
    latest_recommendation: Optional[dict]
    recent_incidents: List[dict]
    throughput_series: List[dict]
    counts: Dict[str, int] = field(default_factory=dict)

    @property
    def has_any_data(self) -> bool:
        return any(self.counts.values())


def _monitoring_status(row) -> MonitoringStatus:
    if row is None:
        return MonitoringStatus(status="NONE")
    return MonitoringStatus(
        status=row["status"],
        source_type=row["source_type"],
        interface_name=row["interface_name"],
        started_at=row["started_at"],
        message=row["status_message"],
    )


def get_monitoring_status(principal: Principal) -> MonitoringStatus:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="dashboard.view")
    with database_service.session() as conn:
        return _monitoring_status(dashboard_repository.latest_monitoring_session(conn))


def _metric_value(row, column: str, unit: str, provenance_column: Optional[str] = None) -> LabeledValue:
    """Use the field-level provenance when the importer recorded one (derived values), else the row's."""
    if row is None or row[column] is None:
        return LabeledValue.unavailable(unit)
    provenance = row["provenance"]
    if provenance_column and row[provenance_column]:
        provenance = row[provenance_column]
    return LabeledValue(value=float(row[column]), provenance=provenance, unit=unit, as_of=row["timestamp"])


def get_overview(principal: Principal, *, series_hours: int = 24) -> OverviewData:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="dashboard.view")
    since = to_iso(utc_now() - timedelta(hours=series_hours))
    with database_service.session() as conn:
        counts = dashboard_repository.table_counts(conn)
        session_row = dashboard_repository.latest_monitoring_session(conn)
        metric = dashboard_repository.latest_metric(conn)
        alerts = dashboard_repository.unresolved_alerts_by_severity(conn)
        prediction = dashboard_repository.latest_prediction(conn)
        recommendation = dashboard_repository.latest_recommendation(conn)
        incidents = dashboard_repository.recent_incidents(conn)
        series = dashboard_repository.metrics_since(conn, since)
        flow_count = (
            dashboard_repository.flow_count_for_session(conn, session_row["id"]) if session_row is not None else None
        )

    if metric is not None and metric["utilization_ratio"] is None:
        utilization = LabeledValue.unavailable(
            "ratio", note="Link capacity is not configured, so utilization cannot be computed."
        )
    else:
        utilization = _metric_value(metric, "utilization_ratio", "ratio", "utilization_provenance")

    if flow_count is None:
        active_flows = LabeledValue.unavailable("flows")
    else:
        active_flows = LabeledValue(
            value=float(flow_count), provenance="measured", unit="flows",
            note="Flows recorded in the most recent monitoring session.",
        )

    if prediction is not None and prediction["predicted_utilization_ratio"] is not None:
        predicted = LabeledValue(
            value=float(prediction["predicted_utilization_ratio"]), provenance="predicted", unit="ratio",
            as_of=prediction["timestamp"],
        )
    else:
        predicted = LabeledValue.unavailable("ratio")

    return OverviewData(
        monitoring=_monitoring_status(session_row),
        incoming_bps=_metric_value(metric, "incoming_bytes_per_second", "B/s"),
        outgoing_bps=_metric_value(metric, "outgoing_bytes_per_second", "B/s"),
        throughput_bps=_metric_value(metric, "throughput_bps", "bit/s", "throughput_provenance"),
        utilization=utilization,
        active_flows=active_flows,
        unresolved_alerts=alerts,
        predicted_utilization=predicted,
        congestion_risk=prediction["congestion_risk"] if prediction is not None else None,
        forecast_horizon_seconds=prediction["forecast_horizon_seconds"] if prediction is not None else None,
        prediction_model_version=prediction["model_version"] if prediction is not None else None,
        latest_recommendation=dict(recommendation) if recommendation is not None else None,
        recent_incidents=[dict(r) for r in incidents],
        throughput_series=[dict(r) for r in series],
        counts=counts,
    )
