"""Read-side telemetry for charts: per-session metrics, coverage and flow summaries."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import pandas as pd

from repositories import flow_repository, monitoring_repository, telemetry_repository
from services import database_service
from services.authorization import Permission, Principal, require_permission
from services.monitoring_service import SessionNotFound
from services.telemetry_schema import METRIC_NAMES

MAX_CHART_POINTS = 2000


@dataclass
class SessionTelemetry:
    session_id: int
    interfaces: List[str]
    metrics: pd.DataFrame  # one row per stored measurement, timestamps as UTC datetimes
    coverage: Dict[str, float]  # share of rows with a value, per metric
    provenance_counts: Dict[str, Dict[str, int]]  # throughput/utilization/capacity provenance
    stats: Dict[str, Dict[str, Optional[float]]]


@dataclass
class FlowSummary:
    total: int
    protocols: List[dict] = field(default_factory=list)
    top_ports: List[dict] = field(default_factory=list)
    per_minute: List[dict] = field(default_factory=list)
    dataset_labels: Dict[str, int] = field(default_factory=dict)


def session_telemetry(principal: Principal, session_id: int, interface: Optional[str] = None) -> SessionTelemetry:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="telemetry.view")
    with database_service.session() as conn:
        if monitoring_repository.get(conn, session_id) is None:
            raise SessionNotFound(f"Monitoring session {session_id} does not exist.")
        interfaces = telemetry_repository.interfaces_for_session(conn, session_id)
        # None = all interfaces; "" = rows without an interface name (never "all", which would mix links).
        rows = telemetry_repository.metrics_for_session(conn, session_id, interface)
    frame = pd.DataFrame([dict(r) for r in rows])
    if frame.empty:
        return SessionTelemetry(session_id, interfaces, frame, {}, {}, {})
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, format="ISO8601")
    coverage = {name: round(float(frame[name].notna().mean()), 4) for name in METRIC_NAMES}
    provenance = {
        column: {str(k): int(v) for k, v in frame[column].fillna("unavailable").value_counts().items()}
        for column in ("throughput_provenance", "utilization_provenance", "capacity_provenance")
    }
    stats: Dict[str, Dict[str, Optional[float]]] = {}
    for name in METRIC_NAMES:
        series = frame[name].dropna()
        if series.empty:
            stats[name] = {"min": None, "mean": None, "p95": None, "max": None, "count": 0}
        else:
            stats[name] = {
                "min": float(series.min()), "mean": float(series.mean()),
                "p95": float(series.quantile(0.95)), "max": float(series.max()), "count": int(series.size),
            }
    return SessionTelemetry(session_id, interfaces, frame, coverage, provenance, stats)


def session_interfaces(principal: Principal, session_id: int) -> List[str]:
    """Interface names in a session ("" stands for rows recorded without one)."""
    require_permission(principal, Permission.VIEW_DASHBOARD, action="telemetry.view")
    with database_service.session() as conn:
        return telemetry_repository.interfaces_for_session(conn, session_id)


def recent_metrics(principal: Principal, session_id: int, limit: int = 200) -> pd.DataFrame:
    """The newest `limit` measurements of a session, oldest first (cheap enough to poll)."""
    require_permission(principal, Permission.VIEW_DASHBOARD, action="telemetry.view")
    with database_service.session() as conn:
        rows = telemetry_repository.recent_metrics(conn, session_id, limit)
    frame = pd.DataFrame([dict(r) for r in reversed(rows)])
    if not frame.empty:
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, format="ISO8601")
    return frame


def downsample(frame: pd.DataFrame, columns: List[str], max_points: int = MAX_CHART_POINTS):
    """Mean-aggregate to at most ~max_points per interface. Returns (frame, bucket label or None).

    Empty buckets stay empty (NaN) so gaps are not drawn as zero.
    """
    if frame.empty or len(frame) <= max_points:
        return frame, None
    span = (frame["timestamp"].max() - frame["timestamp"].min()).total_seconds()
    bucket_seconds = max(1, int(span / max_points) + 1)
    rule = f"{bucket_seconds}s"
    pieces = []
    for interface, group in frame.groupby(frame["interface_name"].fillna(""), sort=False):
        resampled = group.set_index("timestamp")[columns].resample(rule).mean().reset_index()
        resampled["interface_name"] = interface or None
        pieces.append(resampled)
    return pd.concat(pieces, ignore_index=True), f"mean per {bucket_seconds} s"


def break_gaps(frame: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
    """Insert an empty row inside every gap longer than 2x the median interval
    (per interface) so line charts show a break instead of bridging missing data."""
    if frame.empty:
        return frame
    pieces = []
    for interface, group in frame.groupby(frame["interface_name"].fillna(""), sort=False):
        group = group.sort_values("timestamp")
        diffs = group["timestamp"].diff()
        median = diffs.median()
        if pd.notna(median) and median.total_seconds() > 0:
            gap_starts = group.loc[diffs > 2 * median, "timestamp"] - diffs[diffs > 2 * median] / 2
            if not gap_starts.empty:
                filler = pd.DataFrame({"timestamp": gap_starts.reset_index(drop=True)})  # keeps UTC tz
                filler["interface_name"] = interface or None
                for column in columns:
                    filler[column] = float("nan")
                group = pd.concat([group, filler], ignore_index=True).sort_values("timestamp")
        pieces.append(group)
    return pd.concat(pieces, ignore_index=True)


def flow_summary(principal: Principal, session_id: int) -> FlowSummary:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="telemetry.view")
    with database_service.session() as conn:
        protocols = [dict(r) for r in flow_repository.protocol_counts(conn, session_id)]
        ports = [dict(r) for r in flow_repository.top_destination_ports(conn, session_id)]
        per_minute = [dict(r) for r in flow_repository.flows_per_minute(conn, session_id)]
        summaries = flow_repository.feature_summaries(conn, session_id)
    labels: Counter = Counter()
    for raw in summaries:
        try:
            label = json.loads(raw).get("dataset_label")
        except (ValueError, AttributeError):
            label = None
        if label is not None:
            labels[str(label)] += 1
    return FlowSummary(
        total=sum(p["flows"] for p in protocols), protocols=protocols, top_ports=ports,
        per_minute=per_minute, dataset_labels=dict(labels.most_common()),
    )
