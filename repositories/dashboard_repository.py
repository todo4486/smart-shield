"""Read-only queries behind the Overview dashboard and sidebar status."""
from __future__ import annotations

import sqlite3
from typing import Dict, List, Optional

# Fixed allow-list: table names are never taken from user input.
COUNTED_TABLES = (
    "monitoring_sessions",
    "network_metrics",
    "network_flows",
    "alerts",
    "congestion_predictions",
    "bandwidth_recommendations",
    "incidents",
    "model_registry",
)


def table_counts(conn: sqlite3.Connection) -> Dict[str, int]:
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in COUNTED_TABLES}


def latest_monitoring_session(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT id, source_type, interface_name, started_at, ended_at, status, status_message "
        "FROM monitoring_sessions ORDER BY started_at DESC, id DESC LIMIT 1"
    ).fetchone()


def latest_metric(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM network_metrics ORDER BY timestamp DESC, id DESC LIMIT 1"
    ).fetchone()


def metrics_since(conn: sqlite3.Connection, since: str, limit: int = 5000) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT timestamp, source_name, interface_name, incoming_bytes_per_second, "
        "outgoing_bytes_per_second, throughput_bps, provenance "
        "FROM network_metrics WHERE timestamp >= ? ORDER BY timestamp LIMIT ?",
        (since, limit),
    ).fetchall()


def flow_count_for_session(conn: sqlite3.Connection, session_id: int) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM network_flows WHERE session_id = ?", (session_id,)
    ).fetchone()[0]


def unresolved_alerts_by_severity(conn: sqlite3.Connection) -> Dict[str, int]:
    rows = conn.execute(
        "SELECT severity, COUNT(*) AS n FROM alerts "
        "WHERE status IN ('open', 'acknowledged') GROUP BY severity"
    ).fetchall()
    return {row["severity"]: row["n"] for row in rows}


def latest_prediction(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM congestion_predictions ORDER BY timestamp DESC, id DESC LIMIT 1"
    ).fetchone()


def latest_recommendation(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT id, timestamp, source_name, interface_name, capacity_bps, unmet_demand_bps, rationale, status "
        "FROM bandwidth_recommendations ORDER BY timestamp DESC, id DESC LIMIT 1"
    ).fetchone()


def recent_incidents(conn: sqlite3.Connection, limit: int = 5) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT id, title, classification, status, window_start, window_end, created_at "
        "FROM incidents ORDER BY created_at DESC, id DESC LIMIT ?",
        (limit,),
    ).fetchall()
