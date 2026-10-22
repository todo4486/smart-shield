"""SQL for incidents and incident_alerts."""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional


def unlinked_alerts(conn: sqlite3.Connection, statuses: tuple = ("open", "acknowledged")) -> List[sqlite3.Row]:
    placeholders = ", ".join("?" for _ in statuses)
    return conn.execute(
        f"SELECT a.* FROM alerts a WHERE a.status IN ({placeholders}) "
        "AND NOT EXISTS (SELECT 1 FROM incident_alerts ia WHERE ia.alert_id = a.id) ORDER BY a.created_at, a.id",
        statuses,
    ).fetchall()


def active_incidents(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM incidents WHERE status IN ('open', 'investigating') ORDER BY window_start, id"
    ).fetchall()


def insert(conn: sqlite3.Connection, values: Dict[str, Any]) -> int:
    columns = ("title", "classification", "status", "window_start", "window_end", "measured_changes_json",
               "model_outputs_json", "correlation_rationale", "investigation_steps_json", "created_by",
               "created_at", "updated_at")
    cursor = conn.execute(f"INSERT INTO incidents ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
                          tuple(values.get(c) for c in columns))
    return int(cursor.lastrowid)


def update(conn: sqlite3.Connection, incident_id: int, values: Dict[str, Any]) -> None:
    allowed = ("title", "classification", "status", "window_start", "window_end", "measured_changes_json",
               "model_outputs_json", "correlation_rationale", "investigation_steps_json", "updated_at",
               "investigation_notes")
    keys = [k for k in values if k in allowed]
    conn.execute(f"UPDATE incidents SET {', '.join(f'{k} = ?' for k in keys)} WHERE id = ?",
                 tuple(values[k] for k in keys) + (incident_id,))


def link(conn: sqlite3.Connection, incident_id: int, alert_id: int) -> None:
    conn.execute("INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)", (incident_id, alert_id))


def get(conn: sqlite3.Connection, incident_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()


def alerts_for(conn: sqlite3.Connection, incident_id: int) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT a.* FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.id WHERE ia.incident_id = ? "
        "ORDER BY a.created_at, a.id", (incident_id,)).fetchall()


def list_incidents(conn: sqlite3.Connection, statuses: Optional[List[str]] = None, limit: int = 300) -> List[sqlite3.Row]:
    sql = ("SELECT i.*, (SELECT COUNT(*) FROM incident_alerts ia WHERE ia.incident_id = i.id) AS alert_count "
           "FROM incidents i")
    params: list = []
    if statuses:
        sql += f" WHERE i.status IN ({', '.join('?' for _ in statuses)})"
        params.extend(statuses)
    params.append(limit)
    return conn.execute(sql + " ORDER BY i.window_start DESC, i.id DESC LIMIT ?", params).fetchall()


def metrics_between(conn: sqlite3.Connection, start: str, end: str, end_inclusive: bool = True) -> List[sqlite3.Row]:
    end_op = "<=" if end_inclusive else "<"
    return conn.execute(
        "SELECT timestamp, interface_name, throughput_bps, utilization_ratio, latency_ms, packet_loss_ratio, "
        f"provenance, throughput_provenance FROM network_metrics WHERE timestamp >= ? AND timestamp {end_op} ? "
        "ORDER BY timestamp", (start, end)).fetchall()


def predictions_between(conn: sqlite3.Connection, start: str, end: str) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT id, timestamp, interface_name, forecast_horizon_seconds, predicted_utilization_ratio, "
        "predicted_throughput_bps, congestion_risk, model_version FROM congestion_predictions "
        "WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp", (start, end)).fetchall()


def latest_recommendation_for(conn: sqlite3.Connection, interface: Optional[str]) -> Optional[sqlite3.Row]:
    if not interface:
        return None
    return conn.execute(
        "SELECT id, timestamp, status, unmet_demand_bps FROM bandwidth_recommendations WHERE interface_name = ? "
        "ORDER BY timestamp DESC, id DESC LIMIT 1", (interface,)).fetchone()
