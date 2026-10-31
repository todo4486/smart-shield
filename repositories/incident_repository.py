"""SQL for incidents and incident_alerts."""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional


# Replay and simulation data live in sessions with their own source_type. Correlation keeps each apart from real data
# and from the other. An "origin" is 'real', 'replay' or 'simulation'.
REPLAY_SOURCE_NAME = "dataset replay"
SIMULATION_SOURCE_NAME = "simulation"
IS_REPLAY_ALERT = ("EXISTS (SELECT 1 FROM monitoring_sessions s WHERE s.id = a.session_id "
                   "AND s.source_type = 'replay')")
IS_SIMULATION_ALERT = ("EXISTS (SELECT 1 FROM monitoring_sessions s WHERE s.id = a.session_id "
                       "AND s.source_type = 'simulation')")
_METRIC_ORIGIN = ("CASE WHEN session_id IN (SELECT id FROM monitoring_sessions WHERE source_type = 'replay') THEN 'replay' "
                  "WHEN session_id IN (SELECT id FROM monitoring_sessions WHERE source_type = 'simulation') "
                  "THEN 'simulation' ELSE 'real' END")
_PREDICTION_ORIGIN = ("CASE source_name WHEN ? THEN 'replay' WHEN ? THEN 'simulation' ELSE 'real' END")
# What the incident's mitigation actions are doing right now. A dry run changes nothing, so it is counted apart.
_MITIGATION_STATE = (
    "(SELECT COUNT(*) FROM mitigation_actions m WHERE m.incident_id = i.id AND m.status = 'active' "
    "AND COALESCE(m.adapter, '') <> 'dry-run') AS mitigations_active, "
    "(SELECT COUNT(*) FROM mitigation_actions m WHERE m.incident_id = i.id AND m.status = 'active' "
    "AND m.adapter = 'dry-run') AS mitigations_dry_run, "
    "(SELECT COUNT(*) FROM mitigation_actions m WHERE m.incident_id = i.id AND m.status = 'proposed') AS mitigations_proposed, "
    "(SELECT m.status FROM mitigation_actions m WHERE m.incident_id = i.id ORDER BY m.id DESC LIMIT 1) AS mitigation_last_status")


def unlinked_alerts(conn: sqlite3.Connection, statuses: tuple = ("open", "acknowledged")) -> List[sqlite3.Row]:
    placeholders = ", ".join("?" for _ in statuses)
    return conn.execute(
        f"SELECT a.*, {IS_REPLAY_ALERT} AS is_replay, {IS_SIMULATION_ALERT} AS is_simulation FROM alerts a WHERE a.status IN ({placeholders}) "
        "AND a.suppressed_by_rule IS NULL "
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
               "created_at", "updated_at", "is_replay", "is_simulation")
    cursor = conn.execute(f"INSERT INTO incidents ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
                          tuple(int(bool(values.get(c))) if c in ("is_replay", "is_simulation") else values.get(c)
                                for c in columns))
    return int(cursor.lastrowid)


def update(conn: sqlite3.Connection, incident_id: int, values: Dict[str, Any]) -> None:
    allowed = ("title", "classification", "status", "window_start", "window_end", "measured_changes_json",
               "model_outputs_json", "correlation_rationale", "investigation_steps_json", "updated_at",
               "investigation_notes", "assigned_to", "resolution")
    keys = [k for k in values if k in allowed]
    conn.execute(f"UPDATE incidents SET {', '.join(f'{k} = ?' for k in keys)} WHERE id = ?",
                 tuple(values[k] for k in keys) + (incident_id,))


def link(conn: sqlite3.Connection, incident_id: int, alert_id: int) -> None:
    conn.execute("INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)", (incident_id, alert_id))


def get(conn: sqlite3.Connection, incident_id: int) -> Optional[sqlite3.Row]:
    return conn.execute(
        f"SELECT i.*, u.email AS assigned_email, {_MITIGATION_STATE} FROM incidents i LEFT JOIN users u ON u.id = i.assigned_to "
        "WHERE i.id = ?", (incident_id,)).fetchone()


def alerts_for(conn: sqlite3.Connection, incident_id: int) -> List[sqlite3.Row]:
    return conn.execute(
        f"SELECT a.*, {IS_REPLAY_ALERT} AS is_replay, {IS_SIMULATION_ALERT} AS is_simulation FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.id "
        "WHERE ia.incident_id = ? "
        "ORDER BY a.created_at, a.id", (incident_id,)).fetchall()


def list_incidents(conn: sqlite3.Connection, statuses: Optional[List[str]] = None, limit: int = 300) -> List[sqlite3.Row]:
    sql = (f"SELECT i.*, u.email AS assigned_email, {_MITIGATION_STATE}, "
           "(SELECT COUNT(*) FROM incident_alerts ia WHERE ia.incident_id = i.id) AS alert_count, "
           "(SELECT a.severity FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id WHERE ia.incident_id = i.id "
           " ORDER BY CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END "
           " LIMIT 1) AS top_severity "
           "FROM incidents i LEFT JOIN users u ON u.id = i.assigned_to")
    params: list = []
    if statuses:
        sql += f" WHERE i.status IN ({', '.join('?' for _ in statuses)})"
        params.extend(statuses)
    params.append(limit)
    return conn.execute(sql + " ORDER BY i.window_start DESC, i.id DESC LIMIT ?", params).fetchall()


def metrics_between(conn: sqlite3.Connection, start: str, end: str, end_inclusive: bool = True,
                    origin: str = "real") -> List[sqlite3.Row]:
    end_op = "<=" if end_inclusive else "<"
    return conn.execute(
        "SELECT timestamp, interface_name, throughput_bps, utilization_ratio, latency_ms, packet_loss_ratio, "
        f"provenance, throughput_provenance FROM network_metrics WHERE timestamp >= ? AND timestamp {end_op} ? "
        f"AND {_METRIC_ORIGIN} = ? ORDER BY timestamp", (start, end, origin)).fetchall()


def predictions_between(conn: sqlite3.Connection, start: str, end: str, origin: str = "real") -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT id, timestamp, interface_name, forecast_horizon_seconds, predicted_utilization_ratio, "
        "predicted_throughput_bps, congestion_risk, model_version FROM congestion_predictions "
        f"WHERE timestamp >= ? AND timestamp <= ? AND {_PREDICTION_ORIGIN} = ? ORDER BY timestamp",
        (start, end, REPLAY_SOURCE_NAME, SIMULATION_SOURCE_NAME, origin)).fetchall()


def latest_recommendation_for(conn: sqlite3.Connection, interface: Optional[str]) -> Optional[sqlite3.Row]:
    if not interface:
        return None
    return conn.execute(
        "SELECT id, timestamp, status, unmet_demand_bps FROM bandwidth_recommendations WHERE interface_name = ? "
        "ORDER BY timestamp DESC, id DESC LIMIT 1", (interface,)).fetchone()


def insert_event(conn: sqlite3.Connection, *, incident_id: int, event_type: str, user_id: Optional[int], now: str,
                 from_status: Optional[str] = None, to_status: Optional[str] = None,
                 assigned_to: Optional[int] = None, note: Optional[str] = None) -> None:
    conn.execute(
        "INSERT INTO incident_events (incident_id, event_type, from_status, to_status, assigned_to, note, user_id, "
        "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (incident_id, event_type, from_status, to_status, assigned_to, note, user_id, now))


def events(conn: sqlite3.Connection, incident_id: int) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT e.*, actor.email AS user_email, target.email AS assigned_email FROM incident_events e "
        "LEFT JOIN users actor ON actor.id = e.user_id LEFT JOIN users target ON target.id = e.assigned_to "
        "WHERE e.incident_id = ? ORDER BY e.created_at, e.id", (incident_id,)).fetchall()


def is_active_user(conn: sqlite3.Connection, user_id: int) -> bool:
    row = conn.execute("SELECT is_active FROM users WHERE id = ?", (user_id,)).fetchone()
    return bool(row and row["is_active"])


def active_users(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    return conn.execute("SELECT id, name, email, role FROM users WHERE is_active = 1 ORDER BY name, id").fetchall()


def alert_incident_map(conn: sqlite3.Connection) -> Dict[int, int]:
    return {r["alert_id"]: r["incident_id"] for r in conn.execute("SELECT alert_id, incident_id FROM incident_alerts")}


def latest_alerts(conn: sqlite3.Connection, limit: int = 2000) -> List[sqlite3.Row]:
    # Suppressed alerts stay out of the timeline, like every other queue (they are under the "Suppressed" filter).
    return conn.execute("SELECT * FROM alerts WHERE suppressed_by_rule IS NULL ORDER BY id DESC LIMIT ?",
                        (limit,)).fetchall()


def incidents_overlapping(conn: sqlite3.Connection, start: str, end: str) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT id, title, classification, status, window_start, window_end FROM incidents "
        "WHERE window_end >= ? AND window_start <= ? ORDER BY window_start, id", (start, end)).fetchall()
