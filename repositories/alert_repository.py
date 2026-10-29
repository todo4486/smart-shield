"""SQL for alerts and alert_events."""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional


def insert(conn: sqlite3.Connection, values: Dict[str, Any]) -> int:
    columns = (
        "session_id", "flow_id", "alert_type", "severity", "category", "reason", "status", "dedup_key",
        "evidence_json", "model_id", "model_version", "created_at",
    )
    cursor = conn.execute(
        f"INSERT INTO alerts ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
        tuple(values.get(c) for c in columns),
    )
    return int(cursor.lastrowid)


def get(conn: sqlite3.Connection, alert_id: int) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT a.*, ua.email AS acknowledged_by_email, ur.email AS resolved_by_email FROM alerts a "
        "LEFT JOIN users ua ON ua.id = a.acknowledged_by LEFT JOIN users ur ON ur.id = a.resolved_by "
        "WHERE a.id = ?",
        (alert_id,),
    ).fetchone()


def find_recent_by_dedup(conn: sqlite3.Connection, dedup_key: str, since: Optional[str] = None,
                         unresolved_only: bool = False) -> Optional[sqlite3.Row]:
    sql = "SELECT * FROM alerts WHERE dedup_key = ?"
    params: list = [dedup_key]
    if since is not None:
        sql += " AND created_at >= ?"
        params.append(since)
    if unresolved_only:
        sql += " AND status IN ('open', 'acknowledged')"
    return conn.execute(sql + " ORDER BY created_at DESC LIMIT 1", params).fetchone()


def list_alerts(conn: sqlite3.Connection, *, statuses: Optional[List[str]] = None,
                severities: Optional[List[str]] = None, types: Optional[List[str]] = None,
                limit: int = 500, suppressed: str = "include") -> List[sqlite3.Row]:
    clauses, params = [], []
    if suppressed == "exclude":
        clauses.append("suppressed_by_rule IS NULL")
    elif suppressed == "only":
        clauses.append("suppressed_by_rule IS NOT NULL")
    for column, values in (("status", statuses), ("severity", severities), ("alert_type", types)):
        if values:
            clauses.append(f"{column} IN ({', '.join('?' for _ in values)})")
            params.extend(values)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    return conn.execute(
        f"SELECT * FROM alerts {where} ORDER BY created_at DESC, id DESC LIMIT ?", params
    ).fetchall()


def set_suppressed(conn: sqlite3.Connection, alert_id: int, rule_id: int) -> None:
    conn.execute("UPDATE alerts SET suppressed_by_rule = ? WHERE id = ?", (rule_id, alert_id))


def update_status(conn: sqlite3.Connection, alert_id: int, values: Dict[str, Any]) -> None:
    allowed = ("status", "acknowledged_by", "acknowledged_at", "resolved_by", "resolved_at", "investigation_notes")
    sets = [f"{k} = ?" for k in values if k in allowed]
    conn.execute(f"UPDATE alerts SET {', '.join(sets)} WHERE id = ?",
                 tuple(values[k] for k in values if k in allowed) + (alert_id,))


def insert_event(conn: sqlite3.Connection, *, alert_id: int, event_type: str, from_status: Optional[str],
                 to_status: Optional[str], note: Optional[str], user_id: Optional[int], now: str) -> None:
    conn.execute(
        "INSERT INTO alert_events (alert_id, event_type, from_status, to_status, note, user_id, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (alert_id, event_type, from_status, to_status, note, user_id, now),
    )


def events(conn: sqlite3.Connection, alert_id: int) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT e.*, u.email AS user_email FROM alert_events e LEFT JOIN users u ON u.id = e.user_id "
        "WHERE e.alert_id = ? ORDER BY e.created_at, e.id",
        (alert_id,),
    ).fetchall()


def counts_by_day(conn: sqlite3.Connection, since: str) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT substr(created_at, 1, 10) AS day, alert_type, COUNT(*) AS n FROM alerts "
        "WHERE created_at >= ? GROUP BY day, alert_type ORDER BY day",
        (since,),
    ).fetchall()
