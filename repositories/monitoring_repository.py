"""SQL for monitoring_sessions."""
from __future__ import annotations

import sqlite3
from typing import List, Optional


def insert(
    conn: sqlite3.Connection,
    *,
    user_id: Optional[int],
    source_type: str,
    interface_name: Optional[str],
    started_at: str,
    status: str,
    configuration_json: Optional[str],
    dataset_id: Optional[int] = None,
) -> int:
    cursor = conn.execute(
        "INSERT INTO monitoring_sessions (user_id, source_type, interface_name, started_at, status, "
        "configuration_json, dataset_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, source_type, interface_name, started_at, status, configuration_json, dataset_id),
    )
    return int(cursor.lastrowid)


def get(conn: sqlite3.Connection, session_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM monitoring_sessions WHERE id = ?", (session_id,)).fetchone()


def update_status(
    conn: sqlite3.Connection,
    session_id: int,
    *,
    status: str,
    status_message: Optional[str],
    ended_at: Optional[str],
) -> None:
    conn.execute(
        "UPDATE monitoring_sessions SET status = ?, status_message = ?, ended_at = COALESCE(?, ended_at) "
        "WHERE id = ?",
        (status, status_message, ended_at, session_id),
    )


def update_configuration(conn: sqlite3.Connection, session_id: int, configuration_json: str,
                         interface_name: Optional[str], dataset_id: Optional[int]) -> None:
    conn.execute(
        "UPDATE monitoring_sessions SET configuration_json = ?, interface_name = ?, dataset_id = ? WHERE id = ?",
        (configuration_json, interface_name, dataset_id, session_id),
    )


def list_with_counts(conn: sqlite3.Connection, limit: int = 200) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT s.id, s.source_type, s.interface_name, s.started_at, s.ended_at, s.status, s.status_message, "
        "s.dataset_id, s.configuration_json, u.email AS user_email, "
        "(SELECT COUNT(*) FROM network_metrics m WHERE m.session_id = s.id) AS metric_count, "
        "(SELECT COUNT(*) FROM network_flows f WHERE f.session_id = s.id) AS flow_count "
        "FROM monitoring_sessions s LEFT JOIN users u ON u.id = s.user_id "
        "ORDER BY s.started_at DESC, s.id DESC LIMIT ?",
        (limit,),
    ).fetchall()


def delete(conn: sqlite3.Connection, session_id: int) -> None:
    conn.execute("DELETE FROM monitoring_sessions WHERE id = ?", (session_id,))
