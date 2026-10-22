"""SQL for audit_logs."""
from __future__ import annotations

import sqlite3
from typing import List, Optional


def insert_entry(
    conn: sqlite3.Connection,
    *,
    user_id: Optional[int],
    action: str,
    outcome: str,
    details_json: Optional[str],
    now: str,
) -> int:
    cursor = conn.execute(
        "INSERT INTO audit_logs (user_id, action, outcome, details_json, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, action, outcome, details_json, now),
    )
    return int(cursor.lastrowid)


def list_entries(
    conn: sqlite3.Connection,
    *,
    limit: int,
    outcome: Optional[str] = None,
    action_prefix: Optional[str] = None,
) -> List[sqlite3.Row]:
    clauses = []
    params: list = []
    if outcome:
        clauses.append("a.outcome = ?")
        params.append(outcome)
    if action_prefix:
        clauses.append("a.action LIKE ? ESCAPE '\\'")
        escaped = action_prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        params.append(escaped + "%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    return conn.execute(
        "SELECT a.id, a.created_at, a.user_id, u.email AS user_email, a.action, a.outcome, a.details_json "
        "FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id "
        f"{where} ORDER BY a.created_at DESC, a.id DESC LIMIT ?",
        params,
    ).fetchall()


def distinct_actions(conn: sqlite3.Connection) -> List[str]:
    return [r[0] for r in conn.execute("SELECT DISTINCT action FROM audit_logs ORDER BY action")]
