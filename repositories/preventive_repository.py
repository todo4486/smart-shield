"""SQL for preventive_recommendations."""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional


def insert(conn: sqlite3.Connection, values: Dict[str, Any]) -> int:
    columns = ", ".join(values)
    marks = ", ".join("?" for _ in values)
    return int(conn.execute(f"INSERT INTO preventive_recommendations ({columns}) VALUES ({marks})", list(values.values())).lastrowid)


UPDATABLE = frozenset({
    "base_time", "target_time", "horizon_seconds", "predicted_utilization", "upper_utilization", "threshold", "capacity_bps",
    "strength", "risk", "model_id", "model_version", "prediction_id", "model_validated", "consecutive", "current_allocation_json",
    "projected_allocation_json", "actions_json", "automatic_note", "status", "mitigation_id", "updated_at", "decided_at",
    "decided_by", "decision_note",
})


def update(conn: sqlite3.Connection, recommendation_id: int, values: Dict[str, Any]) -> None:
    unknown = set(values) - UPDATABLE
    if unknown:
        raise ValueError(f"not updatable: {sorted(unknown)}")
    assignments = ", ".join(f"{column} = ?" for column in values)
    conn.execute(f"UPDATE preventive_recommendations SET {assignments} WHERE id = ?", [*values.values(), recommendation_id])


def get(conn: sqlite3.Connection, recommendation_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM preventive_recommendations WHERE id = ?", (recommendation_id,)).fetchone()


def open_for(conn: sqlite3.Connection, session_id: int, interface: Optional[str]) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM preventive_recommendations WHERE session_id = ? AND COALESCE(interface_name, '') = ? "
                        "AND status = 'open'", (session_id, interface or "")).fetchone()


def last_decided(conn: sqlite3.Connection, session_id: int, interface: Optional[str]) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM preventive_recommendations WHERE session_id = ? AND COALESCE(interface_name, '') = ? "
                        "AND status IN ('dismissed', 'applied') ORDER BY id DESC LIMIT 1", (session_id, interface or "")).fetchone()


def recent(conn: sqlite3.Connection, limit: int = 50) -> List[sqlite3.Row]:
    return conn.execute("SELECT * FROM preventive_recommendations ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def overdue(conn: sqlite3.Connection, session_id: int, moment: str) -> List[sqlite3.Row]:
    return conn.execute("SELECT * FROM preventive_recommendations WHERE session_id = ? AND status = 'open' AND target_time < ?",
                        (session_id, moment)).fetchall()
