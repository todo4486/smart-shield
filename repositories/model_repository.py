"""SQL for model_registry."""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional


def insert(conn: sqlite3.Connection, values: Dict[str, Any]) -> int:
    columns = (
        "model_family", "model_name", "version", "artifact_path", "artifact_sha256", "feature_schema_version",
        "metrics_json", "training_metadata_json", "trained_at", "created_by", "is_active",
    )
    cursor = conn.execute(
        f"INSERT INTO model_registry ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
        tuple(values.get(c) for c in columns),
    )
    return int(cursor.lastrowid)


def get(conn: sqlite3.Connection, model_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM model_registry WHERE id = ?", (model_id,)).fetchone()


def active_for_family(conn: sqlite3.Connection, family: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM model_registry WHERE model_family = ? AND is_active = 1", (family,)
    ).fetchone()


def list_models(conn: sqlite3.Connection, family: Optional[str] = None) -> List[sqlite3.Row]:
    sql = ("SELECT m.*, u.email AS created_by_email FROM model_registry m "
           "LEFT JOIN users u ON u.id = m.created_by")
    params: tuple = ()
    if family:
        sql += " WHERE m.model_family = ?"
        params = (family,)
    return conn.execute(sql + " ORDER BY m.trained_at DESC, m.id DESC", params).fetchall()


def deactivate_family(conn: sqlite3.Connection, family: str) -> None:
    conn.execute("UPDATE model_registry SET is_active = 0 WHERE model_family = ? AND is_active = 1", (family,))


def set_active(conn: sqlite3.Connection, model_id: int) -> None:
    conn.execute("UPDATE model_registry SET is_active = 1 WHERE id = ?", (model_id,))
