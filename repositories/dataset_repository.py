"""SQL for the datasets table."""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional


def find_by_sha(conn: sqlite3.Connection, kind: str, sha256: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM datasets WHERE kind = ? AND sha256 = ?", (kind, sha256)).fetchone()


def get(conn: sqlite3.Connection, dataset_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM datasets WHERE id = ?", (dataset_id,)).fetchone()


def insert(conn: sqlite3.Connection, values: Dict[str, Any]) -> int:
    columns = (
        "name", "kind", "original_filename", "stored_path", "sha256", "size_bytes", "row_count", "column_count",
        "columns_json", "label_column", "label_distribution_json", "has_timestamps", "profile_json",
        "uploaded_by", "uploaded_at",
    )
    placeholders = ", ".join("?" for _ in columns)
    cursor = conn.execute(
        f"INSERT INTO datasets ({', '.join(columns)}) VALUES ({placeholders})",
        tuple(values.get(c) for c in columns),
    )
    return int(cursor.lastrowid)


def list_all(conn: sqlite3.Connection, kind: Optional[str] = None) -> List[sqlite3.Row]:
    sql = (
        "SELECT d.*, u.email AS uploaded_by_email FROM datasets d "
        "LEFT JOIN users u ON u.id = d.uploaded_by"
    )
    params: tuple = ()
    if kind:
        sql += " WHERE d.kind = ?"
        params = (kind,)
    return conn.execute(sql + " ORDER BY d.uploaded_at DESC, d.id DESC", params).fetchall()


def delete(conn: sqlite3.Connection, dataset_id: int) -> None:
    conn.execute("DELETE FROM datasets WHERE id = ?", (dataset_id,))
