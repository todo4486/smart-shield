"""SQL for login_attempts (lockout tracking per normalized email key)."""
from __future__ import annotations

import sqlite3
from typing import Optional


def record_attempt(conn: sqlite3.Connection, email_key: str, succeeded: bool, now: str) -> None:
    conn.execute(
        "INSERT INTO login_attempts (email_key, attempted_at, succeeded) VALUES (?, ?, ?)",
        (email_key, now, 1 if succeeded else 0),
    )


def recent_failures(conn: sqlite3.Connection, email_key: str, since: str) -> int:
    """Failures for this key at or after ``since`` and after the last success."""
    return conn.execute(
        "SELECT COUNT(*) FROM login_attempts "
        "WHERE email_key = ? AND succeeded = 0 AND attempted_at >= ? "
        "AND attempted_at > COALESCE("
        "  (SELECT MAX(attempted_at) FROM login_attempts WHERE email_key = ? AND succeeded = 1), '')",
        (email_key, since, email_key),
    ).fetchone()[0]


def latest_failure_at(conn: sqlite3.Connection, email_key: str) -> Optional[str]:
    row = conn.execute(
        "SELECT MAX(attempted_at) FROM login_attempts WHERE email_key = ? AND succeeded = 0",
        (email_key,),
    ).fetchone()
    return row[0] if row else None
