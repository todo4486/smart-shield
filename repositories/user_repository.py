"""SQL for the users table. Parameterized statements only."""
from __future__ import annotations

import sqlite3
from typing import List, Optional


def count_users(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def count_active_admins(conn: sqlite3.Connection) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1"
    ).fetchone()[0]


def get_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def insert_user(
    conn: sqlite3.Connection, *, name: str, email: str, password_hash: str, role: str, now: str
) -> int:
    cursor = conn.execute(
        "INSERT INTO users (name, email, password_hash, role, is_active, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 1, ?, ?)",
        (name, email, password_hash, role, now, now),
    )
    return int(cursor.lastrowid)


def update_password_hash(conn: sqlite3.Connection, user_id: int, password_hash: str, now: str) -> None:
    conn.execute(
        "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
        (password_hash, now, user_id),
    )


def update_last_login(conn: sqlite3.Connection, user_id: int, now: str) -> None:
    conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now, user_id))


def update_role(conn: sqlite3.Connection, user_id: int, role: str, now: str) -> None:
    conn.execute("UPDATE users SET role = ?, updated_at = ? WHERE id = ?", (role, now, user_id))


def update_active(conn: sqlite3.Connection, user_id: int, is_active: bool, now: str) -> None:
    conn.execute(
        "UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?",
        (1 if is_active else 0, now, user_id),
    )


def list_users(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT id, name, email, role, is_active, created_at, last_login_at "
        "FROM users ORDER BY created_at, id"
    ).fetchall()


def bump_session_epoch(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?", (user_id,))
