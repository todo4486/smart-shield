"""SQL for bandwidth_policies, bandwidth_recommendations and policy_actions."""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional


def policy_names(conn: sqlite3.Connection) -> List[str]:
    return [r[0] for r in conn.execute("SELECT DISTINCT policy_name FROM bandwidth_policies ORDER BY policy_name")]


def policy_rows(conn: sqlite3.Connection, policy_name: str) -> List[sqlite3.Row]:
    return conn.execute("SELECT * FROM bandwidth_policies WHERE policy_name = ? ORDER BY priority_weight DESC, traffic_class",
                        (policy_name,)).fetchall()


def delete_policy(conn: sqlite3.Connection, policy_name: str) -> None:
    conn.execute("DELETE FROM bandwidth_policies WHERE policy_name = ?", (policy_name,))


def insert_policy_row(conn: sqlite3.Connection, values: Dict[str, Any]) -> None:
    columns = ("policy_name", "interface_name", "configured_capacity_bps", "traffic_class", "minimum_bps",
               "maximum_bps", "priority_weight", "enabled", "dscp", "created_at", "updated_at")
    conn.execute(f"INSERT INTO bandwidth_policies ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
                 tuple(values.get(c) for c in columns))


def insert_recommendation(conn: sqlite3.Connection, values: Dict[str, Any]) -> int:
    columns = ("timestamp", "source_name", "interface_name", "capacity_bps", "recommendation_json",
               "unmet_demand_bps", "rationale", "status", "created_by")
    cursor = conn.execute(
        f"INSERT INTO bandwidth_recommendations ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
        tuple(values.get(c) for c in columns))
    return int(cursor.lastrowid)


def get_recommendation(conn: sqlite3.Connection, recommendation_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM bandwidth_recommendations WHERE id = ?", (recommendation_id,)).fetchone()


def list_recommendations(conn: sqlite3.Connection, limit: int = 200) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT r.*, u.email AS created_by_email FROM bandwidth_recommendations r "
        "LEFT JOIN users u ON u.id = r.created_by ORDER BY r.timestamp DESC, r.id DESC LIMIT ?", (limit,)
    ).fetchall()


def set_recommendation_status(conn: sqlite3.Connection, recommendation_id: int, status: str) -> None:
    conn.execute("UPDATE bandwidth_recommendations SET status = ? WHERE id = ?", (status, recommendation_id))


def insert_action(conn: sqlite3.Connection, values: Dict[str, Any]) -> int:
    columns = ("recommendation_id", "action_type", "target_interface", "policy_before_json", "policy_after_json",
               "status", "executed_by", "executed_at", "rollback_at", "error_message")
    cursor = conn.execute(f"INSERT INTO policy_actions ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
                          tuple(values.get(c) for c in columns))
    return int(cursor.lastrowid)


def last_successful_apply(conn: sqlite3.Connection, interface: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM policy_actions WHERE target_interface = ? AND action_type = 'apply' AND status = 'succeeded' "
        "ORDER BY executed_at DESC, id DESC LIMIT 1", (interface,)).fetchone()


def mark_rolled_back(conn: sqlite3.Connection, action_id: int, now: str) -> None:
    conn.execute("UPDATE policy_actions SET status = 'rolled_back', rollback_at = ? WHERE id = ?", (now, action_id))


def list_actions(conn: sqlite3.Connection, limit: int = 200) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT a.*, u.email AS executed_by_email FROM policy_actions a LEFT JOIN users u ON u.id = a.executed_by "
        "ORDER BY a.executed_at DESC, a.id DESC LIMIT ?", (limit,)).fetchall()
