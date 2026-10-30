"""SQL for mitigation_actions and allocation_snapshots."""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional, Sequence

OPEN_STATUSES = ("proposed", "active")


def insert(conn: sqlite3.Connection, values: Dict[str, Any]) -> int:
    columns = ", ".join(values)
    marks = ", ".join("?" for _ in values)
    return int(conn.execute(f"INSERT INTO mitigation_actions ({columns}) VALUES ({marks})", list(values.values())).lastrowid)


UPDATABLE = frozenset({
    "incident_id", "status", "limit_bps", "duration_seconds", "reason", "previous_allocation_json", "new_allocation_json",
    "before_json", "after_json", "recovery_status", "recovery_note", "adapter", "execution_ms", "failure_reason",
    "decided_at", "decided_by", "decision_note", "applied_at", "expires_at", "ended_at", "ended_by", "end_reason",
    "upstream_required", "severity", "confidence", "confidence_basis", "false_positive_risk", "repetition", "flagged_flows",
    "traffic_bps", "assessment_json",
})


def update(conn: sqlite3.Connection, mitigation_id: int, values: Dict[str, Any]) -> None:
    unknown = set(values) - UPDATABLE
    if unknown:
        raise ValueError(f"not updatable: {sorted(unknown)}")
    assignments = ", ".join(f"{column} = ?" for column in values)
    conn.execute(f"UPDATE mitigation_actions SET {assignments} WHERE id = ?", [*values.values(), mitigation_id])


def get(conn: sqlite3.Connection, mitigation_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM mitigation_actions WHERE id = ?", (mitigation_id,)).fetchone()


def of_session(conn: sqlite3.Connection, session_id: int, statuses: Optional[Sequence[str]] = None) -> List[sqlite3.Row]:
    sql, params = "SELECT * FROM mitigation_actions WHERE session_id = ?", [session_id]
    if statuses:
        sql += f" AND status IN ({', '.join('?' for _ in statuses)})"
        params.extend(statuses)
    return conn.execute(sql + " ORDER BY id DESC", params).fetchall()


def recent(conn: sqlite3.Connection, limit: int = 100) -> List[sqlite3.Row]:
    return conn.execute("SELECT * FROM mitigation_actions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def open_for_target(conn: sqlite3.Connection, session_id: int, target_kind: str, target: str) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM mitigation_actions WHERE session_id = ? AND target_kind = ? AND target = ? "
        "AND status IN ('proposed', 'active')", (session_id, target_kind, target)).fetchall()


def last_refused(conn: sqlite3.Connection, session_id: int, target_kind: str, target: str) -> Optional[sqlite3.Row]:
    """The newest action on this target an administrator said no to or took back."""
    return conn.execute(
        "SELECT * FROM mitigation_actions WHERE session_id = ? AND target_kind = ? AND target = ? "
        "AND status IN ('rejected', 'rolled_back') ORDER BY id DESC LIMIT 1", (session_id, target_kind, target)).fetchone()


def delete_simulation(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM mitigation_actions WHERE origin = 'simulation'")


def count_simulation(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM mitigation_actions WHERE origin = 'simulation'").fetchone()[0])


def flagged_flows_since(conn: sqlite3.Connection, session_id: int, since: str) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT src_ip, dst_ip, intrusion_prediction, timestamp, json_extract(feature_summary_json, "
        "'$.model_score_uncalibrated') AS score FROM network_flows WHERE session_id = ? AND timestamp >= ? "
        "AND intrusion_prediction IS NOT NULL AND src_ip IS NOT NULL AND dst_ip IS NOT NULL", (session_id, since)).fetchall()


def flow_totals_since(conn: sqlite3.Connection, session_id: int, since: str) -> Dict[str, int]:
    rows = conn.execute("SELECT src_ip, COUNT(*) AS flows FROM network_flows WHERE session_id = ? AND timestamp >= ? "
                        "AND src_ip IS NOT NULL GROUP BY src_ip", (session_id, since)).fetchall()
    return {r["src_ip"]: int(r["flows"]) for r in rows}


def metrics_between(conn: sqlite3.Connection, session_id: int, start: str, end: str) -> List[sqlite3.Row]:
    return conn.execute("SELECT * FROM network_metrics WHERE session_id = ? AND timestamp > ? AND timestamp <= ? "
                        "ORDER BY timestamp", (session_id, start, end)).fetchall()


def host_metrics_between(conn: sqlite3.Connection, session_id: int, start: str, end: str) -> List[sqlite3.Row]:
    return conn.execute("SELECT * FROM host_metrics WHERE session_id = ? AND timestamp > ? AND timestamp <= ?",
                        (session_id, start, end)).fetchall()


def incident_for_category(conn: sqlite3.Connection, session_id: int, category: Optional[str]) -> Optional[int]:
    """The newest incident holding an alert of this session and category, or of this session if none matches."""
    row = conn.execute(
        "SELECT ia.incident_id FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id WHERE a.session_id = ? "
        "ORDER BY (a.category = ?) DESC, ia.incident_id DESC LIMIT 1", (session_id, category)).fetchone()
    return None if row is None else int(row["incident_id"])


def insert_allocation(conn: sqlite3.Connection, *, session_id: int, timestamp: str, capacity_bps: float, enforced: bool,
                      classes_json: str, hosts_json: str) -> None:
    conn.execute(
        "INSERT INTO allocation_snapshots (session_id, timestamp, capacity_bps, enforced, classes_json, hosts_json, "
        "provenance) VALUES (?, ?, ?, ?, ?, ?, 'derived')",
        (session_id, timestamp, capacity_bps, int(enforced), classes_json, hosts_json))


def latest_allocation(conn: sqlite3.Connection, session_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM allocation_snapshots WHERE session_id = ? ORDER BY timestamp DESC, id DESC LIMIT 1",
                        (session_id,)).fetchone()


def allocation_history(conn: sqlite3.Connection, session_id: int, limit: int) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT timestamp, capacity_bps, enforced, classes_json FROM allocation_snapshots WHERE session_id = ? "
        "ORDER BY timestamp DESC, id DESC LIMIT ?", (session_id, limit)).fetchall()
