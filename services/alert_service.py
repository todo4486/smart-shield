"""Alerts shared by Smart Shield (security/anomaly) and PredictNet (congestion/performance).

* Creation is deduplicated: an alert with the same dedup_key is not repeated
  while an earlier one is unresolved or still inside the cooldown window.
* Triage follows ALLOWED_TRANSITIONS and every change is written to
  alert_events (status history) and the audit log.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, List, Mapping, Optional

from repositories import alert_repository
from services import audit_service, database_service, suppression_service
from services.authorization import Permission, Principal, require_permission
from services.timeutil import to_iso, utc_now, utc_now_iso

STATUSES = ("open", "acknowledged", "resolved", "false_positive")
SEVERITIES = ("low", "medium", "high", "critical")
TYPES = ("security", "anomaly", "congestion", "performance")
ALLOWED_TRANSITIONS = {
    "open": {"acknowledged", "resolved", "false_positive"},
    "acknowledged": {"resolved", "false_positive", "open"},
    "resolved": {"open"},
    "false_positive": {"open"},
}
MAX_NOTE_LENGTH = 2000


class AlertError(Exception):
    pass


@dataclass(frozen=True)
class Alert:
    id: int
    session_id: Optional[int]
    alert_type: str
    severity: str
    category: str
    reason: str
    status: str
    evidence: Dict[str, Any]
    model_id: Optional[int]
    model_version: Optional[str]
    created_at: str
    acknowledged_at: Optional[str]
    resolved_at: Optional[str]
    investigation_notes: Optional[str]
    suppressed_by_rule: Optional[int] = None  # stored and visible under "Suppressed", left out of the queues

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Alert":
        return cls(
            id=row["id"], session_id=row["session_id"], alert_type=row["alert_type"], severity=row["severity"],
            category=row["category"], reason=row["reason"], status=row["status"],
            evidence=json.loads(row["evidence_json"]) if row["evidence_json"] else {},
            model_id=row["model_id"], model_version=row["model_version"], created_at=row["created_at"],
            acknowledged_at=row["acknowledged_at"], resolved_at=row["resolved_at"],
            investigation_notes=row["investigation_notes"],
            suppressed_by_rule=row["suppressed_by_rule"] if "suppressed_by_rule" in row.keys() else None,
        )


def create_alert(
    conn: sqlite3.Connection,
    *,
    alert_type: str,
    severity: str,
    category: str,
    reason: str,
    evidence: Mapping[str, Any],
    dedup_key: str,
    session_id: Optional[int] = None,
    model_id: Optional[int] = None,
    model_version: Optional[str] = None,
    cooldown_minutes: Optional[int] = None,
    created_by: Optional[int] = None,
) -> Optional[int]:
    """Insert an alert inside the caller's transaction, or return None if it is a duplicate.

    Duplicate = same dedup_key and either still unresolved, or created within the cooldown window.
    """
    if alert_type not in TYPES or severity not in SEVERITIES:
        raise AlertError("Invalid alert type or severity.")
    if alert_repository.find_recent_by_dedup(conn, dedup_key, unresolved_only=True):
        return None
    if cooldown_minutes:
        since = to_iso(utc_now() - timedelta(minutes=cooldown_minutes))
        if alert_repository.find_recent_by_dedup(conn, dedup_key, since=since):
            return None
    now = utc_now_iso()
    alert_id = alert_repository.insert(conn, {
        "session_id": session_id, "alert_type": alert_type, "severity": severity, "category": category[:120],
        "reason": reason[:2000], "status": "open", "dedup_key": dedup_key,
        "evidence_json": json.dumps(dict(evidence), default=str, sort_keys=True),
        "model_id": model_id, "model_version": model_version, "created_at": now,
    })
    alert_repository.insert_event(conn, alert_id=alert_id, event_type="created", from_status=None,
                                  to_status="open", note=None, user_id=created_by, now=now)
    rule = suppression_service.find_rule(conn, alert_type, category, evidence)
    if rule is not None:
        alert_repository.set_suppressed(conn, alert_id, rule.id)
        alert_repository.insert_event(conn, alert_id=alert_id, event_type="note", from_status=None, to_status=None,
                                      note=f"Suppressed by rule #{rule.id} ({rule.describe()}): {rule.reason}",
                                      user_id=None, now=now)
    return alert_id


def list_alerts(principal: Principal, *, statuses=None, severities=None, types=None, limit: int = 500,
                suppressed: str = "exclude") -> List[Alert]:
    """`suppressed`: "exclude" (default queues), "only" (the Suppressed filter) or "include"."""
    require_permission(principal, Permission.VIEW_ALERTS, action="alert.list")
    if suppressed not in ("exclude", "only", "include"):
        raise AlertError("Unknown suppression filter.")
    with database_service.session() as conn:
        rows = alert_repository.list_alerts(conn, statuses=statuses, severities=severities, types=types,
                                            limit=max(1, min(int(limit), 5000)), suppressed=suppressed)
    return [Alert.from_row(r) for r in rows]


def get_alert(principal: Principal, alert_id: int) -> tuple:
    """Return (alert, events)."""
    require_permission(principal, Permission.VIEW_ALERTS, action="alert.view")
    with database_service.session() as conn:
        row = alert_repository.get(conn, alert_id)
        if row is None:
            raise AlertError("Alert not found.")
        events = [dict(e) for e in alert_repository.events(conn, alert_id)]
    return Alert.from_row(row), events


def change_status(principal: Principal, alert_id: int, new_status: str, note: Optional[str] = None) -> None:
    require_permission(principal, Permission.TRIAGE_ALERTS, action="alert.change_status",
                       details={"alert_id": alert_id, "to": new_status})
    if new_status not in STATUSES:
        raise AlertError("Unknown status.")
    note = (note or "").strip()[:MAX_NOTE_LENGTH] or None
    now = utc_now_iso()
    with database_service.session(write=True) as conn:
        row = alert_repository.get(conn, alert_id)
        if row is None:
            raise AlertError("Alert not found.")
        current = row["status"]
        if new_status not in ALLOWED_TRANSITIONS[current]:
            raise AlertError(f"An alert cannot move from {current} to {new_status}.")
        values: Dict[str, Any] = {"status": new_status}
        if new_status == "acknowledged":
            values.update(acknowledged_by=principal.user_id, acknowledged_at=now)
        if new_status in ("resolved", "false_positive"):
            values.update(resolved_by=principal.user_id, resolved_at=now)
        if new_status == "open":
            values.update(resolved_by=None, resolved_at=None)
        alert_repository.update_status(conn, alert_id, values)
        alert_repository.insert_event(conn, alert_id=alert_id, event_type="status_change", from_status=current,
                                      to_status=new_status, note=note, user_id=principal.user_id, now=now)
        audit_service.record(conn, user_id=principal.user_id, action="alert.change_status",
                             details={"alert_id": alert_id, "from": current, "to": new_status})


def add_note(principal: Principal, alert_id: int, note: str) -> None:
    require_permission(principal, Permission.TRIAGE_ALERTS, action="alert.add_note", details={"alert_id": alert_id})
    note = (note or "").strip()
    if not note:
        raise AlertError("The note is empty.")
    note = note[:MAX_NOTE_LENGTH]
    now = utc_now_iso()
    with database_service.session(write=True) as conn:
        row = alert_repository.get(conn, alert_id)
        if row is None:
            raise AlertError("Alert not found.")
        combined = ((row["investigation_notes"] + "\n\n") if row["investigation_notes"] else "") + \
            f"[{now[:16].replace('T', ' ')} UTC · {principal.email}] {note}"
        alert_repository.update_status(conn, alert_id, {"investigation_notes": combined[-20000:]})
        alert_repository.insert_event(conn, alert_id=alert_id, event_type="note", from_status=None, to_status=None,
                                      note=note, user_id=principal.user_id, now=now)
        audit_service.record(conn, user_id=principal.user_id, action="alert.add_note", details={"alert_id": alert_id})


def daily_counts(principal: Principal, days: int = 30) -> List[dict]:
    require_permission(principal, Permission.VIEW_ALERTS, action="alert.list")
    since = to_iso(utc_now() - timedelta(days=days))
    with database_service.session() as conn:
        return [dict(r) for r in alert_repository.counts_by_day(conn, since)]
