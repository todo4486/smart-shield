"""Monitoring sessions: the shared record for every telemetry source
(historical imports and datasets now, live capture in Phase 7).

States are persisted and only change along ALLOWED_TRANSITIONS.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional

from repositories import monitoring_repository
from services import audit_service, database_service
from services.authorization import Permission, Principal, require_permission
from services.timeutil import utc_now_iso


class SessionState(str, Enum):
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    ERROR = "ERROR"


class SourceType(str, Enum):
    DATASET = "dataset"
    HISTORICAL_IMPORT = "historical_import"
    FLOW_IMPORT = "flow_import"
    LIVE_CAPTURE = "live_capture"


ALLOWED_TRANSITIONS = {
    SessionState.STARTING: {SessionState.RUNNING, SessionState.ERROR, SessionState.STOPPED},
    SessionState.RUNNING: {SessionState.STOPPING, SessionState.ERROR},
    SessionState.STOPPING: {SessionState.STOPPED, SessionState.ERROR},
    SessionState.STOPPED: set(),
    SessionState.ERROR: set(),
}
TERMINAL_STATES = {SessionState.STOPPED, SessionState.ERROR}


class InvalidTransition(Exception):
    pass


class SessionNotFound(Exception):
    pass


@dataclass(frozen=True)
class SessionSummary:
    id: int
    source_type: str
    interface_name: Optional[str]
    started_at: str
    ended_at: Optional[str]
    status: str
    status_message: Optional[str]
    dataset_id: Optional[int]
    configuration: Dict[str, Any]
    user_email: Optional[str]
    metric_count: int
    flow_count: int


def create_session(
    conn: sqlite3.Connection,
    *,
    user_id: Optional[int],
    source_type: SourceType,
    interface_name: Optional[str] = None,
    configuration: Optional[Mapping[str, Any]] = None,
    dataset_id: Optional[int] = None,
) -> int:
    return monitoring_repository.insert(
        conn,
        user_id=user_id,
        source_type=SourceType(source_type).value,
        interface_name=interface_name,
        started_at=utc_now_iso(),
        status=SessionState.STARTING.value,
        configuration_json=json.dumps(dict(configuration or {}), sort_keys=True, default=str),
        dataset_id=dataset_id,
    )


def transition(
    conn: sqlite3.Connection, session_id: int, new_state: SessionState, message: Optional[str] = None
) -> None:
    row = monitoring_repository.get(conn, session_id)
    if row is None:
        raise SessionNotFound(f"Monitoring session {session_id} does not exist.")
    current = SessionState(row["status"])
    new_state = SessionState(new_state)
    if new_state not in ALLOWED_TRANSITIONS[current]:
        raise InvalidTransition(f"Cannot move a session from {current.value} to {new_state.value}.")
    monitoring_repository.update_status(
        conn,
        session_id,
        status=new_state.value,
        status_message=message,
        ended_at=utc_now_iso() if new_state in TERMINAL_STATES else None,
    )


def fail_session(session_id: int, message: str) -> None:
    """Mark a session ERROR in its own transaction (used after a rolled-back import)."""
    with database_service.session(write=True) as conn:
        row = monitoring_repository.get(conn, session_id)
        if row is not None and SessionState(row["status"]) not in TERMINAL_STATES:
            transition(conn, session_id, SessionState.ERROR, message[:500])


def list_sessions(principal: Principal, limit: int = 200) -> List[SessionSummary]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="monitoring.list_sessions")
    with database_service.session() as conn:
        rows = monitoring_repository.list_with_counts(conn, limit)
    return [
        SessionSummary(
            id=r["id"], source_type=r["source_type"], interface_name=r["interface_name"],
            started_at=r["started_at"], ended_at=r["ended_at"], status=r["status"],
            status_message=r["status_message"], dataset_id=r["dataset_id"],
            configuration=json.loads(r["configuration_json"]) if r["configuration_json"] else {},
            user_email=r["user_email"], metric_count=r["metric_count"], flow_count=r["flow_count"],
        )
        for r in rows
    ]


def delete_session(principal: Principal, session_id: int) -> None:
    """Delete a finished session and (by cascade) its metrics and flows. Admin-only."""
    require_permission(principal, Permission.DELETE_DATA, action="monitoring.delete_session",
                       details={"session_id": session_id})
    with database_service.session(write=True) as conn:
        row = monitoring_repository.get(conn, session_id)
        if row is None:
            raise SessionNotFound(f"Monitoring session {session_id} does not exist.")
        if SessionState(row["status"]) not in TERMINAL_STATES:
            raise InvalidTransition("Only stopped or failed sessions can be deleted.")
        metric_count = conn.execute("SELECT COUNT(*) FROM network_metrics WHERE session_id = ?", (session_id,)).fetchone()[0]
        flow_count = conn.execute("SELECT COUNT(*) FROM network_flows WHERE session_id = ?", (session_id,)).fetchone()[0]
        monitoring_repository.delete(conn, session_id)
        audit_service.record(
            conn, user_id=principal.user_id, action="monitoring.delete_session",
            details={"session_id": session_id, "source_type": row["source_type"],
                     "metrics_deleted": metric_count, "flows_deleted": flow_count},
        )


def recover_interrupted_sessions() -> int:
    """Live sessions left STARTING/RUNNING/STOPPING by a previous app process cannot still be running."""
    with database_service.session(write=True) as conn:
        rows = conn.execute(
            "SELECT id, status FROM monitoring_sessions WHERE source_type = 'live_capture' "
            "AND status IN ('STARTING', 'RUNNING', 'STOPPING')"
        ).fetchall()
        for row in rows:
            transition(conn, row["id"], SessionState.ERROR,
                       "The application stopped while this capture was active; the session was closed on restart.")
    return len(rows)
