"""Audit logging. ``record`` writes inside the caller's transaction;
``record_standalone`` commits on its own (used for denials and failures that
must persist even when the surrounding work is rolled back)."""
from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any, Mapping, Optional

from repositories import audit_repository
from services import database_service
from services.timeutil import utc_now_iso

logger = logging.getLogger(__name__)

OUTCOMES = ("success", "failure", "denied")


def _encode(details: Optional[Mapping[str, Any]]) -> Optional[str]:
    if not details:
        return None
    return json.dumps(dict(details), sort_keys=True, default=str)


def record(
    conn: sqlite3.Connection,
    *,
    user_id: Optional[int],
    action: str,
    outcome: str = "success",
    details: Optional[Mapping[str, Any]] = None,
) -> int:
    if outcome not in OUTCOMES:
        raise ValueError(f"invalid audit outcome {outcome!r}")
    return audit_repository.insert_entry(
        conn, user_id=user_id, action=action, outcome=outcome, details_json=_encode(details), now=utc_now_iso()
    )


def record_standalone(
    *,
    user_id: Optional[int],
    action: str,
    outcome: str,
    details: Optional[Mapping[str, Any]] = None,
) -> None:
    try:
        with database_service.session(write=True) as conn:
            record(conn, user_id=user_id, action=action, outcome=outcome, details=details)
    except sqlite3.Error:
        # Never let audit failure mask the original outcome, but make it visible.
        logger.exception("Failed to write audit entry %s/%s", action, outcome)
