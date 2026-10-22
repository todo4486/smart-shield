"""Administration: user management and the audit log viewer. Admin-only."""
from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional

from repositories import audit_repository, user_repository
from services import audit_service, database_service
from services.authorization import Permission, Principal, Role, require_permission
from services.timeutil import utc_now_iso

MAX_AUDIT_ROWS = 1000


class AdminActionError(Exception):
    """A refused administrative change (shown to the admin as-is)."""


@dataclass(frozen=True)
class UserSummary:
    id: int
    name: str
    email: str
    role: Role
    is_active: bool
    created_at: str
    last_login_at: Optional[str]


@dataclass(frozen=True)
class AuditEntry:
    id: int
    created_at: str
    user_id: Optional[int]
    user_email: Optional[str]
    action: str
    outcome: str
    details: Dict[str, Any]


def list_users(principal: Principal) -> List[UserSummary]:
    require_permission(principal, Permission.MANAGE_USERS, action="admin.list_users")
    with database_service.session() as conn:
        rows = user_repository.list_users(conn)
    return [
        UserSummary(
            id=r["id"],
            name=r["name"],
            email=r["email"],
            role=Role(r["role"]),
            is_active=bool(r["is_active"]),
            created_at=r["created_at"],
            last_login_at=r["last_login_at"],
        )
        for r in rows
    ]


def change_role(principal: Principal, user_id: int, new_role: Role) -> None:
    new_role = Role(new_role)
    require_permission(
        principal, Permission.MANAGE_USERS, action="admin.change_role",
        details={"target_user_id": user_id, "new_role": new_role.value},
    )
    with _refusals_audited(principal, "admin.change_role", user_id), database_service.session(write=True) as conn:
        target = user_repository.get_by_id(conn, user_id)
        if target is None:
            raise AdminActionError("User not found.")
        old_role = Role(target["role"])
        if old_role is new_role:
            return
        if (
            old_role is Role.ADMIN
            and target["is_active"]
            and user_repository.count_active_admins(conn) <= 1
        ):
            raise _Refused("last_admin")
        user_repository.update_role(conn, user_id, new_role.value, utc_now_iso())
        audit_service.record(
            conn, user_id=principal.user_id, action="admin.change_role",
            details={"target_user_id": user_id, "from": old_role.value, "to": new_role.value},
        )


def set_active(principal: Principal, user_id: int, active: bool) -> None:
    require_permission(
        principal, Permission.MANAGE_USERS, action="admin.set_active",
        details={"target_user_id": user_id, "active": bool(active)},
    )
    with _refusals_audited(principal, "admin.set_active", user_id), database_service.session(write=True) as conn:
        target = user_repository.get_by_id(conn, user_id)
        if target is None:
            raise AdminActionError("User not found.")
        if bool(target["is_active"]) == bool(active):
            return
        if not active:
            if user_id == principal.user_id:
                raise _Refused("self_deactivation")
            if target["role"] == Role.ADMIN.value and user_repository.count_active_admins(conn) <= 1:
                raise _Refused("last_admin")
        user_repository.update_active(conn, user_id, active, utc_now_iso())
        audit_service.record(
            conn, user_id=principal.user_id, action="admin.set_active",
            details={"target_user_id": user_id, "active": bool(active)},
        )


_REFUSAL_MESSAGES = {
    "last_admin": "This is the last active administrator. Promote another user to admin first.",
    "self_deactivation": "You cannot deactivate your own account. Ask another administrator.",
}


class _Refused(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@contextmanager
def _refusals_audited(principal: Principal, action: str, user_id: int) -> Iterator[None]:
    """Turn a refusal raised inside the write transaction into an audited AdminActionError.

    Placed outside ``database_service.session`` so the transaction has already
    rolled back (and released its lock) before the audit entry is written.
    """
    try:
        yield
    except _Refused as refused:
        audit_service.record_standalone(
            user_id=principal.user_id, action=action, outcome="failure",
            details={"target_user_id": user_id, "reason": refused.reason},
        )
        raise AdminActionError(_REFUSAL_MESSAGES[refused.reason]) from None


def list_audit_log(
    principal: Principal,
    *,
    limit: int = 200,
    outcome: Optional[str] = None,
    action_prefix: Optional[str] = None,
) -> List[AuditEntry]:
    require_permission(principal, Permission.VIEW_AUDIT_LOG, action="admin.view_audit_log")
    limit = max(1, min(int(limit), MAX_AUDIT_ROWS))
    if outcome is not None and outcome not in audit_service.OUTCOMES:
        raise AdminActionError("Unknown outcome filter.")
    with database_service.session() as conn:
        rows = audit_repository.list_entries(
            conn, limit=limit, outcome=outcome, action_prefix=(action_prefix or "").strip() or None
        )
    return [
        AuditEntry(
            id=r["id"],
            created_at=r["created_at"],
            user_id=r["user_id"],
            user_email=r["user_email"],
            action=r["action"],
            outcome=r["outcome"],
            details=json.loads(r["details_json"]) if r["details_json"] else {},
        )
        for r in rows
    ]


def audit_actions(principal: Principal) -> List[str]:
    require_permission(principal, Permission.VIEW_AUDIT_LOG, action="admin.view_audit_log")
    with database_service.session() as conn:
        return audit_repository.distinct_actions(conn)
