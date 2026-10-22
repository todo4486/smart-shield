"""Roles, permissions and the acting Principal.

Every service function that reads or changes protected data takes a
``Principal`` and calls ``require_permission`` first. Hiding UI controls is
cosmetic; this is the real check. Denials are written to the audit log.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, FrozenSet, Mapping, Optional

from services import audit_service


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"


class Permission(str, Enum):
    VIEW_DASHBOARD = "view_dashboard"
    VIEW_ALERTS = "view_alerts"
    TRIAGE_ALERTS = "triage_alerts"
    MANAGE_DATASETS = "manage_datasets"
    TRAIN_MODELS = "train_models"
    ACTIVATE_MODELS = "activate_models"
    VIEW_REPORTS = "view_reports"
    CONTROL_MONITORING = "control_monitoring"
    MANAGE_SETTINGS = "manage_settings"
    APPLY_TRAFFIC_POLICY = "apply_traffic_policy"
    DELETE_DATA = "delete_data"
    MANAGE_USERS = "manage_users"
    VIEW_AUDIT_LOG = "view_audit_log"


_ANALYST: FrozenSet[Permission] = frozenset(
    {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_ALERTS,
        Permission.TRIAGE_ALERTS,
        Permission.MANAGE_DATASETS,
        Permission.TRAIN_MODELS,
        Permission.VIEW_REPORTS,
    }
)

ROLE_PERMISSIONS: Dict[Role, FrozenSet[Permission]] = {
    Role.ANALYST: _ANALYST,
    Role.ADMIN: frozenset(Permission),
}


@dataclass(frozen=True)
class Principal:
    user_id: int
    name: str
    email: str
    role: Role

    @property
    def is_admin(self) -> bool:
        return self.role is Role.ADMIN

    def has(self, permission: Permission) -> bool:
        return permission in ROLE_PERMISSIONS.get(self.role, frozenset())


class PermissionDenied(Exception):
    def __init__(self, permission: Permission):
        super().__init__(f"You do not have permission to perform this action ({permission.value}).")
        self.permission = permission


def require_permission(
    principal: Optional[Principal],
    permission: Permission,
    *,
    action: str,
    details: Optional[Mapping[str, Any]] = None,
) -> Principal:
    """Return the principal if allowed; otherwise audit the denial and raise."""
    if principal is not None and principal.has(permission):
        return principal
    audit_details = {"permission": permission.value, "role": principal.role.value if principal else None}
    if details:
        audit_details.update(details)
    audit_service.record_standalone(
        user_id=principal.user_id if principal else None,
        action=action,
        outcome="denied",
        details=audit_details,
    )
    raise PermissionDenied(permission)
