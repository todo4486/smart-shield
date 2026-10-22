from __future__ import annotations

import sqlite3

import pytest

from services import dashboard_service, database_service, user_admin_service
from services.authorization import ROLE_PERMISSIONS, Permission, PermissionDenied, Principal, Role, require_permission
from tests.conftest import audit_rows

ADMIN_ONLY = {
    Permission.MANAGE_USERS,
    Permission.VIEW_AUDIT_LOG,
    Permission.MANAGE_SETTINGS,
    Permission.ACTIVATE_MODELS,
    Permission.CONTROL_MONITORING,
    Permission.APPLY_TRAFFIC_POLICY,
    Permission.DELETE_DATA,
}


def test_admin_has_every_permission():
    assert ROLE_PERMISSIONS[Role.ADMIN] == frozenset(Permission)


def test_analyst_lacks_admin_only_permissions():
    analyst_perms = ROLE_PERMISSIONS[Role.ANALYST]
    assert analyst_perms.isdisjoint(ADMIN_ONLY)
    assert Permission.VIEW_DASHBOARD in analyst_perms


def test_require_permission_with_no_principal_is_denied_and_audited():
    with pytest.raises(PermissionDenied):
        require_permission(None, Permission.VIEW_DASHBOARD, action="dashboard.view")
    assert len(audit_rows("dashboard.view", "denied")) == 1


@pytest.mark.parametrize(
    "call",
    [
        lambda p, target: user_admin_service.list_users(p),
        lambda p, target: user_admin_service.change_role(p, target, Role.ADMIN),
        lambda p, target: user_admin_service.set_active(p, target, False),
        lambda p, target: user_admin_service.list_audit_log(p),
    ],
    ids=["list_users", "change_role", "set_active", "audit_log"],
)
def test_analyst_blocked_from_admin_services(analyst, admin, call):
    with pytest.raises(PermissionDenied):
        call(analyst, admin.user_id)
    denied = audit_rows(outcome="denied")
    assert len(denied) == 1
    assert denied[0]["user_id"] == analyst.user_id


def test_analyst_cannot_escalate_self(analyst):
    with pytest.raises(PermissionDenied):
        user_admin_service.change_role(analyst, analyst.user_id, Role.ADMIN)
    with database_service.session() as conn:
        assert conn.execute("SELECT role FROM users WHERE id = ?", (analyst.user_id,)).fetchone()[0] == "analyst"


def test_analyst_can_view_dashboard(analyst):
    data = dashboard_service.get_overview(analyst)
    assert not data.has_any_data


def test_admin_can_promote_and_demote(admin, analyst):
    user_admin_service.change_role(admin, analyst.user_id, Role.ADMIN)
    user_admin_service.change_role(admin, admin.user_id, Role.ANALYST)
    roles = {u.id: u.role for u in user_admin_service.list_users(Principal(analyst.user_id, "a", "a@x.io", Role.ADMIN))}
    assert roles[analyst.user_id] is Role.ADMIN
    assert roles[admin.user_id] is Role.ANALYST
    assert len(audit_rows("admin.change_role", "success")) == 2


def test_last_admin_cannot_be_demoted(admin, analyst):
    with pytest.raises(user_admin_service.AdminActionError, match="last active administrator"):
        user_admin_service.change_role(admin, admin.user_id, Role.ANALYST)
    assert len(audit_rows("admin.change_role", "failure")) == 1


def test_admin_cannot_deactivate_self(admin, analyst):
    user_admin_service.change_role(admin, analyst.user_id, Role.ADMIN)
    with pytest.raises(user_admin_service.AdminActionError, match="your own account"):
        user_admin_service.set_active(admin, admin.user_id, False)


def test_last_admin_cannot_be_deactivated_by_other_admin_path(admin, analyst):
    # Make analyst an admin, deactivate the original admin, then try to deactivate the last one.
    user_admin_service.change_role(admin, analyst.user_id, Role.ADMIN)
    second_admin = Principal(analyst.user_id, "Alan", "alan@example.com", Role.ADMIN)
    user_admin_service.set_active(second_admin, admin.user_id, False)
    with pytest.raises(user_admin_service.AdminActionError):
        user_admin_service.change_role(second_admin, second_admin.user_id, Role.ANALYST)


def test_database_trigger_protects_last_admin_even_without_service(admin):
    with pytest.raises(sqlite3.IntegrityError, match="last active admin"):
        with database_service.session(write=True) as conn:
            conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (admin.user_id,))
    with pytest.raises(sqlite3.IntegrityError, match="last active admin"):
        with database_service.session(write=True) as conn:
            conn.execute("DELETE FROM users WHERE id = ?", (admin.user_id,))


def test_admin_can_read_audit_log_with_filters(admin, analyst):
    with pytest.raises(PermissionDenied):
        user_admin_service.list_users(analyst)
    denied = user_admin_service.list_audit_log(admin, outcome="denied")
    assert [e.action for e in denied] == ["admin.list_users"]
    auth_entries = user_admin_service.list_audit_log(admin, action_prefix="auth.")
    assert auth_entries and all(e.action.startswith("auth.") for e in auth_entries)


def test_self_deactivation_refusal_is_audited_without_lock_wait(admin, analyst):
    import time

    started = time.monotonic()
    with pytest.raises(user_admin_service.AdminActionError):
        user_admin_service.set_active(admin, admin.user_id, False)
    assert time.monotonic() - started < 2
    rows = audit_rows("admin.set_active", "failure")
    assert len(rows) == 1 and "self_deactivation" in rows[0]["details_json"]
