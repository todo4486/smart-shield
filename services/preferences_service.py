"""Per-user display preferences. Every user manages only their own; changes are audited.

The light/dark theme is chosen in the app menu (⋮ → Settings) by Streamlit itself and is
remembered by the browser, so it is not stored here.
"""
from __future__ import annotations

from dataclasses import dataclass

from services import audit_service, database_service
from services.authorization import Permission, Principal, require_permission
from services.timeutil import utc_now_iso


@dataclass(frozen=True)
class Preferences:
    reduce_motion: bool = False


def get_preferences(principal: Principal) -> Preferences:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="preferences.view")
    with database_service.session() as conn:
        row = conn.execute("SELECT reduce_motion FROM user_preferences WHERE user_id = ?",
                           (principal.user_id,)).fetchone()
    return Preferences(reduce_motion=bool(row["reduce_motion"])) if row else Preferences()


def set_reduce_motion(principal: Principal, enabled: bool) -> Preferences:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="preferences.update")
    with database_service.session(write=True) as conn:
        conn.execute(
            "INSERT INTO user_preferences (user_id, reduce_motion, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT (user_id) DO UPDATE SET reduce_motion = excluded.reduce_motion, updated_at = excluded.updated_at",
            (principal.user_id, int(bool(enabled)), utc_now_iso()),
        )
        audit_service.record(conn, user_id=principal.user_id, action="preferences.update",
                             details={"reduce_motion": bool(enabled)})
    return Preferences(reduce_motion=bool(enabled))
