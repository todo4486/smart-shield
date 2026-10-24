"""Server-side sign-in session kept in ``st.session_state``.

Only ``user_id``, ``last_activity`` and the user's ``session_epoch`` are stored. The
user is reloaded from the database on every rerun, so role changes, deactivation and
password changes take effect immediately. Limitation: Streamlit session state lives in
server memory per browser tab, so refreshing the page or opening a new tab means
signing in again.

Signing in, signing out and expiring a session all wipe the rest of the tab's state
(generated reports, previews, form values), so nothing from one user is ever shown to
the next person who uses the same tab.

Functions take any mutable mapping so they can be unit-tested without Streamlit.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import MutableMapping, Optional

from config import get_settings
from services import auth_service
from services.authorization import Principal
from services.timeutil import utc_now

USER_ID_KEY = "auth_user_id"
LAST_ACTIVITY_KEY = "auth_last_activity"
EPOCH_KEY = "auth_session_epoch"
FLASH_KEY = "auth_flash"


def _reset(state: MutableMapping) -> None:
    """Remove everything from the tab's state except a pending flash message."""
    for key in list(state.keys()):
        if key != FLASH_KEY:
            del state[key]


def start(state: MutableMapping, user: auth_service.User, *, now: Optional[datetime] = None) -> Principal:
    _reset(state)
    state.pop(FLASH_KEY, None)
    state[USER_ID_KEY] = user.id
    state[LAST_ACTIVITY_KEY] = now or utc_now()
    state[EPOCH_KEY] = user.session_epoch
    return user.to_principal()


def clear(state: MutableMapping) -> None:
    _reset(state)


def _end(state: MutableMapping, message: str) -> None:
    _reset(state)
    state[FLASH_KEY] = message


def resolve(state: MutableMapping, *, now: Optional[datetime] = None) -> Optional[Principal]:
    """Return the signed-in principal, or None (expiring idle, revoked or invalid sessions)."""
    user_id = state.get(USER_ID_KEY)
    if user_id is None:
        return None
    now = now or utc_now()
    last = state.get(LAST_ACTIVITY_KEY)
    idle_limit = timedelta(minutes=get_settings().session_idle_minutes)
    if not isinstance(last, datetime) or now - last > idle_limit:
        user = auth_service.get_user(int(user_id))
        _end(state, "Your session expired after a period of inactivity. Please sign in again.")
        if user is not None:
            auth_service.record_logout(user.to_principal(), reason="idle_timeout")
        return None
    user = auth_service.get_user(int(user_id))
    if user is None or not user.is_active:
        _end(state, "Your account is no longer active. Contact an administrator.")
        return None
    if state.get(EPOCH_KEY, 0) != user.session_epoch:
        _end(state, "Your password was changed, so you have been signed out. Please sign in again.")
        auth_service.record_logout(user.to_principal(), reason="password_changed")
        return None
    state[LAST_ACTIVITY_KEY] = now
    return user.to_principal()


def refresh_epoch(state: MutableMapping) -> None:
    """Keep the current tab signed in after it changed its own password."""
    user_id = state.get(USER_ID_KEY)
    user = auth_service.get_user(int(user_id)) if user_id is not None else None
    if user is not None:
        state[EPOCH_KEY] = user.session_epoch


def logout(state: MutableMapping) -> None:
    user_id = state.get(USER_ID_KEY)
    if user_id is not None:
        user = auth_service.get_user(int(user_id))
        if user is not None:
            auth_service.record_logout(user.to_principal())
    _end(state, "You have been signed out.")


def pop_flash(state: MutableMapping) -> Optional[str]:
    return state.pop(FLASH_KEY, None)
