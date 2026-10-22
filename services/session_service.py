"""Server-side sign-in session kept in ``st.session_state``.

Only ``user_id`` and ``last_activity`` are stored. The user is reloaded from
the database on every rerun, so role changes and deactivation take effect
immediately. Limitation: Streamlit session state lives in server memory per
browser tab, so refreshing the page or opening a new tab means signing in again.

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
FLASH_KEY = "auth_flash"


def start(state: MutableMapping, user: auth_service.User, *, now: Optional[datetime] = None) -> Principal:
    state[USER_ID_KEY] = user.id
    state[LAST_ACTIVITY_KEY] = now or utc_now()
    state.pop(FLASH_KEY, None)
    return user.to_principal()


def clear(state: MutableMapping) -> None:
    state.pop(USER_ID_KEY, None)
    state.pop(LAST_ACTIVITY_KEY, None)


def resolve(state: MutableMapping, *, now: Optional[datetime] = None) -> Optional[Principal]:
    """Return the signed-in principal, or None (expiring idle/invalid sessions)."""
    user_id = state.get(USER_ID_KEY)
    if user_id is None:
        return None
    now = now or utc_now()
    last = state.get(LAST_ACTIVITY_KEY)
    idle_limit = timedelta(minutes=get_settings().session_idle_minutes)
    if not isinstance(last, datetime) or now - last > idle_limit:
        user = auth_service.get_user(int(user_id))
        clear(state)
        state[FLASH_KEY] = "Your session expired after a period of inactivity. Please sign in again."
        if user is not None:
            auth_service.record_logout(user.to_principal(), reason="idle_timeout")
        return None
    user = auth_service.get_user(int(user_id))
    if user is None or not user.is_active:
        clear(state)
        state[FLASH_KEY] = "Your account is no longer active. Contact an administrator."
        return None
    state[LAST_ACTIVITY_KEY] = now
    return user.to_principal()


def logout(state: MutableMapping) -> None:
    user_id = state.get(USER_ID_KEY)
    if user_id is not None:
        user = auth_service.get_user(int(user_id))
        if user is not None:
            auth_service.record_logout(user.to_principal())
    clear(state)
    state[FLASH_KEY] = "You have been signed out."


def pop_flash(state: MutableMapping) -> Optional[str]:
    return state.pop(FLASH_KEY, None)
