"""Page guard: every view calls require_principal() first."""
from __future__ import annotations

import streamlit as st

from services import session_service
from services.authorization import Permission, Principal


def require_principal() -> Principal:
    principal = session_service.resolve(st.session_state)
    if principal is None:
        st.warning("Please sign in to continue.")
        st.stop()
    return principal


def require_page_permission(principal: Principal, permission: Permission) -> None:
    """Cosmetic early exit for pages; services still enforce the real check."""
    if not principal.has(permission):
        st.error("You do not have access to this page.")
        st.stop()
