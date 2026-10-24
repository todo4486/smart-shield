"""My account: profile details and password change."""
from __future__ import annotations

import streamlit as st

from components.guard import require_principal
from components.ui import format_timestamp, page_header
from services import auth_service, session_service

principal = require_principal()
page_header("My account", "Your profile and password. Changes are recorded in the audit log.", eyebrow="Workspace")

user = auth_service.get_user(principal.user_id)
c1, c2, c3 = st.columns(3)
c1.metric("Role", principal.role.value)
c2.metric("Member since", format_timestamp(user.created_at)[:10] if user else "—")
c3.metric("Last sign-in", format_timestamp(user.last_login_at) if user and user.last_login_at else "—")

with st.form("change_password", border=True, clear_on_submit=True):
    st.markdown("**Change password**")
    current = st.text_input("Current password", type="password", autocomplete="current-password")
    new = st.text_input("New password", type="password", autocomplete="new-password", max_chars=128,
                        help="10–128 characters, including an uppercase letter, a lowercase letter and a digit.")
    confirm = st.text_input("Confirm new password", type="password", autocomplete="new-password", max_chars=128)
    submitted = st.form_submit_button("Change password", type="primary")
if submitted:
    if new != confirm:
        st.error("The new passwords do not match.")
    else:
        try:
            auth_service.change_password(principal, current, new)
        except auth_service.AuthError as exc:
            st.error(str(exc))
        else:
            session_service.refresh_epoch(st.session_state)  # this tab stays signed in; all others are signed out
            st.success("Password changed. Any other signed-in tabs or devices have been signed out.")
st.caption("Forgot your password? An operator can reset it on the server with "
           "`python -m scripts.manage reset-password --email you@example.com`.")
