"""Administration (admin-only): users, roles, activation and the audit log."""
from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from components.guard import require_page_permission, require_principal
from components.ui import format_timestamp, page_header
from services import user_admin_service
from services.authorization import Permission, PermissionDenied, Role

principal = require_principal()
require_page_permission(principal, Permission.MANAGE_USERS)

page_header("Administration", "Manage accounts and roles, and review the audit trail. "
            "The last active administrator can never be demoted or deactivated.", eyebrow="Workspace")

users_tab, audit_tab = st.tabs(["Users", "Audit log"])

with users_tab:
    try:
        users = user_admin_service.list_users(principal)
    except PermissionDenied as exc:
        st.error(str(exc))
        st.stop()

    active_admins = sum(1 for u in users if u.role is Role.ADMIN and u.is_active)
    c1, c2, c3 = st.columns(3)
    c1.metric("Accounts", len(users))
    c2.metric("Active administrators", active_admins)
    c3.metric("Inactive accounts", sum(1 for u in users if not u.is_active))

    st.dataframe(
        pd.DataFrame(
            [
                {
                    "ID": u.id, "Name": u.name, "Email": u.email, "Role": u.role.value,
                    "Status": "Active" if u.is_active else "Inactive",
                    "Created": format_timestamp(u.created_at), "Last sign-in": format_timestamp(u.last_login_at),
                }
                for u in users
            ]
        ),
        hide_index=True,
    )

    st.subheader("Change an account")
    by_id = {u.id: u for u in users}
    selected_id = st.selectbox(
        "Account", options=list(by_id), format_func=lambda i: f"{by_id[i].name} <{by_id[i].email}>"
    )
    target = by_id[selected_id]
    left, right = st.columns(2)
    with left:
        with st.form("role_form", border=True):
            roles = [r.value for r in Role]
            new_role = st.radio("Role", roles, index=roles.index(target.role.value), horizontal=True)
            if st.form_submit_button("Update role", type="primary"):
                try:
                    user_admin_service.change_role(principal, target.id, Role(new_role))
                except (user_admin_service.AdminActionError, PermissionDenied) as exc:
                    st.error(str(exc))
                else:
                    st.toast(f"Role for {target.email} is now {new_role}.")
                    st.rerun()
    with right:
        with st.form("active_form", border=True):
            st.markdown(f"Status: **{'Active' if target.is_active else 'Inactive'}**")
            label = "Deactivate account" if target.is_active else "Reactivate account"
            confirm = st.checkbox(f"I understand this will {'block' if target.is_active else 'restore'} sign-in for this account")
            if st.form_submit_button(label):
                if not confirm:
                    st.warning("Tick the confirmation box first.")
                else:
                    try:
                        user_admin_service.set_active(principal, target.id, not target.is_active)
                    except (user_admin_service.AdminActionError, PermissionDenied) as exc:
                        st.error(str(exc))
                    else:
                        st.toast(f"{target.email} is now {'inactive' if target.is_active else 'active'}.")
                        st.rerun()

with audit_tab:
    f1, f2, f3 = st.columns([1, 2, 1])
    outcome = f1.selectbox("Outcome", ["all", "success", "failure", "denied"])
    action_prefix = f2.text_input("Action starts with", placeholder="e.g. auth. or admin.")
    limit = f3.number_input("Rows", min_value=10, max_value=1000, value=200, step=10)
    try:
        entries = user_admin_service.list_audit_log(
            principal, limit=int(limit), outcome=None if outcome == "all" else outcome, action_prefix=action_prefix
        )
    except (PermissionDenied, user_admin_service.AdminActionError) as exc:
        st.error(str(exc))
        st.stop()
    if not entries:
        st.info("No audit entries match these filters.")
    else:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Time": format_timestamp(e.created_at), "User": e.user_email or "—", "Action": e.action,
                        "Outcome": e.outcome, "Details": json.dumps(e.details, sort_keys=True) if e.details else "",
                    }
                    for e in entries
                ]
            ),
            hide_index=True,
        )
        st.caption(f"Showing the {len(entries)} most recent matching entries. Denied attempts are recorded too.")
