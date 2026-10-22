"""Administration (admin-only): users, roles, activation and the audit log."""
from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from components.guard import require_page_permission, require_principal
from components.ui import format_timestamp, page_header
from services import retention_service, settings_service, user_admin_service
from services.authorization import Permission, PermissionDenied, Role

principal = require_principal()
require_page_permission(principal, Permission.MANAGE_USERS)

page_header("Administration", "Manage accounts and roles, and review the audit trail. "
            "The last active administrator can never be demoted or deactivated.", eyebrow="Workspace")

users_tab, audit_tab, retention_tab = st.tabs(["Users", "Audit log", "Data retention"])

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

with retention_tab:
    st.markdown("Delete data older than the ages below. Retention is **off by default**: nothing is deleted until you "
                "enable it here and apply it. Open alerts, alerts linked to open incidents, open incidents, models, "
                "users, settings and policies are never deleted. Audit logs are kept for at least one year.")
    retention = settings_service.get_retention_settings()
    with st.form("retention_form", border=True):
        enabled = st.checkbox("Enable data retention", value=retention.enabled)
        c1, c2, c3, c4 = st.columns(4)
        metrics_days = c1.number_input("Traffic measurements (days)", 1, 3650, retention.metrics_days)
        flows_days = c2.number_input("Flows (days)", 1, 3650, retention.flows_days)
        predictions_days = c3.number_input("Forecasts (days)", 1, 3650, retention.predictions_days)
        login_days = c4.number_input("Sign-in attempts (days)", 1, 3650, retention.login_attempts_days)
        c5, c6, c7 = st.columns(3)
        alerts_days = c5.number_input("Resolved alerts (days)", 1, 3650, retention.closed_alerts_days)
        incidents_days = c6.number_input("Closed incidents (days)", 1, 3650, retention.closed_incidents_days)
        audit_days = c7.number_input("Audit log (days, minimum 365)", 365, 3650, retention.audit_days)
        if st.form_submit_button("Save retention settings", type="primary"):
            try:
                settings_service.update_retention_settings(principal, settings_service.RetentionSettings(
                    enabled, int(metrics_days), int(flows_days), int(predictions_days), int(alerts_days),
                    int(incidents_days), int(login_days), int(audit_days)))
            except (settings_service.SettingsError, PermissionDenied) as exc:
                st.error(str(exc))
            else:
                st.toast("Retention settings saved.")
                st.rerun()
    st.caption("Ages use each record's own timestamp. Imported historical data counts as old as the period it "
               "describes, so preview before applying.")
    c1, c2 = st.columns(2)
    if c1.button("Preview what would be deleted", icon=":material/preview:"):
        try:
            st.session_state["retention_preview"] = retention_service.preview(principal)
        except (retention_service.RetentionError, PermissionDenied) as exc:
            st.error(str(exc))
    result = st.session_state.get("retention_preview")
    if result is not None:
        st.dataframe(pd.DataFrame([{"Data": name.replace("_", " "), "Rows to delete": count,
                                    "Older than": format_timestamp(result.cutoffs[name])}
                                   for name, count in result.counts.items()]), hide_index=True)
    with c2.form("retention_apply", border=False):
        confirm = st.checkbox("I understand deleted data cannot be recovered")
        if st.form_submit_button("Apply retention now", disabled=not retention.enabled):
            if not confirm:
                st.warning("Tick the confirmation box first.")
            else:
                try:
                    applied = retention_service.apply(principal)
                except (retention_service.RetentionError, PermissionDenied) as exc:
                    st.error(str(exc))
                else:
                    st.session_state.pop("retention_preview", None)
                    st.success("Deleted: " + ", ".join(f"{v:,} {k.replace('_', ' ')}" for k, v in applied.counts.items()))
    if not retention.enabled:
        st.caption("Enable retention and save before applying. Preview works either way.")
