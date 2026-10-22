"""Shared sidebar: logo, (navigation is placed by st.navigation), user, status, logout."""
from __future__ import annotations

from html import escape

import streamlit as st

from config import ASSETS_DIR
from components.ui import format_timestamp, section_label
from services import dashboard_service, database_service, session_service
from services.authorization import Principal

_STATUS_STYLE = {
    "RUNNING": ("ss-dot-ok", "Running"),
    "STARTING": ("ss-dot-warn", "Starting"),
    "STOPPING": ("ss-dot-warn", "Stopping"),
    "STOPPED": ("ss-dot-idle", "Stopped"),
    "ERROR": ("ss-dot-critical", "Error"),
    "NONE": ("ss-dot-idle", "Not started"),
}


def render_logo() -> None:
    st.logo(str(ASSETS_DIR / "shield.svg"), icon_image=str(ASSETS_DIR / "shield_icon.svg"), size="large")


def _logout() -> None:
    session_service.logout(st.session_state)


def render_sidebar(principal: Principal) -> None:
    status = dashboard_service.get_monitoring_status(principal)
    schema_version = database_service.current_schema_version()
    dot, label = _STATUS_STYLE.get(status.status, ("ss-dot-idle", status.status.title()))
    if status.status == "NONE":
        detail = "No monitoring sessions recorded yet"
    else:
        source = status.interface_name or status.source_type or "unknown source"
        detail = f"{source} · since {format_timestamp(status.started_at)}"

    with st.sidebar:
        st.divider()
        section_label("Signed in")
        st.markdown(
            f"<div class='ss-user'><div class='ss-user-name'>{escape(principal.name)}</div>"
            f"<div class='ss-user-email'>{escape(principal.email)}</div>"
            f"<span class='ss-role ss-role-{escape(principal.role.value)}'>{escape(principal.role.value)}</span></div>",
            unsafe_allow_html=True,
        )
        st.write("")
        section_label("System")
        st.markdown(
            f"<div class='ss-status'><span class='ss-dot {dot}'></span><div>Monitoring: {escape(label)}"
            f"<small>{escape(detail)}</small></div></div>"
            f"<div class='ss-status'><span class='ss-dot ss-dot-ok'></span><div>Database online"
            f"<small>Schema version {escape(schema_version or 'none')}</small></div></div>",
            unsafe_allow_html=True,
        )
        st.write("")
        st.button("Sign out", icon=":material/logout:", on_click=_logout, width="stretch")
