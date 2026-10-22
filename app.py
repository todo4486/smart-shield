"""Smart Shield entry point and router.

Pages live in views/ and are registered with st.navigation. When nobody is
signed in, ONLY the login page is registered, so no other page can be reached
by URL. Each view also calls require_principal() as a second gate.
"""
from __future__ import annotations

import logging

import streamlit as st

from components.sidebar import render_logo, render_sidebar
from components.theme import inject_css, register_plotly_template
from config import get_settings
from services import database_service, monitoring_service, session_service
from services.authorization import Permission

st.set_page_config(
    page_title="Smart Shield",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_resource(show_spinner=False)
def _prepare_database(db_path: str) -> str:
    """Run pending migrations once per process and database file."""
    database_service.run_migrations(db_path)
    # No capture worker survives a server restart, so close live sessions left open by a previous process.
    monitoring_service.recover_interrupted_sessions()
    return db_path


settings = get_settings()
logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
_prepare_database(str(settings.db_path))
register_plotly_template()
inject_css()

principal = session_service.resolve(st.session_state)

if principal is None:
    navigation = st.navigation(
        [st.Page("views/login.py", title="Sign in", icon=":material/lock:", default=True)],
        position="hidden",
    )
else:
    render_logo()
    sections = {
        "Monitor": [
            st.Page("views/overview.py", title="Overview", icon=":material/space_dashboard:", default=True),
            st.Page("views/live_monitoring.py", title="Live Monitoring", icon=":material/monitor_heart:"),
            st.Page("views/incident_center.py", title="Incident Center", icon=":material/crisis_alert:"),
        ],
        "Intelligence": [
            st.Page("views/security_center.py", title="Smart Shield Security", icon=":material/security:"),
            st.Page("views/predictnet.py", title="PredictNet Congestion", icon=":material/insights:"),
            st.Page("views/bandwidth.py", title="Bandwidth Management", icon=":material/tune:"),
            st.Page("views/ml_lab.py", title="ML Laboratory", icon=":material/science:"),
        ],
        "Workspace": [
            st.Page("views/reports.py", title="Reports", icon=":material/description:"),
            st.Page("views/settings.py", title="Settings", icon=":material/settings:"),
            st.Page("views/account.py", title="My account", icon=":material/person:"),
        ],
    }
    if principal.has(Permission.MANAGE_USERS):
        sections["Workspace"].append(
            st.Page("views/administration.py", title="Administration", icon=":material/admin_panel_settings:")
        )
    navigation = st.navigation(sections, position="sidebar", expanded=True)
    render_sidebar(principal)

navigation.run()
