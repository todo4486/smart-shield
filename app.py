"""Smart Shield entry point and router.

Pages live in views/ and are registered with st.navigation. When nobody is
signed in, ONLY the login page is registered, so no other page can be reached
by URL. Each view also calls require_principal() as a second gate.
"""
from __future__ import annotations

import logging

import streamlit as st

from components.sidebar import render_logo, render_sidebar
from components.header import render_header
from components.theme import inject_css, register_plotly_template
from config import get_settings
from services import database_service, monitoring_service, preferences_service, session_service
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
    # No capture worker or replay survives a server restart, so close sessions left open by a previous process.
    monitoring_service.recover_interrupted_sessions("live_capture")
    monitoring_service.recover_interrupted_sessions("replay")
    return db_path


settings = get_settings()
logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
_prepare_database(str(settings.db_path))
register_plotly_template()

principal = session_service.resolve(st.session_state)
preferences = preferences_service.get_preferences(principal) if principal else None
# Pages and animated components read this flag; it mirrors the signed-in user's saved preference.
st.session_state["reduce_motion"] = bool(preferences and preferences.reduce_motion)
inject_css(reduce_motion=st.session_state["reduce_motion"])

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
            st.Page("views/network_map.py", title="Network Map", icon=":material/hub:"),
            st.Page("views/incident_center.py", title="Incident Center", icon=":material/crisis_alert:"),
            st.Page("views/replay.py", title="Replay / demo", icon=":material/play_circle:"),
        ],
        "Intelligence": [
            st.Page("views/security_center.py", title="Smart Shield Security", icon=":material/security:"),
            st.Page("views/predictnet.py", title="PredictNet Congestion", icon=":material/insights:"),
            st.Page("views/bandwidth.py", title="Bandwidth Management", icon=":material/tune:"),
            st.Page("views/ml_lab.py", title="ML Laboratory", icon=":material/science:"),
        ],
        "Workspace": [
            st.Page("views/reports.py", title="Reports", icon=":material/description:"),
            st.Page("views/how_it_works.py", title="How it works", icon=":material/school:"),
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
    render_header(principal)
    # Incident permalinks (?incident=42): the page path is lost while signing in (only the login page exists
    # then), so a signed-in visit carrying the parameter is taken to the Incident Center once.
    incident_link = st.query_params.get("incident")
    if incident_link and st.session_state.get("followed_incident_link") != incident_link:
        st.session_state["followed_incident_link"] = incident_link
        if navigation.url_path != "incident_center":
            st.switch_page("views/incident_center.py", query_params={"incident": incident_link})

navigation.run()
