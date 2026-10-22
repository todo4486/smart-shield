"""Sign-in and registration page (the only page registered when signed out)."""
from __future__ import annotations

from html import escape

import streamlit as st

from components.theme import hide_sidebar
from config import ASSETS_DIR
from services import auth_service, session_service

hide_sidebar()

flash = session_service.pop_flash(st.session_state)
first_run = not auth_service.has_any_users()
registration_open = auth_service.registration_open()

FEATURES = [
    ("🛡️", "Smart Shield", "Machine-learning intrusion and anomaly detection on network flows."),
    ("📈", "PredictNet", "Congestion forecasting and capacity-aware bandwidth recommendations."),
    ("🔗", "Unified intelligence", "Security and performance evidence correlated without assuming congestion is an attack."),
]

st.write("")
brand_col, gap, form_col = st.columns([1.15, 0.12, 1])

with brand_col:
    logo_svg = (ASSETS_DIR / "shield_icon.svg").read_text(encoding="utf-8")
    features = "".join(
        f"<div class='ss-feature'><div class='ss-feature-icon'>{escape(icon)}</div>"
        f"<div><b>{escape(title)}</b><span>{escape(text)}</span></div></div>"
        for icon, title, text in FEATURES
    )
    st.markdown(
        f"<div class='ss-brand'>{logo_svg}<h1>Smart Shield</h1>"
        "<div class='ss-tagline'>An AI-powered network intelligence platform for intrusion detection, "
        "congestion prediction and intelligent bandwidth management.</div>"
        f"{features}</div>",
        unsafe_allow_html=True,
    )

with form_col:
    st.write("")
    if flash:
        st.info(flash)
    if first_run:
        st.info(
            "No accounts exist yet. The first account you create becomes the **administrator**; "
            "accounts created afterwards are analysts.",
            icon=":material/key:",
        )

    tab_names = ["Create account", "Sign in"] if first_run else ["Sign in", "Create account"]
    tabs = dict(zip(tab_names, st.tabs(tab_names)))

    with tabs["Sign in"]:
        with st.form("login_form", clear_on_submit=False, border=True):
            email = st.text_input("Email", key="login_email", autocomplete="email")
            password = st.text_input("Password", type="password", key="login_password", autocomplete="current-password")
            submitted = st.form_submit_button("Sign in", type="primary", width="stretch")
        if submitted:
            try:
                user = auth_service.login(email, password)
            except auth_service.LoginError as exc:
                st.error(str(exc))
            else:
                session_service.start(st.session_state, user)
                st.rerun()

    with tabs["Create account"]:
        if not registration_open:
            st.info("Self-registration is disabled. Ask an administrator to create an account for you.")
        else:
            with st.form("register_form", clear_on_submit=False, border=True):
                name = st.text_input("Full name", key="register_name", max_chars=100, autocomplete="name")
                reg_email = st.text_input("Email", key="register_email", max_chars=254, autocomplete="email")
                reg_password = st.text_input(
                    "Password", type="password", key="register_password", max_chars=128, autocomplete="new-password",
                    help="10–128 characters, including an uppercase letter, a lowercase letter and a digit.",
                )
                confirm = st.text_input(
                    "Confirm password", type="password", key="register_confirm", max_chars=128, autocomplete="new-password"
                )
                created = st.form_submit_button("Create account", type="primary", width="stretch")
            if created:
                if reg_password != confirm:
                    st.error("Passwords do not match.")
                else:
                    try:
                        user = auth_service.register(name, reg_email, reg_password)
                    except auth_service.RegistrationError as exc:
                        st.error(str(exc))
                    else:
                        session_service.start(st.session_state, user)
                        st.rerun()

    st.markdown(
        "<div class='ss-auth-note'>Passwords are hashed with Argon2. Repeated failed sign-ins lock the email "
        "temporarily. Sessions end after a period of inactivity, and refreshing the browser requires signing in again.</div>",
        unsafe_allow_html=True,
    )
