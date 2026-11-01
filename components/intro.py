"""The animated intro on the sign-in page, and a short welcome straight after signing in. CSS only.

The overlay must never get in the way: it ignores the pointer from start to finish, the form works underneath it, and it is
hidden unless its animation is running. So with Reduce motion on (animations are removed entirely) it simply never appears.

Streamlit keeps an element whose HTML has not changed, so a failed sign-in does not replay the intro.
"""
from __future__ import annotations

from html import escape

import streamlit as st

WELCOME_KEY = "intro_welcome_pending"
_SHIELD = "M22 4 L38 10 V22 C38 32.5 31.2 40.6 22 44 C12.8 40.6 6 32.5 6 22 V10 Z"
_CHECK = "M15.5 23.5 L20.2 28.2 L29 18.6"
_WORD_START, _LETTER_STEP = 0.95, 0.045

# Only on the sign-in page, so these never play on the dashboard. The brand panel and form arrive as the intro clears.
LOGIN_CSS = """<style>
.ss-brand > svg, .ss-brand h1, .ss-brand .ss-tagline, .ss-brand .ss-feature { animation: ss-intro-rise .6s cubic-bezier(.2,.7,.2,1) both; }
.ss-brand > svg { animation-delay: 2.3s; filter: drop-shadow(0 0 12px rgba(59,130,246,.45)); }
.ss-brand h1 { animation-delay: 2.4s; }
.ss-brand .ss-tagline { animation-delay: 2.5s; }
.ss-brand .ss-feature:nth-of-type(1) { animation-delay: 2.6s; }
.ss-brand .ss-feature:nth-of-type(2) { animation-delay: 2.7s; }
.ss-brand .ss-feature:nth-of-type(3) { animation-delay: 2.8s; }
[data-testid="stTabs"] { animation: ss-intro-rise .6s cubic-bezier(.2,.7,.2,1) 2.5s both; }
.ss-auth-note { animation: ss-intro-rise .6s ease-out 2.9s both; }
</style>"""


def _logo() -> str:
    return (
        "<svg class='ss-intro-logo' viewBox='0 0 44 48' aria-hidden='true'>"
        "<defs><linearGradient id='ss-intro-fill' x1='0' y1='0' x2='1' y2='1'><stop offset='0' stop-color='#60A5FA'/>"
        "<stop offset='1' stop-color='#2563EB'/></linearGradient></defs>"
        f"<path class='ss-intro-fill' d='{_SHIELD}' fill='url(#ss-intro-fill)'/>"
        f"<path class='ss-intro-outline' d='{_SHIELD}' pathLength='1' fill='none' stroke='#60A5FA' stroke-width='1.4' stroke-linejoin='round'/>"
        f"<path class='ss-intro-check' d='{_CHECK}' pathLength='1' fill='none' stroke='#E6EBF5' stroke-width='3.2' "
        "stroke-linecap='round' stroke-linejoin='round'/></svg>")


def _letters(text: str, start: float) -> str:
    return "".join(f"<span style='animation-delay:{start + i * _LETTER_STEP:.3f}s'>{'&nbsp;' if c == ' ' else escape(c)}</span>"
                   for i, c in enumerate(text))


def intro_html() -> str:
    return ("<div class='ss-intro' aria-hidden='true'><div class='ss-intro-stage'><div class='ss-intro-mark'>"
            "<i class='ss-intro-ring'></i><i class='ss-intro-ring ss-intro-ring-2'></i>" + _logo() + "</div>"
            f"<div class='ss-intro-word'>{_letters('Smart Shield', _WORD_START)}</div>"
            "<div class='ss-intro-sub'>POWERED BY PREDICTNET</div><div class='ss-intro-bar'><b></b></div></div></div>")


def welcome_html(name: str) -> str:
    first = (name or "").strip().split(" ")[0] or "back"
    return ("<div class='ss-intro ss-intro-quick' aria-hidden='true'><div class='ss-intro-stage'><div class='ss-intro-mark'>"
            "<i class='ss-intro-ring'></i>" + _logo() + "</div>"
            f"<div class='ss-intro-word ss-intro-welcome'>Welcome, {escape(first)}</div></div></div>")


def render_login() -> None:
    st.markdown(LOGIN_CSS + intro_html(), unsafe_allow_html=True)


def request_welcome() -> None:
    st.session_state[WELCOME_KEY] = True


def render_welcome(name: str) -> None:
    """Once, on the first page after signing in."""
    if st.session_state.pop(WELCOME_KEY, False) and not st.session_state.get("reduce_motion"):
        st.markdown(welcome_html(name), unsafe_allow_html=True)
