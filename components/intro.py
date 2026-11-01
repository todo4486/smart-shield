"""The animated intro on the sign-in page, and a short welcome straight after signing in. CSS only.

A radar lock-on: the scope powers up and sweeps, signals converge on the centre, the two halves of the shield slam together, the
name decodes, and the screen splits open. It is decoration and carries no figures: no invented hosts, counts or statuses.

The overlay must never get in the way: it ignores the pointer from start to finish, the form works underneath it, and it is
hidden unless its animation is running. So with Reduce motion on (animations are removed entirely) it simply never appears.

Streamlit keeps an element whose HTML has not changed, so a failed sign-in does not replay the intro.
"""
from __future__ import annotations

import math
from html import escape

import streamlit as st

WELCOME_KEY = "intro_welcome_pending"
_SHIELD = "M22 4 L38 10 V22 C38 32.5 31.2 40.6 22 44 C12.8 40.6 6 32.5 6 22 V10 Z"
_CHECK = "M15.5 23.5 L20.2 28.2 L29 18.6"
_WORD_START, _LETTER_STEP = 1.55, 0.05
_SIGNALS = 10

# Only on the sign-in page, so these never play on the dashboard. The brand panel and form arrive as the screen splits open.
LOGIN_CSS = """<style>
.ss-brand-word, .ss-brand .ss-tagline, .ss-brand .ss-feature { animation: ss-intro-rise .55s cubic-bezier(.2,.7,.2,1) both; }
.ss-brand-word { animation-delay: 2.95s; }
.ss-brand .ss-tagline { animation-delay: 3.05s; }
.ss-brand .ss-feature { animation-delay: 3.1s; }
.ss-brand .ss-feature + .ss-feature { animation-delay: 3.18s; }
.ss-brand .ss-feature + .ss-feature + .ss-feature { animation-delay: 3.26s; }
[data-testid="stTabs"] { animation: ss-intro-rise .55s cubic-bezier(.2,.7,.2,1) 3s both; }
.ss-auth-note { animation: ss-intro-rise .55s ease-out 3.3s both; }
</style>"""


def _signals() -> str:
    """Lines racing in from the edge of the scope. Evenly spaced on purpose: this is a pattern, not a picture of any network."""
    parts = []
    for i in range(_SIGNALS):
        angle = 2 * math.pi * i / _SIGNALS + 0.3
        x, y = 200 + 186 * math.cos(angle), 200 + 186 * math.sin(angle)
        delay = 0.35 + 0.055 * ((i * 3) % _SIGNALS)
        parts.append(f"<rect class='ss-intro-node' x='{x - 3:.1f}' y='{y - 3:.1f}' width='6' height='6' style='animation-delay:{delay:.3f}s'/>"
                     f"<line class='ss-intro-signal' x1='{x:.1f}' y1='{y:.1f}' x2='200' y2='200' pathLength='1' "
                     f"style='animation-delay:{delay + 0.1:.3f}s'/>")
    return "".join(parts)


def _scope() -> str:
    rings = "".join(f"<circle class='ss-intro-scope-ring' cx='200' cy='200' r='{r}' style='animation-delay:{0.05 + i * 0.07:.2f}s'/>"
                    for i, r in enumerate((60, 110, 150, 186)))
    ticks = "".join(f"<line class='ss-intro-tick' x1='200' y1='6' x2='200' y2='{16 if i % 6 == 0 else 11}' transform='rotate({i * 15} 200 200)'/>"
                    for i in range(24))
    return (
        "<svg class='ss-intro-scope' viewBox='0 0 400 400' aria-hidden='true'>"
        "<defs><linearGradient id='ss-intro-fill' x1='0' y1='0' x2='1' y2='1'><stop offset='0' stop-color='#60A5FA'/>"
        "<stop offset='1' stop-color='#2563EB'/></linearGradient>"
        "<clipPath id='ss-intro-left'><rect x='0' y='0' width='22' height='48'/></clipPath>"
        "<clipPath id='ss-intro-right'><rect x='22' y='0' width='22' height='48'/></clipPath></defs>"
        f"<g class='ss-intro-grid'>{rings}{ticks}<line class='ss-intro-cross' x1='14' y1='200' x2='386' y2='200' pathLength='1'/>"
        "<line class='ss-intro-cross' x1='200' y1='14' x2='200' y2='386' pathLength='1'/></g>"
        f"{_signals()}<circle class='ss-intro-shock' cx='200' cy='200' r='60'/>"
        "<g transform='translate(134 128) scale(3)'>"
        f"<g clip-path='url(#ss-intro-left)'><path class='ss-intro-half ss-intro-half-left' d='{_SHIELD}' fill='url(#ss-intro-fill)'/></g>"
        f"<g clip-path='url(#ss-intro-right)'><path class='ss-intro-half ss-intro-half-right' d='{_SHIELD}' fill='url(#ss-intro-fill)'/></g>"
        f"<path class='ss-intro-outline' d='{_SHIELD}' pathLength='1' fill='none' stroke='#BFDBFE' stroke-width='.7' stroke-linejoin='round'/>"
        f"<path class='ss-intro-check' d='{_CHECK}' pathLength='1' fill='none' stroke='#FFFFFF' stroke-width='3.2' "
        "stroke-linecap='round' stroke-linejoin='round'/></g></svg>")


def _letters(text: str, start: float) -> str:
    return "".join(f"<span style='animation-delay:{start + i * _LETTER_STEP:.3f}s'>{'&nbsp;' if c == ' ' else escape(c)}</span>"
                   for i, c in enumerate(text))


def intro_html() -> str:
    return ("<div class='ss-intro' aria-hidden='true'><div class='ss-intro-scanline'></div><div class='ss-intro-stage'>"
            "<div class='ss-intro-mark'><i class='ss-intro-sweep'></i>" + _scope() + "</div>"
            f"<div class='ss-intro-word'>{_letters('Smart Shield', _WORD_START)}</div>"
            "<div class='ss-intro-sub'>POWERED BY PREDICTNET</div></div><i class='ss-intro-flash'></i></div>")


def welcome_html(name: str) -> str:
    first = (name or "").strip().split(" ")[0] or "back"
    return ("<div class='ss-intro ss-intro-quick' aria-hidden='true'><div class='ss-intro-stage'><div class='ss-intro-mark'>"
            "<i class='ss-intro-sweep'></i>" + _scope() + "</div>"
            f"<div class='ss-intro-word ss-intro-welcome'>Welcome, {escape(first)}</div></div></div>")


def render_login() -> None:
    st.markdown(LOGIN_CSS + intro_html(), unsafe_allow_html=True)


def request_welcome() -> None:
    st.session_state[WELCOME_KEY] = True


def render_welcome(name: str) -> None:
    """Once, on the first page after signing in."""
    if st.session_state.pop(WELCOME_KEY, False) and not st.session_state.get("reduce_motion"):
        st.markdown(welcome_html(name), unsafe_allow_html=True)
