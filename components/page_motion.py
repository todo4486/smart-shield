"""A small animation when moving between pages. CSS only.

The page's content rises in, one block just after another, and a thin line crosses the top of the window. The header strip
stays still: only what comes after the marker moves.

Streamlit reuses elements between pages, so nothing would restart by itself. Changing an animation's name does restart it, so
each page change swaps between two identical animations. A rerun on the same page keeps the same name, and live panels
refreshing themselves are inside one block that is not touched, so neither replays anything.
"""
from __future__ import annotations

from typing import MutableMapping, Optional

import streamlit as st

PAGE_KEY = "page_motion_page"
VARIANT_KEY = "page_motion_variant"


def next_variant(state: MutableMapping, page: str) -> Optional[str]:
    """'a' or 'b', changing only when the page does. None on the first page, where there was no move to show."""
    previous = state.get(PAGE_KEY)
    state[PAGE_KEY] = page
    if previous is None:
        return None
    if previous != page:
        state[VARIANT_KEY] = "b" if state.get(VARIANT_KEY) == "a" else "a"
    return state.get(VARIANT_KEY)


def page_css(variant: Optional[str]) -> str:
    if variant is None:
        return "<span class='ss-page-motion'></span>"
    after = "[data-testid='stElementContainer']:has(.ss-page-motion)"
    rules = [f"{after} ~ * {{ animation: ss-page-in-{variant} .32s cubic-bezier(.2,.7,.2,1) both; }}"]
    for step in range(1, 4):  # the first few blocks arrive one after another; the rest with the last of them
        rules.append(f"{after}{' ~ *' * (step + 1)} {{ animation-delay: {step * 0.05:.2f}s; }}")
    rules.append(f".stApp::before {{ animation: ss-page-bar-{variant} .55s ease-out both; }}")
    return f"<style>{''.join(rules)}</style><span class='ss-page-motion'></span>"


def render(page: str) -> None:
    st.markdown(page_css(next_variant(st.session_state, page)), unsafe_allow_html=True)
