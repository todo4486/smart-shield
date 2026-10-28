"""Animated pipeline strip for the "How it works" page: the active stage lights up and a packet moves along.

Pure HTML + CSS: the fill bar eases to the active stage (350 ms) and a dot slides in. Reduce motion and
prefers-reduced-motion switch both off (assets/styles.css, components/theme.py).
"""
from __future__ import annotations

from html import escape
from typing import List

import streamlit as st

from services.how_it_works_service import Stage


def strip_html(stages: List[Stage], active: int) -> str:
    cells = []
    for i, stage in enumerate(stages):
        state = "ss-active" if i == active else "ss-done" if i < active else ""
        reached = "" if stage.reached else " title='Not reached by this flow'"
        cells.append(f"<div class='ss-pipe-stage {state}'{reached}><div class='ss-pipe-num'>STEP {i + 1}</div>"
                     f"<div class='ss-pipe-icon'>{escape(stage.icon)}</div>"
                     f"<div class='ss-pipe-name'>{escape(stage.title)}</div></div>")
    share = 100 * (active + 0.5) / len(stages)
    track = (f"<div class='ss-pipe-track'><div class='ss-pipe-fill' style='width:{share:.1f}%'></div>"
             f"<div class='ss-pipe-packet' style='left:calc({share:.1f}% - 5px)'></div></div>")
    return f"<div class='ss-pipe' role='list' aria-label='Pipeline stages'>{''.join(cells)}{track}</div>"


def detail_html(stage: Stage, index: int, total: int) -> str:
    facts = "".join(f"<dt>{escape(k)}</dt><dd>{escape(v)}</dd>" for k, v in stage.facts)
    note = f"<p><i>{escape(stage.note)}</i></p>" if stage.note else ""
    body = f"<dl class='ss-pipe-kv'>{facts}</dl>" if facts else ""
    return (f"<div class='ss-pipe-detail'><h4>{escape(stage.icon)} Step {index + 1} of {total} · {escape(stage.title)}"
            f"</h4><p>{escape(stage.explanation)}</p>{note}{body}</div>")


def render(stages: List[Stage], active: int) -> None:
    st.markdown(strip_html(stages, active), unsafe_allow_html=True)
    st.markdown(detail_html(stages[active], active, len(stages)), unsafe_allow_html=True)
