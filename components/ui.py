"""Reusable UI building blocks. Every dynamic value is passed through
html.escape() before being placed in markdown HTML."""
from __future__ import annotations

from html import escape
from typing import Iterable, Optional, Sequence, Tuple

import streamlit as st

PROVENANCE_LABELS = {
    "measured": "Measured",
    "derived": "Derived",
    "predicted": "Predicted",
    "configured": "Configured",
    "unavailable": "Unavailable",
}


def page_header(title: str, subtitle: str, eyebrow: str = "Smart Shield") -> None:
    st.markdown(
        f"<div class='ss-page-header'><div class='ss-eyebrow'>{escape(eyebrow)}</div>"
        f"<h1>{escape(title)}</h1><p>{escape(subtitle)}</p></div>",
        unsafe_allow_html=True,
    )


def provenance_chip(provenance: str) -> str:
    key = provenance if provenance in PROVENANCE_LABELS else "unavailable"
    return f"<span class='ss-chip ss-chip-{key}'>{escape(PROVENANCE_LABELS[key])}</span>"


def kpi_tile(label: str, value: Optional[str], provenance: str, foot: Optional[str] = None) -> None:
    if value is None:
        value_html = "<div class='ss-kpi-value ss-unavailable'>Unavailable</div>"
    else:
        value_html = f"<div class='ss-kpi-value'>{escape(value)}</div>"
    foot_html = f"<div class='ss-kpi-foot'>{escape(foot)}</div>" if foot else ""
    st.markdown(
        f"<div class='ss-kpi'><div class='ss-kpi-label'>{escape(label)}</div>{value_html}"
        f"{provenance_chip(provenance)}{foot_html}</div>",
        unsafe_allow_html=True,
    )


def card(title: str, body: str) -> None:
    st.markdown(
        f"<div class='ss-card'><h4>{escape(title)}</h4><p>{escape(body)}</p></div>",
        unsafe_allow_html=True,
    )


def empty_state(icon: str, title: str, body: str) -> None:
    st.markdown(
        f"<div class='ss-empty'><div class='ss-empty-icon'>{escape(icon)}</div>"
        f"<h2>{escape(title)}</h2><p>{escape(body)}</p></div>",
        unsafe_allow_html=True,
    )


def step_cards(steps: Sequence[Tuple[str, str, str, bool]]) -> None:
    """Render numbered next-step cards: (title, body, tag, ready)."""
    columns = st.columns(len(steps))
    for index, (column, (title, body, tag, ready)) in enumerate(zip(columns, steps), start=1):
        tag_class = "ss-tag ss-tag-ready" if ready else "ss-tag"
        with column:
            st.markdown(
                f"<div class='ss-step'><div class='ss-step-num'>{index}</div><h4>{escape(title)}</h4>"
                f"<p>{escape(body)}</p><span class='{tag_class}'>{escape(tag)}</span></div>",
                unsafe_allow_html=True,
            )


def planned_notice(phase: str, title: str, summary: str, items: Iterable[str]) -> None:
    bullets = "".join(f"<li>{escape(item)}</li>" for item in items)
    st.markdown(
        f"<div class='ss-planned'><span class='ss-phase'>Planned for {escape(phase)}</span>"
        f"<h2>{escape(title)}</h2><p>{escape(summary)}</p><ul>{bullets}</ul></div>",
        unsafe_allow_html=True,
    )


def section_label(text: str) -> None:
    st.markdown(f"<div class='ss-section-label'>{escape(text)}</div>", unsafe_allow_html=True)


# ------------------------------------------------------------- formatting

def format_bytes_rate(value: Optional[float]) -> Optional[str]:
    if value is None:
        return None
    units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]
    size = float(value)
    for unit in units:
        if size < 1000 or unit == units[-1]:
            return f"{size:,.1f} {unit}"
        size /= 1000
    return None


def format_bits_rate(value: Optional[float]) -> Optional[str]:
    if value is None:
        return None
    units = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"]
    size = float(value)
    for unit in units:
        if size < 1000 or unit == units[-1]:
            return f"{size:,.1f} {unit}"
        size /= 1000
    return None


def format_ratio(value: Optional[float]) -> Optional[str]:
    return None if value is None else f"{value * 100:.1f}%"


def format_timestamp(value: Optional[str]) -> str:
    if not value:
        return "—"
    return value.replace("T", " ")[:19] + " UTC"
