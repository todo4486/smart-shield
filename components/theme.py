"""Shared look and feel: CSS injection and the Plotly chart theme."""
from __future__ import annotations

import plotly.graph_objects as go
import plotly.io as pio
import streamlit as st

from config import ASSETS_DIR

COLORS = {
    "background": "#0B1220",
    "card": "#111A2E",
    "border": "#1E2A44",
    "text": "#E6EBF5",
    "muted": "#8B97AD",
    "accent": "#3B82F6",
    "ok": "#22C55E",
    "warn": "#F59E0B",
    "critical": "#EF4444",
}

SERIES_COLORS = [COLORS["accent"], "#22D3EE", COLORS["ok"], COLORS["warn"], "#A78BFA", COLORS["critical"]]

PLOTLY_TEMPLATE_NAME = "smart_shield"

PLOTLY_LAYOUT = dict(
    paper_bgcolor=COLORS["card"],
    plot_bgcolor=COLORS["card"],
    font=dict(family="Inter, Segoe UI, system-ui, sans-serif", color=COLORS["text"], size=13),
    colorway=SERIES_COLORS,
    margin=dict(l=48, r=20, t=48, b=40),
    hoverlabel=dict(bgcolor=COLORS["background"], bordercolor=COLORS["border"], font=dict(color=COLORS["text"])),
    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, bgcolor="rgba(0,0,0,0)"),
    xaxis=dict(gridcolor=COLORS["border"], linecolor=COLORS["border"], zeroline=False, tickfont=dict(color=COLORS["muted"])),
    yaxis=dict(gridcolor=COLORS["border"], linecolor=COLORS["border"], zeroline=False, tickfont=dict(color=COLORS["muted"])),
    title=dict(font=dict(size=15, color=COLORS["text"]), x=0, xanchor="left"),
)


def register_plotly_template() -> None:
    if PLOTLY_TEMPLATE_NAME not in pio.templates:
        pio.templates[PLOTLY_TEMPLATE_NAME] = go.layout.Template(layout=PLOTLY_LAYOUT)


def apply_chart_theme(fig: go.Figure, *, height: int = 340) -> go.Figure:
    register_plotly_template()
    fig.update_layout(template=PLOTLY_TEMPLATE_NAME, height=height)
    return fig


@st.cache_data(show_spinner=False)
def _load_css() -> str:
    return (ASSETS_DIR / "styles.css").read_text(encoding="utf-8")


def inject_css() -> None:
    st.markdown(f"<style>{_load_css()}</style>", unsafe_allow_html=True)


def hide_sidebar() -> None:
    st.markdown(
        "<style>[data-testid='stSidebar'],[data-testid='stSidebarCollapsedControl'],"
        "[data-testid='stExpandSidebarButton']{display:none !important;}</style>",
        unsafe_allow_html=True,
    )
