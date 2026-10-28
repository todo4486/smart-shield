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
    "cyan": "#22D3EE",
    "ok": "#22C55E",
    "warn": "#F59E0B",
    "high": "#F97316",
    "critical": "#EF4444",
}

# Light theme surfaces; accent and status colours stay the same so meaning never changes between themes.
LIGHT_COLORS = {**COLORS, "background": "#F5F7FB", "card": "#FFFFFF", "border": "#D6DEEB", "text": "#0F172A",
                "muted": "#5B6B84"}

SERIES_COLORS = [COLORS["accent"], COLORS["cyan"], COLORS["ok"], COLORS["warn"], "#A78BFA", COLORS["critical"]]

PLOTLY_TEMPLATE_NAME = "smart_shield"
PLOTLY_LIGHT_TEMPLATE_NAME = "smart_shield_light"
UI_FONT = "Space Grotesk, system-ui, sans-serif"
MONO_FONT = "JetBrains Mono, ui-monospace, monospace"


def _layout(colors: dict) -> dict:
    return dict(
        paper_bgcolor=colors["card"],
        plot_bgcolor=colors["card"],
        font=dict(family=UI_FONT, color=colors["text"], size=13),
        colorway=SERIES_COLORS,
        margin=dict(l=48, r=20, t=48, b=40),
        hoverlabel=dict(bgcolor=colors["background"], bordercolor=colors["border"],
                        font=dict(color=colors["text"], family=MONO_FONT)),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, bgcolor="rgba(0,0,0,0)"),
        xaxis=dict(gridcolor=colors["border"], linecolor=colors["border"], zeroline=False,
                   tickfont=dict(color=colors["muted"], family=MONO_FONT)),
        yaxis=dict(gridcolor=colors["border"], linecolor=colors["border"], zeroline=False,
                   tickfont=dict(color=colors["muted"], family=MONO_FONT)),
        title=dict(font=dict(size=15, color=colors["text"]), x=0, xanchor="left"),
    )


PLOTLY_LAYOUT = _layout(COLORS)


def theme_type() -> str:
    """"light" or "dark" as chosen in the app menu (⋮ → Settings). Dark outside a running app."""
    try:
        return "light" if getattr(st.context.theme, "type", None) == "light" else "dark"
    except Exception:  # no script run context (tests, CLI)
        return "dark"


def palette() -> dict:
    return LIGHT_COLORS if theme_type() == "light" else COLORS


def register_plotly_template() -> None:
    if PLOTLY_TEMPLATE_NAME not in pio.templates:
        pio.templates[PLOTLY_TEMPLATE_NAME] = go.layout.Template(layout=PLOTLY_LAYOUT)
    if PLOTLY_LIGHT_TEMPLATE_NAME not in pio.templates:
        pio.templates[PLOTLY_LIGHT_TEMPLATE_NAME] = go.layout.Template(layout=_layout(LIGHT_COLORS))


def apply_chart_theme(fig: go.Figure, *, height: int = 340) -> go.Figure:
    register_plotly_template()
    name = PLOTLY_LIGHT_TEMPLATE_NAME if theme_type() == "light" else PLOTLY_TEMPLATE_NAME
    fig.update_layout(template=name, height=height)
    return fig


_LIGHT_CSS = """:root { --ss-bg: #F5F7FB; --ss-card: #FFFFFF; --ss-sidebar: #EEF2F8; --ss-border: #D6DEEB;
--ss-text: #0F172A; --ss-muted: #5B6B84; }
.ss-sev-info { color: #0E7490; } .ss-sev-low { color: #1D4ED8; } .ss-sev-medium { color: #92400E; }
.ss-sev-high { color: #9A3412; } .ss-sev-critical { color: #B91C1C; }
.ss-src-live, .ss-chip-measured { color: #15803D; } .ss-src-counters { color: #0E7490; }
.ss-src-dataset, .ss-chip-derived { color: #1D4ED8; } .ss-src-replay, .ss-chip-configured { color: #92400E; }
.ss-chip-predicted { color: #6D28D9; } .ss-banner-replay { color: #92400E; }
.ss-role-admin { color: #B91C1C; } .ss-role-analyst { color: #1D4ED8; } .ss-step-num { color: #1D4ED8; }
.ss-planned .ss-phase { color: #92400E; } .ss-mitre { color: #6D28D9; }"""

_REDUCED_MOTION_CSS = "*, *::before, *::after { animation: none !important; transition: none !important; }"


@st.cache_data(show_spinner=False)
def _load_css() -> str:
    return (ASSETS_DIR / "styles.css").read_text(encoding="utf-8")


def inject_css(*, reduce_motion: bool = False) -> None:
    extra = (_LIGHT_CSS if theme_type() == "light" else "") + (_REDUCED_MOTION_CSS if reduce_motion else "")
    st.markdown(f"<style>{_load_css()}{extra}</style>", unsafe_allow_html=True)


def hide_sidebar() -> None:
    st.markdown(
        "<style>[data-testid='stSidebar'],[data-testid='stSidebarCollapsedControl'],"
        "[data-testid='stExpandSidebarButton']{display:none !important;}</style>",
        unsafe_allow_html=True,
    )
