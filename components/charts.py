"""Shared Plotly charts. Every chart uses the shared theme and never bridges gaps."""
from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components.theme import COLORS, SERIES_COLORS, apply_chart_theme


def time_series(
    frame: pd.DataFrame,
    series: Sequence[Tuple[str, str]],
    *,
    title: str,
    y_title: str,
    split_by_interface: bool = False,
    y_format: Optional[str] = None,
    height: int = 340,
) -> None:
    """series: (column, legend label). Missing values are drawn as gaps."""
    fig = go.Figure()
    color_index = 0
    groups = frame.groupby(frame["interface_name"].fillna("(unnamed)")) if split_by_interface else [("", frame)]
    for interface, group in groups:
        for column, label in series:
            values = group[["timestamp", column]]
            if values[column].notna().sum() == 0:
                continue
            name = f"{label} · {interface}" if split_by_interface else label
            fig.add_trace(go.Scatter(
                x=values["timestamp"], y=values[column], name=name, mode="lines",
                line=dict(width=2, color=SERIES_COLORS[color_index % len(SERIES_COLORS)]), connectgaps=False,
            ))
            color_index += 1
    # Date ticks are two lines high, so the time zone goes in the title rather than an axis title that overlaps them.
    fig.update_layout(title=f"{title} · UTC", yaxis_title=y_title, hovermode="x unified")
    if y_format:
        fig.update_yaxes(tickformat=y_format)
    st.plotly_chart(apply_chart_theme(fig, height=height), theme=None)


def bar(labels: List[str], values: List[float], *, title: str, x_title: str = "", y_title: str = "",
        horizontal: bool = False, color: str = COLORS["accent"], height: int = 320, text_format: str = ",") -> None:
    if horizontal:
        trace = go.Bar(x=values, y=labels, orientation="h", marker_color=color,
                       texttemplate=f"%{{x:{text_format}}}", textposition="outside", cliponaxis=False)
    else:
        trace = go.Bar(x=labels, y=values, marker_color=color,
                       texttemplate=f"%{{y:{text_format}}}", textposition="outside", cliponaxis=False)
    fig = go.Figure(trace)
    fig.update_layout(title=title, xaxis_title=x_title, yaxis_title=y_title, showlegend=False,
                      bargap=0.55 if len(labels) < 4 else 0.25)
    if horizontal:
        fig.update_yaxes(autorange="reversed", type="category")
    else:
        fig.update_xaxes(type="category")
    st.plotly_chart(apply_chart_theme(fig, height=height), theme=None)


def coverage_bars(coverage: Dict[str, float], *, title: str) -> None:
    items = sorted(coverage.items(), key=lambda kv: -kv[1])
    colors = [COLORS["ok"] if v >= 0.95 else COLORS["warn"] if v > 0 else COLORS["border"] for _, v in items]
    fig = go.Figure(go.Bar(
        x=[v for _, v in items], y=[k for k, _ in items], orientation="h", marker_color=colors,
        texttemplate="%{x:.0%}", textposition="outside", cliponaxis=False,
    ))
    fig.update_layout(title=title, xaxis=dict(range=[0, 1.08], tickformat=".0%"), showlegend=False)
    fig.update_yaxes(autorange="reversed")
    st.plotly_chart(apply_chart_theme(fig, height=max(260, 34 * len(items) + 90)), theme=None)


def confusion_heatmap(matrix: List[List[int]], labels: List[str], *, title: str, height: int = 360) -> None:
    """Rows = actual, columns = predicted. Cell text shows counts; colour shows the row share."""
    import numpy as np

    values = np.asarray(matrix, dtype=float)
    row_totals = values.sum(axis=1, keepdims=True)
    shares = np.divide(values, row_totals, out=np.zeros_like(values), where=row_totals > 0)
    fig = go.Figure(go.Heatmap(
        z=shares, x=labels, y=labels, text=values.astype(int), texttemplate="%{text:,}",
        colorscale=[[0, COLORS["card"]], [1, COLORS["accent"]]], zmin=0, zmax=1, showscale=False,
        hovertemplate="Actual %{y}<br>Predicted %{x}<br>%{text:,} rows (%{z:.1%} of actual)<extra></extra>",
    ))
    fig.update_layout(title=title, xaxis_title="Predicted", yaxis_title="Actual")
    fig.update_yaxes(autorange="reversed", type="category")
    fig.update_xaxes(type="category")
    st.plotly_chart(apply_chart_theme(fig, height=height), theme=None)
