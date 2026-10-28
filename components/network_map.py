"""Plotly rendering of the network map (encoding is documented in services/network_map_service.py).

Motion without JavaScript: busy links get an extra dotted "particle" line whose dashes are animated with
CSS (stroke-dashoffset), and hosts in an open incident get a halo whose opacity pulses. Both are selected
in assets/styles.css by their unique dash pattern / colour, so the chart stays a normal Plotly chart with
click-to-select. With Reduce motion on, the particle and halo traces are not drawn at all.
"""
from __future__ import annotations

import math
from typing import List

import plotly.graph_objects as go

from components import severity
from components.theme import COLORS, MONO_FONT, palette
from services.network_map_service import OTHERS, NetworkMap

RISK_COLORS = {"normal": COLORS["accent"], "elevated": COLORS["warn"], "high": COLORS["high"],
               "critical": COLORS["critical"], "unknown": "#64748B"}
RISK_LABELS = {"normal": "Link risk: normal", "elevated": "Link risk: elevated", "high": "Link risk: high",
               "critical": "Link risk: critical", "unknown": "Link risk: unknown (no capacity)"}
# Unique dash patterns; assets/styles.css animates each at a different speed (slow → fast).
PARTICLE_DASHES = ("2px,10px", "2px,11px", "2px,12px")
HALO_COLOR = "rgba(239,68,68,0.31)"
MAX_EDGES_DRAWN = 300
MAX_PARTICLE_EDGES = 40


def _width(throughput: float, top: float) -> float:
    return 1.0 + 9.0 * math.sqrt(throughput / top) if top > 0 else 1.0


def _human_bits(value: float) -> str:
    for unit in ("bit/s", "kbit/s", "Mbit/s", "Gbit/s"):
        if value < 1000 or unit == "Gbit/s":
            return f"{value:,.1f} {unit}"
        value /= 1000
    return f"{value:,.1f} Gbit/s"


def figure(network: NetworkMap, *, reduce_motion: bool, selected: str = None) -> go.Figure:
    fig = go.Figure()
    pos = {n.id: (n.x, n.y) for n in network.nodes}
    edges = network.edges[:MAX_EDGES_DRAWN]
    top = max((e.throughput_bps for e in edges), default=0.0)
    shown_risks = set()
    for e in edges:
        (x0, y0), (x1, y1) = pos[e.source], pos[e.target]
        # Lines are not interactive (hoverinfo skip), so a click near a host always reaches the host marker.
        # Link figures are in the host panel instead of a tooltip.
        fig.add_trace(go.Scatter(
            x=[x0, x1], y=[y0, y1], mode="lines", line=dict(width=_width(e.throughput_bps, top),
                                                            color=RISK_COLORS[e.risk]),
            opacity=0.75, name=RISK_LABELS[e.risk], legendgroup=e.risk, showlegend=e.risk not in shown_risks,
            hoverinfo="skip"))
        shown_risks.add(e.risk)
    if not reduce_motion and top > 0:
        busy = [e for e in edges if e.throughput_bps >= 0.01 * top][:MAX_PARTICLE_EDGES]
        for e in busy:
            tier = 2 if e.throughput_bps >= 0.5 * top else 1 if e.throughput_bps >= 0.2 * top else 0
            (x0, y0), (x1, y1) = pos[e.source], pos[e.target]
            fig.add_trace(go.Scatter(x=[x0, x1], y=[y0, y1], mode="lines", hoverinfo="skip", showlegend=False,
                                     line=dict(width=3, color=COLORS["cyan"], dash=PARTICLE_DASHES[tier])))
    incident_nodes = [n for n in network.nodes if n.in_incident]
    if incident_nodes and not reduce_motion:
        fig.add_trace(go.Scatter(
            x=[n.x for n in incident_nodes], y=[n.y for n in incident_nodes], mode="markers", hoverinfo="skip",
            showlegend=False, marker=dict(size=[_node_size(n.bytes, network) + 22 for n in incident_nodes],
                                          color=HALO_COLOR, line=dict(width=0))))
    biggest = max((n.bytes for n in network.nodes), default=1)
    labels = {n.id for n in sorted(network.nodes, key=lambda n: -n.bytes)[:12]} | ({selected} if selected else set())
    fig.add_trace(go.Scatter(
        x=[n.x for n in network.nodes], y=[n.y for n in network.nodes], mode="markers+text",
        customdata=[n.id for n in network.nodes], name="Host (size = traffic)",
        text=[(f"{n.id} ({n.members})" if n.id == OTHERS else n.id) if n.id in labels else "" for n in network.nodes],
        textposition="top center", textfont=dict(family=MONO_FONT, size=10, color=palette()["muted"]),
        hovertext=[_node_hover(n) for n in network.nodes], hoverinfo="text",
        marker=dict(
            size=[_node_size(n.bytes, network) for n in network.nodes],
            color=["#475569" if n.id == OTHERS else (COLORS["cyan"] if n.id == selected else palette()["card"])
                   for n in network.nodes],
            symbol=[_symbol(n.severity) for n in network.nodes],
            line=dict(width=[4 if n.severity else 1.5 for n in network.nodes],
                      color=[severity.COLORS[severity.normalize(n.severity)] if n.severity else palette()["muted"]
                             for n in network.nodes]),
        ),
    ))
    fig.update_layout(
        xaxis=dict(visible=False, range=[-0.04, 1.04]), yaxis=dict(visible=False, range=[-0.06, 1.08]),
        # "select" drag mode is what makes a click emit a selection (Streamlit listens for selections, not clicks).
        hovermode="closest", dragmode="select", clickmode="event+select",
        legend=dict(orientation="h", x=0, xanchor="left", y=-0.02, yanchor="top"), margin=dict(l=10, r=10, t=40, b=40),
        title=f"{len(network.nodes)} host node(s) · {len(edges)} link(s) · biggest host "
              f"{_human_bytes(biggest)} in the window")
    return fig


def _symbol(level) -> str:
    # Shape follows severity too, so the ring colour is never the only signal.
    return {"critical": "x", "high": "diamond", "medium": "triangle-up"}.get(severity.normalize(level), "circle") \
        if level else "circle"


def _node_size(size: int, network: NetworkMap) -> float:
    biggest = max((n.bytes for n in network.nodes), default=1) or 1
    return 12 + 34 * math.sqrt(size / biggest)


def _human_bytes(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1000 or unit == "TB":
            return f"{value:,.1f} {unit}"
        value /= 1000
    return f"{value:,.1f} TB"


def _node_hover(n) -> str:
    lines = [f"<b>{n.id}</b>" + (f" · {n.members} hosts merged" if n.id == OTHERS else ""),
             f"{_human_bytes(n.bytes)} · {n.flows:,} flows · {n.flagged_flows:,} flagged",
             f"Highest open alert: {severity.plain(n.severity) if n.severity else 'none'}"]
    if n.in_incident:
        lines.append("Part of an open incident")
    if n.id != OTHERS:
        lines.append("Click to open the host panel")
    return "<br>".join(lines)


def legend_rows() -> List[str]:
    return ["Edge thickness = average throughput in the window (derived from stored flows).",
            "Edge colour = link utilization risk against the configured capacity; grey = capacity unknown.",
            "Node size = bytes sent and received. Node ring colour and shape = most severe open alert naming the host.",
            "Moving dots = busy links (faster = busier). A pulsing halo = host in an open incident. "
            "Both are off with Reduce motion."]
