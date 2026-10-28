"""Animated water-filling bars for a bandwidth allocation.

Each class is a tank as tall as the largest of its maximum or demand. Its "water" rises through the
allocator's own recorded steps (minimums reserved → each sharing round → final), so classes that are
capped by their small demand fill completely first and the leftover visibly flows into the others by
weight. Pure HTML + CSS keyframes: it plays on load, works offline, and with Reduce motion the bars
simply show the final allocation.
"""
from __future__ import annotations

import hashlib
from html import escape
from typing import Dict, List

import streamlit as st

from services.bandwidth_allocation import AllocationResult

STEP_MS = 350  # each step eases out over 350 ms (motion rule: 200–400 ms)


def _bits(value: float) -> str:
    for unit in ("bit/s", "kbit/s", "Mbit/s", "Gbit/s"):
        if value < 1000 or unit == "Gbit/s":
            return f"{value:,.1f} {unit}"
        value /= 1000
    return f"{value:,.1f} Gbit/s"


def frames(result: AllocationResult) -> Dict[str, List[float]]:
    """Fill level (0–1 of the tank) per class at every recorded step (pure; used by the tests too)."""
    out: Dict[str, List[float]] = {}
    for a in result.allocations:
        tank = max(a.maximum_bps, a.demand_bps, 1.0)
        out[a.name] = [min(1.0, step["allocations"].get(a.name, 0.0) / tank) for step in result.steps]
    return out


def render(result: AllocationResult, *, replay: int = 0) -> None:
    levels = frames(result)
    steps = len(result.steps)
    seed = hashlib.sha1(repr((sorted(levels.items()), replay)).encode()).hexdigest()[:10]
    duration = STEP_MS * max(1, steps - 1)
    css, bars = [], []
    for index, a in enumerate(result.allocations):
        name = f"ssfill-{seed}-{index}"
        stops = " ".join(f"{100 * i / max(1, steps - 1):.1f}% {{ height: {100 * v:.2f}%; }}"
                         for i, v in enumerate(levels[a.name]))
        css.append(f"@keyframes {name} {{ {stops} }}")
        tank = max(a.maximum_bps, a.demand_bps, 1.0)
        demand_mark = f"{100 * min(1.0, a.demand_bps / tank):.2f}%"
        min_mark = f"{100 * min(1.0, a.minimum_bps / tank):.2f}%"
        unmet = f"<div class='ss-wf-unmet'>unmet {_bits(a.unmet_demand_bps)}</div>" if a.unmet_demand_bps else ""
        bars.append(
            f"<div class='ss-wf-col'><div class='ss-wf-tank' title='{escape(a.name)}: {_bits(a.allocated_bps)} of "
            f"{_bits(a.demand_bps)} demanded · weight {a.priority_weight:g} · limited by {escape(a.limited_by)}'>"
            f"<div class='ss-wf-water' style='height:{100 * levels[a.name][-1]:.2f}%;"
            f"animation:{name} {duration}ms ease-out both'></div>"
            f"<div class='ss-wf-mark ss-wf-demand' style='bottom:{demand_mark}'><span>demand</span></div>"
            f"<div class='ss-wf-mark ss-wf-min' style='bottom:{min_mark}'><span>min</span></div></div>"
            f"<div class='ss-wf-name'>{escape(a.name)}</div>"
            f"<div class='ss-wf-value'>{_bits(a.allocated_bps)}</div>{unmet}</div>")
    st.markdown(
        f"<style>{' '.join(css)}</style><div class='ss-wf'>{''.join(bars)}</div>"
        f"<div class='ss-wf-steps'>{' → '.join(escape(s['label']) for s in result.steps)}</div>",
        unsafe_allow_html=True)
