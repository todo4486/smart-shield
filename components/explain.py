""""Why was this flagged?" panel for one alert (data from services/explainability_service.py)."""
from __future__ import annotations

from html import escape

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import mitre
from components.theme import COLORS, apply_chart_theme
from components.ui import kpi_tile, section_label
from services.explainability_service import Explanation, pretty


def _anomaly_line(anomaly: dict) -> str:
    pos = anomaly["position"]
    return (
        "<div class='ss-anom' role='img' aria-label='Anomaly score on a line from normal to anomalous'>"
        f"<div class='ss-anom-mark' style='left:{100 * pos['score']:.1f}%'><span>flagged flows "
        f"{anomaly['score']:.3f}</span></div>"
        f"<div class='ss-anom-mark ss-anom-threshold' style='left:{100 * pos['threshold']:.1f}%'><span>threshold "
        f"{anomaly['threshold']:.3f}</span></div></div>"
        "<div class='ss-anom-ends'><span>● normal</span><span>anomalous ✖</span></div>")


def render(explanation: Explanation) -> None:
    st.markdown(f"<div class='ss-explain-summary'>{escape(explanation.summary)}</div>", unsafe_allow_html=True)
    if explanation.alert_type == "security":
        st.markdown(mitre.badges(explanation.category, all_techniques=True), unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    with c1:
        kpi_tile("Model score", None if explanation.model_score is None else f"{explanation.model_score:.2f}",
                 "predicted" if explanation.model_score is not None else "unavailable",
                 "median of the flagged flows · uncalibrated"
                 + (f" · flags at ≥ {explanation.score_threshold:.2f}" if explanation.score_threshold is not None else ""))
    with c2:
        top = explanation.type_votes[0] if explanation.type_votes else None
        kpi_tile("Attack type", top["label"] if top else explanation.category, "predicted",
                 f"{top['share']:.0%} of attack-type trees" if top else "no attack-type model output")
    with c3:
        kpi_tile("Flows explained", f"{explanation.flows_used:,}", "measured",
                 f"vs {explanation.reference_rows:,} benign reference rows")
    for note in explanation.notes:
        st.caption(note)

    left, right = st.columns(2)
    with left:
        section_label("Biggest deviations from the benign median")
        if explanation.deviations:
            rows = [{"Feature": pretty(d.feature),
                     "Flagged median": d.flagged_median, "Benign median": d.benign_median,
                     "× benign": "—" if d.ratio is None else f"{d.ratio:,.2g}×",
                     "Robust z": round(d.robust_z, 1),
                     "Model importance": None if d.importance is None else round(d.importance, 3)}
                    for d in explanation.deviations]
            st.dataframe(pd.DataFrame(rows), hide_index=True)
            st.caption("Robust z = (flagged median − benign median) ÷ (1.4826 × benign median absolute deviation), "
                       f"capped at ±99. Flagged: {explanation.basis.get('flagged', '—')}. "
                       f"Reference: {explanation.basis.get('reference', '—')}.")
        else:
            st.caption("No per-flow deviations are available for this alert.")
    with right:
        section_label("What the model relies on overall")
        if explanation.importances:
            data = list(reversed(explanation.importances))
            fig = go.Figure(go.Bar(x=[d["importance"] for d in data], y=[pretty(d["feature"]) for d in data],
                                   orientation="h", marker_color=COLORS["accent"],
                                   hovertemplate="%{y}: %{x:.3f}<extra></extra>"))
            fig.update_layout(title="Random Forest feature importance (global, from training)",
                              xaxis_title="Mean decrease in impurity", yaxis=dict(automargin=True))
            st.plotly_chart(apply_chart_theme(fig, height=300), theme=None, key=f"importance_{explanation.alert_id}")
        else:
            st.caption("Feature importances are only available for Random Forest classifier alerts.")
        if len(explanation.type_votes) > 1:
            st.caption("Attack-type votes: " + " · ".join(f"{v['label']} {v['share']:.0%}" for v in explanation.type_votes)
                       + " (share of trees, not probabilities).")

    section_label("Anomaly score")
    if explanation.anomaly:
        st.markdown(_anomaly_line(explanation.anomaly), unsafe_allow_html=True)
        benign = explanation.anomaly.get("benign_median")
        st.caption("Isolation Forest score (higher = more normal). "
                   f"{explanation.anomaly['below_threshold_share']:.0%} of the flagged flows fall past the threshold"
                   + (f"; benign reference median {benign:.3f}." if benign is not None else "."))
    else:
        st.caption("No compatible anomaly detector is active, so no anomaly score is shown.")
