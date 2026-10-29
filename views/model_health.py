"""Model health: model cards from the registry and a read-only PSI drift check."""
from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components.guard import require_principal
from components.theme import COLORS, apply_chart_theme
from components.ui import empty_state, format_timestamp, kpi_tile, page_header, section_label
from services import model_health_service as health, settings_service
from services.authorization import PermissionDenied
from services.explainability_service import pretty
from services.model_health_service import HealthError

principal = require_principal()
FAMILY_NAMES = {"intrusion_classifier": "Intrusion classifier (Random Forest)",
                "anomaly_detector": "Anomaly detector (Isolation Forest)",
                "congestion_forecaster": "Congestion forecaster", "congestion_classifier": "Congestion classifier"}
LEVEL_STYLE = {"stable": ("ss-sev-low", "● Stable"), "moderate": ("ss-sev-medium", "▲ Moderate shift"),
               "drift": ("ss-sev-critical", "✖ Drift"), "unavailable": ("ss-sev-info", "ⓘ Unavailable")}

page_header("Model health", "What each registered model was trained on, how it scored on held-out data, whether its "
            "file is still the one that was registered, and whether recent data has drifted from its training data. "
            "Read-only: nothing here retrains or changes a model.", eyebrow="Intelligence")

cards = health.model_cards(principal)
if not cards:
    empty_state("🧪", "No models registered yet", "Train models in the ML Laboratory; their cards appear here.")
    st.stop()

show_all = st.toggle("Show inactive models too", value=False)
for card in [c for c in cards if c.active or show_all]:
    with st.container(border=True):
        state = ("<span class='ss-src ss-src-live'>ACTIVE</span>" if card.active else
                 "<span class='ss-src ss-src-none'>INACTIVE</span>")
        check = ("<span class='ss-sev ss-sev-low'>✓ SHA-256 verified</span>" if card.verified else
                 "<span class='ss-sev ss-sev-critical'>✖ File does not match its registered SHA-256</span>")
        st.markdown(f"#### {FAMILY_NAMES.get(card.family, card.family)} · `{card.version}`  \n{state} {check}",
                    unsafe_allow_html=True)
        c1, c2, c3 = st.columns(3)
        c1.markdown(f"**Trained** {format_timestamp(card.trained_at)}  \n**Model** `{card.name}`")
        c2.markdown("**Data** " + (", ".join(card.trained_on) or "unknown"))
        sizes = " · ".join(f"{k} {v:,}" for k, v in card.split_sizes.items())
        c3.markdown(f"**Split** {card.split or 'unknown'}" + (f"  \n{sizes}" if sizes else ""))
        metrics = {k: v for k, v in card.metrics.items() if v is not None}
        items = list(metrics.items())[:10]
        for row in range(0, len(items), 5):  # fill row by row, so tiles read left to right
            for column, (name, value) in zip(st.columns(5), items[row:row + 5]):
                with column:
                    shown = f"{value:.1%}" if name in ("precision", "recall", "f1", "false_positive_rate") else \
                        f"{value:,.4g}" if isinstance(value, float) else str(value)
                    kpi_tile(name.replace("_", " "), shown, "derived", "held-out test set")
        if card.confusion_matrix:
            m = card.confusion_matrix
            st.dataframe(pd.DataFrame({"Predicted benign": [m.get("tn"), m.get("fn")],
                                       "Predicted attack": [m.get("fp"), m.get("tp")]},
                                      index=["Actually benign", "Actually attack"]))
        for note in card.notes:
            st.caption(note)

section_label("Drift check (Population Stability Index)")
settings = settings_service.get_drift_settings()
ready = [c for c in cards if c.drift_ready]
sources = health.drift_sources(principal)
st.caption(f"PSI compares recent feature values with the training split, bin by bin. Under 0.10 is usually read as "
           f"stable and 0.10–0.25 as a moderate shift; this workspace warns at **{settings.psi_threshold:g}** "
           f"(Settings). The {settings.top_features} most important features are checked.")
if not ready:
    st.info("No model has stored training distributions yet. Models trained from now on store them; retrain the "
            "intrusion models in the ML Laboratory to enable this check. Nothing is retrained automatically.")
    st.stop()
if not sources:
    st.info("No recent data to compare: start a replay or live capture, or register a dataset.")
    st.stop()
c1, c2 = st.columns(2)
model_id = c1.selectbox("Model", [c.id for c in ready], format_func=lambda i: next(
    f"{FAMILY_NAMES.get(c.family, c.family)} · {c.version}" + (" · active" if c.active else "")
    for c in ready if c.id == i))
source = c2.selectbox("Recent data", range(len(sources)), format_func=lambda i: sources[i]["label"])
if st.button("Check drift", type="primary", icon=":material/monitoring:"):
    try:
        st.session_state["drift_report"] = health.check_drift(principal, model_id, sources[source]["kind"],
                                                             sources[source]["id"])
    except (HealthError, PermissionDenied) as exc:
        st.session_state.pop("drift_report", None)
        st.error(str(exc))
report = st.session_state.get("drift_report")
if report is not None and report.model_id == model_id:
    css, label = LEVEL_STYLE[report.overall]
    st.markdown(f"Overall: <span class='ss-sev {css}'>{label}</span> · {report.rows:,} recent rows from "
                f"{report.source}", unsafe_allow_html=True)
    if report.overall == "drift":
        st.warning(f"At least one important feature has PSI ≥ {report.threshold:g}. The model may be less reliable on "
                   "this data. Consider retraining on more recent data; nothing is changed automatically.")
    for note in report.notes:
        st.caption(note)
    st.dataframe(pd.DataFrame([{
        "Feature": pretty(f.feature), "PSI": None if f.psi is None else round(f.psi, 3),
        "Reading": LEVEL_STYLE[f.level][1], "Importance": None if f.importance is None else round(f.importance, 3)}
        for f in report.features]), hide_index=True)
    checked = [f for f in report.features if f.psi is not None]
    if checked:
        pick = st.selectbox("Compare distributions for", [f.feature for f in checked], format_func=pretty)
        f = next(x for x in checked if x.feature == pick)
        labels = ([f"≤ {f.edges[0]:,.3g}"] + [f"{a:,.3g}–{b:,.3g}" for a, b in zip(f.edges, f.edges[1:])]
                  + [f"> {f.edges[-1]:,.3g}"] if f.edges else ["all"]) + ["missing"]
        fig = go.Figure([go.Bar(name="Training", x=labels, y=f.expected, marker_color=COLORS["muted"]),
                         go.Bar(name="Recent", x=labels, y=f.actual, marker_color=COLORS["accent"])])
        fig.update_layout(title=f"{pretty(pick)}: share of rows per training decile bin (PSI {f.psi:.3f})",
                          barmode="group", yaxis=dict(tickformat=".0%"), xaxis_title="Bin (training deciles)")
        st.plotly_chart(apply_chart_theme(fig, height=320), theme=None)
