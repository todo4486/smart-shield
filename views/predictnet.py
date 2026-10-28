"""PredictNet Congestion Center: current rates, forecasts vs actuals, congestion risk and history."""
from __future__ import annotations

from html import escape

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import charts, severity
from components.guard import require_principal
from components.theme import COLORS, MONO_FONT, apply_chart_theme, palette
from components.ui import (
    empty_state, format_bits_rate, format_bytes_rate, format_ratio, format_timestamp, kpi_tile, page_header, recall,
    remember, section_label,
)
from services import (
    congestion_prediction_service, model_registry_service, monitoring_service, settings_service, telemetry_view_service,
)
from services.authorization import Permission, PermissionDenied
from services.congestion_prediction_service import PredictionError
from services.forecasting import TARGETS

principal = require_principal()
settings = settings_service.get_predictnet_settings()
RISK_COLORS = {"normal": COLORS["ok"], "elevated": COLORS["warn"], "high": "#F97316", "critical": COLORS["critical"],
               "unknown": COLORS["muted"]}

page_header(
    "PredictNet Congestion Center",
    "Forecast utilization from measured telemetry, see how forecasts compare with what actually happened, and "
    "assess congestion risk against configured thresholds.",
    eyebrow="Intelligence",
)

model = model_registry_service.active_model(principal, "congestion_forecaster")
sessions = [s for s in monitoring_service.list_sessions(principal) if s.metric_count]
if not sessions:
    empty_state("📈", "No telemetry to forecast yet",
                "Import historical network measurements under ML Laboratory → Data sources, then train a forecaster "
                "in ML Laboratory → PredictNet models.")
    st.page_link("views/ml_lab.py", label="Go to ML Laboratory", icon=":material/science:")
    st.stop()

by_id = {s.id: s for s in sessions}
default_session = model.training_metadata.get("session_id") if model else None
c1, c2 = st.columns(2)
session_id = c1.selectbox("Telemetry session", list(by_id),
                          index=list(by_id).index(default_session) if default_session in by_id else 0,
                          format_func=lambda i: f"#{i} · {by_id[i].configuration.get('filename', '')}")
interfaces = telemetry_view_service.session_interfaces(principal, session_id) or [""]
interface = c2.selectbox("Interface", interfaces, format_func=lambda i: i or "(unnamed)")
# "" selects rows without an interface name; it never means "all interfaces".
frame = telemetry_view_service.session_telemetry(principal, session_id, interface).metrics
latest = frame.iloc[-1]

# ------------------------------------------------------------------ current
section_label("Latest measurements in this session")
c1, c2, c3, c4 = st.columns(4)
with c1:
    kpi_tile("Incoming", format_bytes_rate(latest.get("incoming_bytes_per_second")),
             "measured" if pd.notna(latest.get("incoming_bytes_per_second")) else "unavailable",
             f"as of {format_timestamp(latest['timestamp'].isoformat())}")
with c2:
    kpi_tile("Outgoing", format_bytes_rate(latest.get("outgoing_bytes_per_second")),
             "measured" if pd.notna(latest.get("outgoing_bytes_per_second")) else "unavailable")
with c3:
    tp = latest.get("throughput_bps")
    kpi_tile("Throughput", format_bits_rate(tp if pd.notna(tp) else None),
             latest.get("throughput_provenance") or "unavailable")
with c4:
    util = latest.get("utilization_ratio")
    kpi_tile("Utilization", format_ratio(util if pd.notna(util) else None),
             latest.get("utilization_provenance") or "unavailable",
             "Capacity unknown, so no percentage" if pd.isna(util) else
             f"Capacity {format_bits_rate(latest.get('configured_capacity_bps'))} (configured)"
             if pd.notna(latest.get("configured_capacity_bps")) else "Measured utilization")

# Per-link risk gauges: the newest stored utilization of every link in this session.
gauges = []
for name in interfaces:
    link_frame = frame if name == interface else telemetry_view_service.session_telemetry(principal, session_id, name).metrics
    values = link_frame["utilization_ratio"].dropna() if "utilization_ratio" in link_frame else pd.Series(dtype=float)
    gauges.append((name, None if values.empty else float(values.iloc[-1])))
if any(v is not None for _, v in gauges):
    section_label("Link risk (latest measured utilization)")
    columns = st.columns(min(4, len(gauges)))
    for n, (name, value) in enumerate(gauges):
        with columns[n % len(columns)]:
            if value is None:
                kpi_tile(name or "(unnamed)", None, "unavailable", "No configured capacity, so no utilization")
                continue
            level = settings_service.risk_level(value, settings)
            gauge = go.Figure(go.Indicator(
                mode="gauge+number", value=value * 100, number=dict(suffix="%", valueformat=".1f",
                                                                    font=dict(family=MONO_FONT, size=26)),
                title=dict(text=f"{name or '(unnamed)'} · {severity.plain(level)}", font=dict(size=13)),
                gauge=dict(axis=dict(range=[0, 100], ticksuffix="%"), bar=dict(color=RISK_COLORS.get(level)),
                           steps=[dict(range=[settings.elevated_threshold * 100, settings.high_threshold * 100],
                                       color="rgba(245,158,11,0.15)"),
                                  dict(range=[settings.high_threshold * 100, settings.critical_threshold * 100],
                                       color="rgba(249,115,22,0.18)"),
                                  dict(range=[settings.critical_threshold * 100, 100], color="rgba(239,68,68,0.2)")])))
            gauge.update_layout(margin=dict(l=20, r=20, t=50, b=10))
            st.plotly_chart(apply_chart_theme(gauge, height=190), theme=None, key=f"gauge_{session_id}_{name}")

if model is None:
    st.info("No forecaster is active. Train one under **ML Laboratory → PredictNet models**, then an administrator "
            "activates it.")
    st.stop()

meta = model.training_metadata
target = meta["target"]
horizons = meta["horizons_seconds"]
st.caption(f"Active forecaster **{model.version}** · {TARGETS[target]} · {meta['interval_seconds']} s interval · "
           f"horizons {', '.join(f'{h // 60} min' for h in horizons)} · trained on session #{meta['session_id']}.")

# ----------------------------------------------------------------- forecast
def _forecast_figure(run, history: pd.DataFrame) -> go.Figure:
    """Measured past + forecast with its error band, threshold lines and a 'now' marker."""
    base = pd.to_datetime(run.base_time, utc=True)
    column = run.target
    past = history[["timestamp", column]].dropna() if column in history else pd.DataFrame(columns=["timestamp", column])
    past = past[past["timestamp"] <= base].tail(72)
    current = float(past[column].iloc[-1]) if not past.empty else None
    xs = [base] + [pd.to_datetime(f.target_time, utc=True) for f in run.forecasts]
    ys = [current] + [f.predicted_value for f in run.forecasts]
    lower = [current] + [f.lower for f in run.forecasts]
    upper = [current] + [f.upper for f in run.forecasts]
    if current is None:
        xs, ys, lower, upper = xs[1:], ys[1:], lower[1:], upper[1:]
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=past["timestamp"], y=past[column], mode="lines", name="Measured (past)",
                             line=dict(color=palette()["text"], width=1.6), connectgaps=False))
    fig.add_trace(go.Scatter(x=xs + xs[::-1], y=upper + lower[::-1], fill="toself", fillcolor="rgba(59,130,246,0.16)",
                             line=dict(width=0), hoverinfo="skip", name="Typical error band (residual-based)"))
    fig.add_trace(go.Scatter(x=xs, y=ys, mode="lines+markers", name="Forecast (predicted)",
                             line=dict(color=COLORS["accent"], width=2.4, dash="dot"), marker=dict(size=8)))
    scale = 1.0 if column == "utilization_ratio" else run.capacity_bps
    if scale:
        for name, value, color in (("elevated", settings.elevated_threshold, COLORS["warn"]),
                                   ("high", settings.high_threshold, COLORS["high"]),
                                   ("critical", settings.critical_threshold, COLORS["critical"])):
            fig.add_hline(y=value * scale, line=dict(color=color, width=1, dash="dash"),
                          annotation_text=f"{name} {value:.0%}", annotation_position="top left",
                          annotation_font=dict(size=10, color=color))
    fig.add_vline(x=base, line=dict(color=COLORS["cyan"], width=1.5))
    fig.add_annotation(x=base, y=1.04, yref="paper", text="Now (latest data)", showarrow=False,
                       font=dict(size=10, color=COLORS["cyan"]))
    fig.update_layout(title=f"{TARGETS[column]}: measured past and forecast · UTC", hovermode="x unified",
                      legend=dict(orientation="h", x=0, xanchor="left", y=-0.15, yanchor="top"), margin=dict(b=80))
    if column == "utilization_ratio":
        fig.update_yaxes(tickformat=".0%")
    return fig


forecast_tab, backtest_tab, history_tab, metrics_tab = st.tabs(
    ["Forecast & risk", "Forecast vs actual", "Congestion history", "Model evaluation"]
)
with forecast_tab:
    if principal.has(Permission.RUN_DETECTION):
        if st.button("Generate forecast from the latest data", type="primary", icon=":material/insights:"):
            try:
                with st.spinner("Forecasting…"):
                    run = congestion_prediction_service.generate_forecast(principal, session_id, interface)
            except (PredictionError, PermissionDenied) as exc:
                st.error(str(exc))
            else:
                remember(st.session_state, "last_forecast_run", (session_id, interface), run)
    # Only show a run for the session and interface it was generated for.
    run = recall(st.session_state, "last_forecast_run", (session_id, interface))
    if run is None:
        st.caption("Forecasts are generated on request and stored with the model version. "
                   "The most recent stored forecasts appear under Congestion history.")
    else:
        for warning in run.warnings:
            st.warning(warning)
        st.caption(f"Forecast from data up to {format_timestamp(run.base_time)} with model {run.model_version}. "
                   "Predicted values are model outputs, not measurements.")
        cols = st.columns(len(run.forecasts))
        for col, f in zip(cols, run.forecasts):
            with col:
                value = format_ratio(f.predicted_utilization) if f.predicted_utilization is not None else \
                    format_bits_rate(f.predicted_throughput_bps)
                kpi_tile(f"In {f.horizon_seconds // 60} min", value, "predicted",
                         f"Risk: {f.risk.level.upper()} · typical error ±"
                         + (f"{(f.upper - f.predicted_value):.1%}" if target == "utilization_ratio"
                            else format_bits_rate(f.upper - f.predicted_value)))
        outlook = congestion_prediction_service.congestion_outlook(
            run.forecasts, settings.high_threshold, capacity_bps=run.capacity_bps, target=run.target)
        outlook_level = {"likely": "high", "possible": "medium", "clear": "low", "unavailable": "info"}[outlook["status"]]
        st.markdown(f"<div class='ss-card' style='border-left:4px solid {severity.COLORS[outlook_level]};margin:.6rem 0'>"
                    f"<h4>{severity.badge(outlook_level, outlook['status'].upper())} &nbsp;{escape(outlook['text'])}</h4>"
                    f"<p>Judged against the configured high threshold ({settings.high_threshold:.0%}). Predicted, not "
                    "measured.</p></div>", unsafe_allow_html=True)
        st.plotly_chart(apply_chart_theme(_forecast_figure(run, frame), height=380), theme=None)
        st.caption("Shaded band: the model's 90th-percentile absolute error on held-out validation data (residual-based, "
                   "not a calibrated probability interval).")
        worst = max(run.forecasts, key=lambda f: ["unknown", "normal", "elevated", "high", "critical"].index(f.risk.level))
        color = RISK_COLORS.get(worst.risk.level, COLORS["muted"])
        reasons = "".join(f"<li>{escape(r)}</li>" for r in worst.risk.reasons)
        st.markdown(f"<div class='ss-card' style='border-left:4px solid {color}'><h4>Congestion risk: "
                    f"{escape(worst.risk.level.upper())}</h4><ul style='color:#8B97AD;margin:0'>{reasons}</ul></div>",
                    unsafe_allow_html=True)
        if run.alerts_created:
            st.warning(f"{len(run.alerts_created)} congestion alert(s) raised. They are performance alerts; congestion "
                       "alone is never treated as an attack.")
        elif run.alerts_suppressed:
            st.caption(f"{run.alerts_suppressed} alert(s) suppressed by the {settings.alert_cooldown_minutes}-minute "
                       "cooldown or because an earlier alert is still open.")
    with st.expander("How risk is assessed"):
        st.markdown(f"""
- **Thresholds (configured):** elevated ≥ {settings.elevated_threshold:.0%}, high ≥ {settings.high_threshold:.0%},
  critical ≥ {settings.critical_threshold:.0%}. These are starting values, not universal standards. Administrators change them in Settings.
- **Base risk:** the higher of the current and the predicted utilization level.
- **Uncertainty:** if the prediction plus its typical (90th percentile) validation error reaches the next level while traffic is rising,
  the risk goes up one level.
- **Degradation:** packet loss ≥ 2% or latency ≥ 2× the session median raises *normal* to *elevated*.
- **Unknown capacity:** without utilization data or a configured capacity, the risk is *unknown* and only absolute rates are shown.
- **Alerts:** predicted high/critical risk, a rapid rise (≥ {settings.rapid_rise_per_hour:.0%}/hour while above elevated), sustained
  high utilization (last {settings.sustained_high_samples} samples), or measured degradation. Identical alerts are suppressed for
  {settings.alert_cooldown_minutes} minutes and while unresolved.
""")

with backtest_tab:
    horizon = st.radio("Horizon", horizons, horizontal=True, format_func=lambda h: f"{h // 60} min")
    try:
        bt = congestion_prediction_service.backtest(principal, model, session_id, interface, horizon)
    except (PredictionError, model_registry_service.ModelRegistryError) as exc:
        st.error(str(exc))
        bt = pd.DataFrame()
    except Exception as exc:  # e.g. the session lacks the model's target metric
        st.error(f"This session cannot be used with the active model: {exc}")
        bt = pd.DataFrame()
    if not bt.empty:
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=bt["target_time"], y=bt["actual"], name="Actual (measured)", mode="lines",
                                 line=dict(color=palette()["text"], width=1.5), connectgaps=False))
        period_colors = {"train": COLORS["muted"], "validation": COLORS["warn"], "test": COLORS["accent"],
                   "not used in training": COLORS["accent"], "beyond available data": COLORS["ok"]}
        for period, part in bt.groupby("period", sort=False):
            fig.add_trace(go.Scatter(x=part["target_time"], y=part["predicted"], mode="lines",
                                     name=f"Predicted ({period})", line=dict(color=period_colors[period], width=2, dash="dot")))
        fig.update_layout(title=f"{TARGETS[target]}: forecast {horizon // 60} min ahead vs actual · UTC",
                          hovermode="x unified",
                          legend=dict(orientation="h", x=0, xanchor="left", y=-0.12, yanchor="top"),
                          margin=dict(b=90))
        if target == "utilization_ratio":
            fig.update_yaxes(tickformat=".0%")
        st.plotly_chart(apply_chart_theme(fig, height=420), theme=None)
        scored = bt.dropna(subset=["actual"])
        if not scored.empty:
            test_part = scored[scored["period"].isin(["test", "not used in training"])]
            if not test_part.empty:
                mae = (test_part["actual"] - test_part["predicted"]).abs().mean()
                st.caption(f"Mean absolute error on data not used for fitting: "
                           + (f"{mae:.2%}" if target == "utilization_ratio" else format_bits_rate(mae))
                           + ". Training-period predictions are shown in grey; they are in-sample and look better "
                           "than real performance.")

with history_tab:
    history = congestion_prediction_service.recent_predictions(principal)
    if not history:
        st.info("No forecasts have been stored yet.")
    else:
        table = pd.DataFrame([{
            "Generated for data up to": format_timestamp(h["timestamp"]),
            "Horizon": f"{h['forecast_horizon_seconds'] // 60} min",
            "Predicted utilization": format_ratio(h["predicted_utilization_ratio"]) or "unavailable",
            "Predicted throughput": format_bits_rate(h["predicted_throughput_bps"]) or "—",
            "Risk": h["congestion_risk"], "Interface": h["interface_name"] or "—", "Model": h["model_version"],
        } for h in history])
        st.dataframe(table, hide_index=True)
        counts = pd.Series([h["congestion_risk"] for h in history]).value_counts()
        charts.bar(list(counts.index), list(counts.values), title="Stored forecasts by risk level", height=260)

with metrics_tab:
    rows = []
    for label, h in model.metrics.get("per_horizon", {}).items():
        chosen = h["candidates"][h["chosen"]]
        baseline = min((h["candidates"][n] for n in ("last_value", "moving_average")), key=lambda c: c["test"]["mae"])
        fmt = (lambda v: f"{v:.2%}") if target == "utilization_ratio" else (lambda v: format_bits_rate(v))
        rows.append({"Horizon": label, "Chosen model": h["chosen"].replace("_", " "),
                     "Test MAE": fmt(chosen["test"]["mae"]), "Test RMSE": fmt(chosen["test"]["rmse"]),
                     "Test R²": "—" if chosen["test"]["r2"] is None else f"{chosen['test']['r2']:.3f}",
                     "Best baseline MAE": fmt(baseline["test"]["mae"]), "Test samples": chosen["test"]["n"]})
    st.dataframe(pd.DataFrame(rows), hide_index=True)
    comparison = go.Figure()
    per_horizon = model.metrics.get("per_horizon", {})
    for name, color in (("last_value", COLORS["muted"]), ("moving_average", "#A78BFA"),
                        ("random_forest", COLORS["ok"]), ("hist_gradient_boosting", COLORS["accent"])):
        values = [(label, h["candidates"][name]["test"]["mae"]) for label, h in per_horizon.items()
                  if name in h["candidates"]]
        if values:
            comparison.add_trace(go.Bar(x=[v[0] for v in values], y=[v[1] for v in values],
                                        name=name.replace("_", " ") + (" (baseline)" if name in ("last_value",
                                                                                                  "moving_average") else ""),
                                        marker_color=color))
    if comparison.data:
        comparison.update_layout(barmode="group", title="Test MAE by horizon: model vs baselines (lower is better)",
                                 legend=dict(orientation="h", x=0, xanchor="left", y=-0.15, yanchor="top"))
        if target == "utilization_ratio":
            comparison.update_yaxes(tickformat=".1%")
        st.plotly_chart(apply_chart_theme(comparison, height=320), theme=None)
    st.caption(f"Trained on {format_timestamp(meta['training_period'][0])} → {format_timestamp(meta['training_period'][1])} "
               f"with a chronological 70/15/15 split. Minimum history: {meta['minimum_history_samples']} samples.")
