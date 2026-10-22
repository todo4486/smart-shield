"""ML Laboratory → PredictNet workspace: inspect telemetry, train and compare forecasters."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from components import charts
from components.models import registry_section
from components.ui import format_timestamp, section_label
from services import congestion_training_service, monitoring_service, settings_service, telemetry_view_service
from services.authorization import Permission, PermissionDenied, Principal
from services.congestion_training_service import ForecastTrainingError, ForecastTrainingOptions
from services.forecasting import TARGETS, summarize, valid_horizons_minutes

KIND_LABELS = {"last_value": "Last value (baseline)", "moving_average": "Moving average (baseline)",
               "hist_gradient_boosting": "HistGradientBoosting", "random_forest": "Random Forest"}


def _fmt(value, target: str) -> str:
    if value is None:
        return "—"
    return f"{value:.2%}" if target == "utilization_ratio" else f"{value / 1e6:,.2f} Mbit/s"


def show_report(report: congestion_training_service.ForecastTrainingReport) -> None:
    meta = report.metadata
    target = meta["target"]
    st.success(f"Trained forecaster **{report.version}** in {meta['training_seconds']:,.0f} s for "
               f"{TARGETS[target].lower()} at a {meta['interval_seconds']} s interval."
               + (" It is now active." if report.activated else ""))
    for warning in report.warnings:
        st.warning(warning)
    rows = []
    for label, horizon in report.per_horizon.items():
        for name, result in horizon["candidates"].items():
            rows.append({"Horizon": label, "Model": KIND_LABELS[name] + (" ✓ chosen" if name == horizon["chosen"] else ""),
                         "Test MAE": _fmt(result["test"]["mae"], target), "Test RMSE": _fmt(result["test"]["rmse"], target),
                         "Test R²": "—" if result["test"]["r2"] is None else f"{result['test']['r2']:.3f}",
                         "Validation MAE": _fmt(result["validation"]["mae"], target)})
    section_label("Baselines vs machine learning (chronological test period)")
    st.dataframe(pd.DataFrame(rows), hide_index=True)
    for label, horizon in report.per_horizon.items():
        st.caption(f"**{label}:** {horizon['reason']} Split: {horizon['split_sizes']}.")
    errors = {label: h["candidates"][h["chosen"]]["test"]["mae"] for label, h in report.per_horizon.items()}
    charts.bar(list(errors), list(errors.values()), title="Test error by forecast horizon (MAE of chosen model)",
               text_format=".2%" if target == "utilization_ratio" else ",.0f", height=280)


def render(principal: Principal) -> None:
    st.markdown(
        "Forecast **utilization** or **throughput** from imported telemetry. Data is split chronologically "
        "(never shuffled), features use only past values, and every model is compared with last-value and "
        "moving-average baselines."
    )
    settings = settings_service.get_predictnet_settings()
    sessions = [s for s in monitoring_service.list_sessions(principal) if s.metric_count]
    train_tab, registry_tab = st.tabs(["Train", "Model registry"])
    with train_tab:
        if not sessions:
            st.info("Import historical telemetry under **Data sources** first.")
        else:
            by_id = {s.id: s for s in sessions}
            session_id = st.selectbox("Telemetry session", list(by_id),
                                      format_func=lambda i: f"#{i} · {by_id[i].configuration.get('filename', '')} "
                                                            f"({by_id[i].metric_count:,} measurements)")
            telemetry = telemetry_view_service.session_telemetry(principal, session_id)
            interfaces = telemetry.interfaces or [""]
            c1, c2, c3 = st.columns(3)
            interface = c1.selectbox("Interface", interfaces, format_func=lambda i: i or "(unnamed)")
            available = [t for t in TARGETS if telemetry.coverage.get(t, 0) > 0]
            if not available:
                st.warning("This session has neither utilization nor throughput values to forecast.")
                return
            target = c2.selectbox("Forecast target", available, format_func=lambda t: TARGETS[t])
            frame = telemetry.metrics if not interface else telemetry.metrics[telemetry.metrics["interface_name"] == interface]
            detected = summarize(frame, target, 300).median_interval_seconds or 300
            interval = int(c3.number_input("Sampling interval (s)", 10, 86_400, int(round(detected)), step=10,
                                           help=f"Detected median spacing: {detected:,.0f} s. Horizons must be multiples."))
            summary = summarize(frame, target, interval)
            section_label("Time-series inspection")
            charts.time_series(frame.assign(interface_name=None), [(target, TARGETS[target])],
                               title=f"{TARGETS[target]} history", y_title=TARGETS[target],
                               y_format=".0%" if target == "utilization_ratio" else None, height=280)
            usable_hours = summary.measured_points * interval / 3600
            st.caption(f"{summary.measured_points:,} of {summary.points:,} intervals have a value "
                       f"({summary.missing_share:.0%} missing) · {format_timestamp(summary.start)} → "
                       f"{format_timestamp(summary.end)} · ≈ {usable_hours:,.1f} h of data. Minimum required: "
                       f"{settings.min_training_samples} usable samples per horizon.")
            if summary.measured_points < settings.min_training_samples:
                st.warning("This session is shorter than the minimum history, so training will be refused. "
                           "Import more telemetry.")

            if not principal.has(Permission.TRAIN_MODELS):
                st.info("Your role cannot train models.")
                return
            choices = sorted(set(valid_horizons_minutes(list(settings.horizons_minutes) + [5, 15, 30, 60], interval)))
            with st.form("forecast_train_form", border=True):
                default = [m for m in settings.horizons_minutes if m in choices] or choices[:1]
                horizons = st.multiselect("Forecast horizons (minutes)", choices, default=default,
                                          help="Only horizons that are whole multiples of the sampling interval.")
                activate = False
                if principal.has(Permission.ACTIVATE_MODELS):
                    activate = st.checkbox("Activate this forecaster if training succeeds")
                submitted = st.form_submit_button("Train forecaster", type="primary", icon=":material/model_training:")
            if submitted:
                bar = st.progress(0.0, text="Starting")
                try:
                    report = congestion_training_service.train_forecaster(
                        principal, ForecastTrainingOptions(session_id=session_id, interface_name=interface or None,
                                                           target=target, interval_seconds=interval,
                                                           horizons_minutes=tuple(horizons), activate=activate),
                        progress=lambda message, fraction: bar.progress(fraction, text=message),
                    )
                except (ForecastTrainingError, PermissionDenied) as exc:
                    bar.empty()
                    st.error(str(exc))
                else:
                    bar.empty()
                    show_report(report)
    with registry_tab:
        def metric_columns(m):
            summary = m.metrics.get("summary", {})
            target = m.training_metadata.get("target", "utilization_ratio")
            return {"Target": TARGETS.get(target, target),
                    "Interval": f"{m.training_metadata.get('interval_seconds', 0)} s",
                    "Horizons": ", ".join(summary) or "—",
                    "Test MAE": " · ".join(f"{k}: {_fmt(v['test']['mae'], target)}" for k, v in summary.items()),
                    "Chosen": ", ".join(sorted({KIND_LABELS[v['chosen']] for v in summary.values()}))}

        registry_section(principal, ["congestion_forecaster"], metric_columns, key="predictnet")
