from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from services import (
    alert_service, congestion_prediction_service, congestion_training_service, database_service,
    model_registry_service, settings_service, telemetry_service,
)
from services.authorization import PermissionDenied
from services.congestion_prediction_service import PredictionError, assess_risk
from services.congestion_training_service import ForecastTrainingError, ForecastTrainingOptions
from services.forecasting import (
    ForecastError, LastValueModel, MovingAverageModel, build_features, chronological_split, horizon_steps,
    regression_metrics, resample, supervised, valid_horizons_minutes,
)
from services.settings_service import PredictNetSettings, SettingsError, risk_level
from services.telemetry_service import TelemetryImportOptions
from tests.conftest import audit_rows
from tests.synthetic import telemetry_csv

DEFAULTS = PredictNetSettings()


def regular_series(values, start="2026-10-01T00:00:00Z", freq="5min"):
    return pd.Series(values, index=pd.date_range(start, periods=len(values), freq=freq), dtype=float)


def import_session(principal, **kwargs):
    data = telemetry_csv(**kwargs)
    return telemetry_service.import_telemetry_csv(principal, data, "t.csv", TelemetryImportOptions(source_name="lab")).session_id


# ------------------------------------------------------- features & splits

def test_features_use_only_past_values():
    series = regular_series(np.arange(40))
    features = build_features(series)
    t = series.index[20]
    assert features.loc[t, "lag_0"] == 20 and features.loc[t, "lag_3"] == 17
    assert features.loc[t, "rolling_mean_3"] == pytest.approx((18 + 19 + 20) / 3)
    assert features.loc[t, "rolling_max_12"] == 20  # never sees 21+
    # Changing a future value must not change any feature at t.
    changed = series.copy()
    changed.iloc[21:] = 999
    pd.testing.assert_series_equal(build_features(changed).loc[t], features.loc[t])


def test_supervised_target_is_future_and_gaps_are_dropped_not_filled():
    series = regular_series(np.arange(60, dtype=float))
    series.iloc[30] = np.nan
    x, y = supervised(series, horizon_steps=2)
    assert (y.to_numpy() == x["lag_0"].to_numpy() + 2).all()
    assert x.notna().all(axis=None) and y.notna().all()
    assert series.index[30] not in x.index and series.index[28] not in x.index  # target would be the gap


def test_resample_keeps_missing_buckets_empty():
    frame = pd.DataFrame({"timestamp": pd.to_datetime(["2026-10-01T00:00Z", "2026-10-01T00:20Z"], utc=True),
                          "utilization_ratio": [0.1, 0.2]})
    series = resample(frame, "utilization_ratio", 300)
    assert len(series) == 5 and series.isna().sum() == 3


def test_chronological_split_is_ordered_and_disjoint():
    index = pd.date_range("2026-01-01", periods=100, freq="h")
    train, val, test = chronological_split(index)
    assert index[train][-1] < index[val][0] and index[val][-1] < index[test][0]
    assert len(index[train]) + len(index[val]) + len(index[test]) == 100


def test_horizons_must_match_sampling_interval():
    assert horizon_steps(900, 300) == 3
    with pytest.raises(ForecastError, match="multiples"):
        horizon_steps(60, 300)
    with pytest.raises(ForecastError):
        horizon_steps(450, 300)
    assert valid_horizons_minutes([1, 5, 7, 15], 300) == [5, 15]


def test_baselines_and_metrics():
    series = regular_series(np.arange(30, dtype=float))
    features = build_features(series).dropna()
    assert LastValueModel().predict(features)[0] == features["lag_0"].iloc[0]
    assert MovingAverageModel().predict(features)[0] == pytest.approx(features["rolling_mean_6"].iloc[0])
    metrics = regression_metrics(np.array([1.0, 2, 3]), np.array([1.0, 2, 4]))
    assert metrics["mae"] == pytest.approx(1 / 3) and metrics["rmse"] == pytest.approx(np.sqrt(1 / 3))


# --------------------------------------------------------------- settings

def test_settings_defaults_validation_and_admin_only(admin, analyst):
    assert settings_service.get_predictnet_settings() == DEFAULTS
    with pytest.raises(SettingsError, match="increase"):
        PredictNetSettings(elevated_threshold=0.8, high_threshold=0.7).validate()
    with pytest.raises(PermissionDenied):
        settings_service.update_predictnet_settings(analyst, DEFAULTS)
    settings_service.update_predictnet_settings(admin, PredictNetSettings(horizons_minutes=(15, 5, 5)))
    assert settings_service.get_predictnet_settings().horizons_minutes == (5, 15)
    assert settings_service.settings_source() == "configured"
    assert len(audit_rows("settings.update", "success")) == 1


def test_risk_levels_follow_configured_thresholds():
    assert [risk_level(v, DEFAULTS) for v in (0.1, 0.6, 0.75, 0.95)] == ["normal", "elevated", "high", "critical"]
    custom = PredictNetSettings(elevated_threshold=0.3, high_threshold=0.4, critical_threshold=0.5)
    assert risk_level(0.45, custom) == "high"


def test_risk_assessment_rules():
    assert assess_risk(None, None, 0.05, None, DEFAULTS).level == "unknown"
    assert assess_risk(0.5, 0.65, 0.02, 0.1, DEFAULTS).level == "elevated"
    assert assess_risk(0.8, 0.4, 0.02, -0.1, DEFAULTS).level == "high"  # current counts too
    raised = assess_risk(0.6, 0.70, 0.08, 0.2, DEFAULTS)  # 0.70 + 0.08 reaches "high" while rising
    assert raised.level == "high" and any("Raised one level" in r for r in raised.reasons)
    assert assess_risk(0.6, 0.70, 0.08, -0.2, DEFAULTS).level == "elevated"  # falling: no escalation
    assert assess_risk(0.2, 0.2, 0.01, 0, DEFAULTS, packet_loss=0.05).level == "elevated"


# --------------------------------------------------------------- training

def test_training_compares_baselines_and_registers(analyst):
    session_id = import_session(analyst, days=3)
    report = congestion_training_service.train_forecaster(
        analyst, ForecastTrainingOptions(session_id=session_id, interface_name="eth0", horizons_minutes=(5, 15)))
    assert set(report.per_horizon) == {"5 min", "15 min"}
    for horizon in report.per_horizon.values():
        assert set(horizon["candidates"]) == {"last_value", "moving_average", "hist_gradient_boosting", "random_forest"}
        for result in horizon["candidates"].values():
            assert {"mae", "rmse", "r2", "n"} <= set(result["test"])
    periods = report.metadata["split_periods"]["5 min"]
    assert periods["train"][1] < periods["validation"][0] < periods["test"][0]
    record = model_registry_service.get_model(analyst, report.model_id)
    assert record.family == "congestion_forecaster" and not record.is_active


def test_baseline_is_kept_when_ml_does_not_beat_it(analyst):
    # A random walk: the best predictor is the last value, so ML should not be chosen.
    rng = np.random.default_rng(0)
    n = 900
    walk = np.clip(0.5 + np.cumsum(rng.normal(0, 0.01, n)), 0, 1)
    times = pd.date_range("2026-10-01T00:00:00Z", periods=n, freq="5min")
    csv = pd.DataFrame({"timestamp": times.strftime("%Y-%m-%dT%H:%M:%SZ"), "utilization_ratio": walk.round(5)})
    session_id = telemetry_service.import_telemetry_csv(
        analyst, csv.to_csv(index=False).encode(), "walk.csv", TelemetryImportOptions(source_name="walk")).session_id
    report = congestion_training_service.train_forecaster(
        analyst, ForecastTrainingOptions(session_id=session_id, interface_name=None, horizons_minutes=(5,)))
    assert report.per_horizon["5 min"]["chosen"] in ("last_value", "moving_average")
    assert "baseline is used" in report.per_horizon["5 min"]["reason"]


def test_training_refused_below_minimum_history(analyst):
    session_id = import_session(analyst, days=0.5)  # 144 samples < 200
    with pytest.raises(ForecastTrainingError, match="Not enough history"):
        congestion_training_service.train_forecaster(
            analyst, ForecastTrainingOptions(session_id=session_id, interface_name="eth0", horizons_minutes=(5,)))
    assert model_registry_service.list_models(analyst) == []
    assert len(audit_rows("model.train_forecaster", "failure")) == 1


def test_inconsistent_horizon_refused(analyst):
    session_id = import_session(analyst, days=2)
    with pytest.raises(ForecastTrainingError, match="multiples"):
        congestion_training_service.train_forecaster(
            analyst, ForecastTrainingOptions(session_id=session_id, interface_name="eth0", horizons_minutes=(1,)))


def test_throughput_target_without_capacity_gives_unknown_risk(admin):
    data = telemetry_csv(days=2, with_utilization=False)
    session_id = telemetry_service.import_telemetry_csv(admin, data, "tp.csv", TelemetryImportOptions(source_name="x")).session_id
    report = congestion_training_service.train_forecaster(admin, ForecastTrainingOptions(
        session_id=session_id, interface_name="eth0", target="throughput_bps", horizons_minutes=(5,), activate=True))
    run = congestion_prediction_service.generate_forecast(admin, session_id, "eth0")
    forecast = run.forecasts[0]
    assert forecast.predicted_throughput_bps > 0 and forecast.predicted_utilization is None
    assert forecast.risk.level == "unknown"
    with database_service.session() as conn:
        row = conn.execute("SELECT * FROM congestion_predictions").fetchone()
    assert row["predicted_utilization_ratio"] is None and row["congestion_risk"] == "unknown"
    assert row["model_id"] == report.model_id and row["provenance"] == "predicted"


# ------------------------------------------------------- prediction/alerts

@pytest.fixture
def active_forecaster(admin):
    session_id = import_session(admin, days=3, peak=0.97)
    report = congestion_training_service.train_forecaster(admin, ForecastTrainingOptions(
        session_id=session_id, interface_name="eth0", horizons_minutes=(5, 15), activate=True))
    return session_id, report


def test_forecast_stores_predictions_with_model_version(admin, analyst, active_forecaster):
    session_id, report = active_forecaster
    run = congestion_prediction_service.generate_forecast(analyst, session_id, "eth0")
    assert [f.horizon_seconds for f in run.forecasts] == [300, 900]
    with database_service.session() as conn:
        rows = conn.execute("SELECT * FROM congestion_predictions ORDER BY forecast_horizon_seconds").fetchall()
    assert len(rows) == 2 and all(r["model_version"] == report.version for r in rows)
    assert all(0 <= r["predicted_utilization_ratio"] <= 1 for r in rows)
    history = congestion_prediction_service.recent_predictions(analyst)
    assert history[0]["metadata"]["target_time"] > history[0]["metadata"]["base_time"]


def test_congestion_alerts_are_performance_alerts_with_cooldown(admin, active_forecaster):
    session_id, _ = active_forecaster
    # Push the latest data into sustained critical territory.
    with database_service.session(write=True) as conn:
        conn.execute("UPDATE network_metrics SET utilization_ratio = 0.96 WHERE id IN "
                     "(SELECT id FROM network_metrics ORDER BY timestamp DESC LIMIT 20)")
    run = congestion_prediction_service.generate_forecast(admin, session_id, "eth0")
    alerts = alert_service.list_alerts(admin)
    assert run.alerts_created and {a.alert_type for a in alerts} <= {"congestion", "performance"}
    categories = {a.category for a in alerts}
    assert "Sustained high utilization" in categories
    assert all("does not indicate an attack" in a.evidence["note"] for a in alerts)
    again = congestion_prediction_service.generate_forecast(admin, session_id, "eth0")
    assert again.alerts_created == [] and again.alerts_suppressed == len(run.alerts_created)


def test_forecast_needs_complete_recent_history(admin, active_forecaster):
    session_id, _ = active_forecaster
    with database_service.session(write=True) as conn:
        conn.execute("DELETE FROM network_metrics WHERE id IN "
                     "(SELECT id FROM network_metrics ORDER BY timestamp DESC LIMIT 5 OFFSET 2)")
    with pytest.raises(PredictionError, match="Not enough recent history"):
        congestion_prediction_service.generate_forecast(admin, session_id, "eth0")


def test_no_active_forecaster_explains_next_step(analyst):
    session_id = import_session(analyst, days=1)
    with pytest.raises(PredictionError, match="no active PredictNet forecaster"):
        congestion_prediction_service.generate_forecast(analyst, session_id, "eth0")


def test_backtest_labels_periods(admin, active_forecaster):
    session_id, report = active_forecaster
    record = model_registry_service.get_model(admin, report.model_id)
    bt = congestion_prediction_service.backtest(admin, record, session_id, "eth0", 300)
    assert {"train", "validation", "test"} <= set(bt["period"])
    test_part = bt[bt["period"] == "test"].dropna()
    assert (test_part["predicted"].between(0, 1)).all() and len(test_part) > 20
