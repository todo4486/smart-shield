"""PredictNet training: baselines first, then Random Forest / HistGradientBoosting,
one model per forecast horizon, all evaluated on a chronological test period.

Selection rule ("use the simplest model that performs reliably"): for each
horizon the machine-learning model is chosen only if its validation MAE beats
the best baseline by at least ML_MARGIN; otherwise the baseline is kept.
Training refuses to run below the configured minimum history.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingRegressor, RandomForestRegressor

from repositories import monitoring_repository, telemetry_repository
from services import audit_service, database_service, model_registry_service, settings_service
from services.authorization import Permission, Principal, require_permission
from services.intrusion_features import schema_version
from services.forecasting import (
    TARGETS, ForecastError, LastValueModel, MovingAverageModel, chronological_split, clip_predictions,
    feature_names, horizon_steps, regression_metrics, resample, supervised,
)

RANDOM_STATE = 42
ML_MARGIN = 0.02  # ML must beat the best baseline's validation MAE by 2%
MIN_SPLIT_ROWS = 20
Progress = Callable[[str, float], None]


class ForecastTrainingError(Exception):
    """A user-facing training failure. Nothing was registered."""


@dataclass(frozen=True)
class ForecastTrainingOptions:
    session_id: int
    interface_name: Optional[str]
    target: str = "utilization_ratio"
    interval_seconds: int = 300
    horizons_minutes: tuple = (5,)
    activate: bool = False


@dataclass
class ForecastTrainingReport:
    model_id: int
    version: str
    per_horizon: Dict[str, Dict[str, Any]]
    metadata: Dict[str, Any]
    activated: bool = False
    warnings: List[str] = field(default_factory=list)


def load_session_frame(session_id: int, interface_name: Optional[str]) -> pd.DataFrame:
    with database_service.session() as conn:
        if monitoring_repository.get(conn, session_id) is None:
            raise ForecastTrainingError("Monitoring session not found.")
        rows = telemetry_repository.metrics_for_session(conn, session_id, interface_name)
    frame = pd.DataFrame([dict(r) for r in rows])
    if frame.empty:
        raise ForecastTrainingError("This session has no measurements for that interface.")
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, format="ISO8601")
    return frame


def train_forecaster(principal: Principal, options: ForecastTrainingOptions,
                     progress: Optional[Progress] = None) -> ForecastTrainingReport:
    require_permission(principal, Permission.TRAIN_MODELS, action="model.train_forecaster",
                       details={"session_id": options.session_id})
    if options.activate:
        require_permission(principal, Permission.ACTIVATE_MODELS, action="model.activate")
    try:
        return _train(principal, options, progress or (lambda message, fraction: None))
    except (ForecastTrainingError, ForecastError) as exc:
        audit_service.record_standalone(user_id=principal.user_id, action="model.train_forecaster", outcome="failure",
                                        details={"session_id": options.session_id, "error": str(exc)[:300]})
        if isinstance(exc, ForecastError):
            raise ForecastTrainingError(str(exc)) from exc
        raise


def _train(principal: Principal, options: ForecastTrainingOptions, progress: Progress) -> ForecastTrainingReport:
    started = time.monotonic()
    settings = settings_service.get_predictnet_settings()
    if options.target not in TARGETS:
        raise ForecastTrainingError("Unknown forecasting target.")
    if not 10 <= options.interval_seconds <= 86_400:
        raise ForecastTrainingError("Sampling interval must be between 10 seconds and 1 day.")
    if not options.horizons_minutes:
        raise ForecastTrainingError("Choose at least one forecast horizon.")
    steps_by_horizon = {int(m) * 60: horizon_steps(int(m) * 60, options.interval_seconds)
                        for m in sorted(set(options.horizons_minutes))}

    progress("Loading telemetry", 0.05)
    frame = load_session_frame(options.session_id, options.interface_name)
    series = resample(frame, options.target, options.interval_seconds)
    measured = int(series.notna().sum())
    warnings: List[str] = []
    missing_share = float(series.isna().mean())
    if missing_share > 0.2:
        warnings.append(f"{missing_share:.0%} of {options.interval_seconds}-second intervals have no measurement. "
                        "Gaps are left empty, which reduces the usable history.")
    if options.target == "utilization_ratio" and "utilization_provenance" in frame.columns:
        derived = (frame["utilization_provenance"] == "derived").mean()
        if derived > 0:
            warnings.append(f"{derived:.0%} of utilization values were derived from throughput and configured "
                            "capacity rather than measured directly.")

    per_horizon: Dict[str, Dict[str, Any]] = {}
    bundle_horizons: Dict[int, Dict[str, Any]] = {}
    periods: Dict[str, Any] = {}
    for index, (horizon_seconds, steps) in enumerate(steps_by_horizon.items()):
        label = f"{horizon_seconds // 60} min"
        progress(f"Training {label} horizon", 0.1 + 0.75 * index / len(steps_by_horizon))
        x, y = supervised(series, steps)
        if len(x) < settings.min_training_samples:
            hours = settings.min_training_samples * options.interval_seconds / 3600
            raise ForecastTrainingError(
                f"Not enough history for the {label} horizon: {len(x)} usable samples after removing gaps, but "
                f"at least {settings.min_training_samples} are required (about {hours:,.1f} hours of complete data "
                f"at a {options.interval_seconds}-second interval). Import more telemetry."
            )
        train_s, val_s, test_s = chronological_split(x.index)
        x_train, x_val, x_test = x.iloc[train_s], x.iloc[val_s], x.iloc[test_s]
        y_train, y_val, y_test = y.iloc[train_s], y.iloc[val_s], y.iloc[test_s]
        if min(len(x_val), len(x_test)) < MIN_SPLIT_ROWS:
            raise ForecastTrainingError("The validation or test period is too short. Import more telemetry.")

        candidates: Dict[str, Any] = {
            "last_value": LastValueModel(),
            "moving_average": MovingAverageModel(),
            "hist_gradient_boosting": HistGradientBoostingRegressor(
                max_iter=300, learning_rate=0.05, random_state=RANDOM_STATE),
            "random_forest": RandomForestRegressor(
                n_estimators=200, min_samples_leaf=2, n_jobs=-1, random_state=RANDOM_STATE),
        }
        results: Dict[str, Dict[str, Any]] = {}
        for name, model in candidates.items():
            if hasattr(model, "fit"):
                model.fit(x_train, y_train)
            val_pred = clip_predictions(model.predict(x_val), options.target)
            test_pred = clip_predictions(model.predict(x_test), options.target)
            results[name] = {
                "validation": regression_metrics(y_val, val_pred), "test": regression_metrics(y_test, test_pred),
                "baseline": name in ("last_value", "moving_average"),
                "val_abs_error_q90": float(np.quantile(np.abs(y_val.to_numpy() - val_pred), 0.90)),
            }
        best_baseline = min(("last_value", "moving_average"), key=lambda n: results[n]["validation"]["mae"])
        best_ml = min(("hist_gradient_boosting", "random_forest"), key=lambda n: results[n]["validation"]["mae"])
        baseline_mae = results[best_baseline]["validation"]["mae"]
        if results[best_ml]["validation"]["mae"] < baseline_mae * (1 - ML_MARGIN):
            chosen = best_ml
            reason = (f"{best_ml.replace('_', ' ')} beat the best baseline ({best_baseline.replace('_', ' ')}) on "
                      f"validation MAE by {(1 - results[best_ml]['validation']['mae'] / baseline_mae):.1%}.")
        else:
            chosen = best_baseline
            reason = (f"No machine-learning model beat the {best_baseline.replace('_', ' ')} baseline by at least "
                      f"{ML_MARGIN:.0%} on validation data, so the simpler baseline is used.")
        per_horizon[label] = {"horizon_seconds": horizon_seconds, "steps": steps, "chosen": chosen,
                              "reason": reason, "candidates": results,
                              "split_sizes": {"train": len(x_train), "validation": len(x_val), "test": len(x_test)}}
        bundle_horizons[horizon_seconds] = {"kind": chosen, "model": candidates[chosen], "steps": steps,
                                            "val_mae": results[chosen]["validation"]["mae"],
                                            "abs_error_q90": results[chosen]["val_abs_error_q90"]}
        periods[label] = {
            "train": [x_train.index.min().isoformat(), x_train.index.max().isoformat()],
            "validation": [x_val.index.min().isoformat(), x_val.index.max().isoformat()],
            "test": [x_test.index.min().isoformat(), x_test.index.max().isoformat()],
        }

    progress("Saving and registering the model", 0.9)
    version = model_registry_service.new_version("forecast")
    environment = model_registry_service.environment_info()
    with database_service.session() as conn:
        session_row = monitoring_repository.get(conn, options.session_id)
    source_name = frame["source_name"].iloc[0] if "source_name" in frame.columns else None
    metadata = {
        "session_id": options.session_id, "dataset_id": session_row["dataset_id"], "source_name": source_name,
        "interface_name": options.interface_name, "target": options.target,
        "interval_seconds": options.interval_seconds, "horizons_seconds": sorted(bundle_horizons),
        "measured_intervals": measured, "missing_share": missing_share,
        "training_period": [series.index.min().isoformat(), series.index.max().isoformat()],
        "split_periods": periods, "feature_names": feature_names(),
        "minimum_history_samples": settings.min_training_samples, "selection_margin": ML_MARGIN,
        "environment": environment, "warnings": warnings,
        "training_seconds": round(time.monotonic() - started, 1),
    }
    bundle = {"family": "congestion_forecaster", "feature_names": feature_names(), "target": options.target,
              "interval_seconds": options.interval_seconds, "horizons": bundle_horizons, "environment": environment}
    path = None
    try:
        path, sha = model_registry_service.save_artifact(bundle, "congestion_forecaster", version)
        summary = {label: {"chosen": h["chosen"], "test": h["candidates"][h["chosen"]]["test"],
                           "best_baseline_test": min((h["candidates"][n]["test"] for n in ("last_value", "moving_average")),
                                                     key=lambda m: m["mae"])}
                   for label, h in per_horizon.items()}
        with database_service.session(write=True) as conn:
            model_id = model_registry_service.register(
                conn, family="congestion_forecaster", name=f"forecast_{options.target}", version=version,
                artifact_path=path, artifact_sha256=sha, feature_schema_version=schema_version(feature_names()),
                metrics={"per_horizon": per_horizon, "summary": summary}, training_metadata=metadata,
                created_by=principal.user_id,
            )
            audit_service.record(conn, user_id=principal.user_id, action="model.train_forecaster",
                                 details={"model_id": model_id, "version": version, "session_id": options.session_id,
                                          "chosen": {k: v["chosen"] for k, v in per_horizon.items()}})
    except Exception as exc:
        if path is not None:
            model_registry_service.discard_artifact(path)
        raise ForecastTrainingError(f"Saving the model failed; nothing was registered: {exc}") from exc

    report = ForecastTrainingReport(model_id=model_id, version=version, per_horizon=per_horizon,
                                    metadata=metadata, warnings=warnings)
    if options.activate:
        model_registry_service.activate(principal, model_id)
        report.activated = True
    progress("Done", 1.0)
    return report
