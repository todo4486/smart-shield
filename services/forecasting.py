"""PredictNet time-series building blocks (pure functions, no database).

Feature rules
* The series is resampled onto a fixed grid at the sampling interval. Empty
  buckets stay NaN: missing measurements are never filled.
* Every feature at time t uses only values at t or earlier (lags, trailing
  rolling windows, time of day). The target is the value h steps ahead.
* Rows with any missing feature or target are dropped, never imputed.
* Splits are chronological (train → validation → test) and never shuffled.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score

LAGS = 12
WINDOWS = (3, 6, 12)
MOVING_AVERAGE_WINDOW = 6
GROWTH_STEPS = 6
TARGETS = {
    "utilization_ratio": "Utilization (ratio 0–1)",
    "throughput_bps": "Throughput (bit/s)",
}


class ForecastError(ValueError):
    pass


def feature_names() -> List[str]:
    names = [f"lag_{i}" for i in range(LAGS)]
    for w in WINDOWS:
        names += [f"rolling_mean_{w}", f"rolling_max_{w}", f"rolling_std_{w}"]
    names += ["diff_1", f"diff_{GROWTH_STEPS}", "hour_sin", "hour_cos", "dow_sin", "dow_cos"]
    return names


def resample(frame: pd.DataFrame, target: str, interval_seconds: int) -> pd.Series:
    """Mean of the target per interval bucket on a regular UTC grid (NaN where nothing was measured)."""
    if target not in frame.columns:
        raise ForecastError(f"The data has no {target} column.")
    data = frame[["timestamp", target]].dropna()
    if data.empty:
        raise ForecastError(f"There are no {target} values to forecast.")
    series = data.set_index("timestamp")[target].sort_index()
    return series.resample(f"{int(interval_seconds)}s").mean()


def build_features(series: pd.Series) -> pd.DataFrame:
    """Past-only features for every timestamp of a regular series."""
    y = series.astype(float)
    features = {f"lag_{i}": y.shift(i) for i in range(LAGS)}
    for w in WINDOWS:
        rolling = y.rolling(w, min_periods=w)
        features[f"rolling_mean_{w}"] = rolling.mean()
        features[f"rolling_max_{w}"] = rolling.max()
        features[f"rolling_std_{w}"] = rolling.std(ddof=0)
    features["diff_1"] = y - y.shift(1)
    features[f"diff_{GROWTH_STEPS}"] = y - y.shift(GROWTH_STEPS)
    index = series.index
    hours = index.hour + index.minute / 60.0
    features["hour_sin"] = np.sin(2 * np.pi * hours / 24)
    features["hour_cos"] = np.cos(2 * np.pi * hours / 24)
    features["dow_sin"] = np.sin(2 * np.pi * index.dayofweek / 7)
    features["dow_cos"] = np.cos(2 * np.pi * index.dayofweek / 7)
    return pd.DataFrame(features, index=index)[feature_names()]


def supervised(series: pd.Series, horizon_steps: int) -> Tuple[pd.DataFrame, pd.Series]:
    """(X at time t, y at time t + horizon). Rows with gaps are dropped."""
    if horizon_steps < 1:
        raise ForecastError("Horizon must be at least one sampling interval.")
    features = build_features(series)
    target = series.shift(-horizon_steps).rename("target")
    joined = features.join(target).dropna()
    return joined[feature_names()], joined["target"]


def chronological_split(index: pd.Index, train: float = 0.70, validation: float = 0.15) -> Tuple[slice, slice, slice]:
    n = len(index)
    a, b = int(n * train), int(n * (train + validation))
    return slice(0, a), slice(a, b), slice(b, n)


def horizon_steps(horizon_seconds: int, interval_seconds: int) -> int:
    if horizon_seconds < interval_seconds or horizon_seconds % interval_seconds:
        raise ForecastError(
            f"A {horizon_seconds // 60}-minute horizon is not a whole number of {interval_seconds}-second "
            "sampling intervals. Choose horizons that are multiples of the interval."
        )
    return horizon_seconds // interval_seconds


def valid_horizons_minutes(candidates: List[int], interval_seconds: int) -> List[int]:
    return [m for m in candidates if m * 60 >= interval_seconds and (m * 60) % interval_seconds == 0]


# --------------------------------------------------------------- baselines
# Module-level classes so joblib can reload them from a registered artifact.

class LastValueModel:
    """Baseline: the forecast is the latest observed value."""

    kind = "last_value"

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        return features["lag_0"].to_numpy(dtype=float)


class MovingAverageModel:
    """Baseline: the forecast is the mean of the last MOVING_AVERAGE_WINDOW values."""

    kind = "moving_average"

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        return features[f"rolling_mean_{MOVING_AVERAGE_WINDOW}"].to_numpy(dtype=float)


def clip_predictions(values: np.ndarray, target: str) -> np.ndarray:
    upper = 1.0 if target == "utilization_ratio" else None
    return np.clip(values, 0.0, upper)


def regression_metrics(actual: np.ndarray, predicted: np.ndarray) -> Dict[str, Optional[float]]:
    actual = np.asarray(actual, dtype=float)
    predicted = np.asarray(predicted, dtype=float)
    return {
        "mae": float(mean_absolute_error(actual, predicted)),
        "rmse": float(np.sqrt(mean_squared_error(actual, predicted))),
        "r2": float(r2_score(actual, predicted)) if len(actual) > 1 and np.var(actual) > 0 else None,
        "n": int(len(actual)),
    }


@dataclass
class SeriesSummary:
    points: int
    measured_points: int
    missing_share: float
    start: str
    end: str
    median_interval_seconds: Optional[float]


def summarize(frame: pd.DataFrame, target: str, interval_seconds: int) -> SeriesSummary:
    series = resample(frame, target, interval_seconds)
    raw = frame[["timestamp", target]].dropna()
    diffs = raw["timestamp"].sort_values().diff().dropna().dt.total_seconds()
    return SeriesSummary(
        points=int(len(series)), measured_points=int(series.notna().sum()),
        missing_share=float(series.isna().mean()) if len(series) else 1.0,
        start=series.index.min().isoformat(), end=series.index.max().isoformat(),
        median_interval_seconds=float(diffs.median()) if len(diffs) else None,
    )
