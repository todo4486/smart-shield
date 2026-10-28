"""PredictNet forecasts, congestion risk and congestion alerts.

Risk rules (deterministic, documented in the PredictNet Congestion Center)
1. Utilization is needed. Forecasting throughput converts to utilization only
   with a configured capacity. Without one the risk is "unknown" and only
   absolute rates are shown.
2. Base level = the higher of the current and the predicted utilization level,
   using the configured thresholds.
3. Uncertainty: if predicted + the 90th-percentile validation error reaches the
   next level while utilization is rising, the risk is raised one level.
4. Degradation: packet loss ≥ 2% or latency ≥ 2× the session median raises
   "normal" to "elevated".

Congestion never implies an attack. These alerts are performance alerts.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from services import alert_service, audit_service, database_service, model_registry_service, settings_service
from services.authorization import Permission, Principal, require_permission
from services.congestion_training_service import load_session_frame
from services.forecasting import GROWTH_STEPS, ForecastError, build_features, clip_predictions, resample
from services.model_registry_service import ModelRecord
from services.settings_service import RISK_ORDER, PredictNetSettings, risk_level

LOSS_DEGRADATION = 0.02
LATENCY_FACTOR = 2.0
NOT_AN_ATTACK = "Congestion alone does not indicate an attack; check Smart Shield alerts for security evidence."


class PredictionError(Exception):
    pass


@dataclass
class RiskAssessment:
    level: str  # normal / elevated / high / critical / unknown
    current_utilization: Optional[float]
    predicted_utilization: Optional[float]
    upper_bound: Optional[float]
    growth_per_hour: Optional[float]
    reasons: List[str] = field(default_factory=list)


@dataclass
class HorizonForecast:
    horizon_seconds: int
    target_time: str
    predicted_value: float
    predicted_utilization: Optional[float]
    predicted_throughput_bps: Optional[float]
    lower: float
    upper: float
    model_kind: str
    risk: RiskAssessment
    prediction_id: int


@dataclass
class ForecastRun:
    model_id: int
    model_version: str
    base_time: str
    target: str
    capacity_bps: Optional[float]
    forecasts: List[HorizonForecast]
    alerts_created: List[int]
    alerts_suppressed: int
    warnings: List[str] = field(default_factory=list)


def assess_risk(current: Optional[float], predicted: Optional[float], q90: float, growth_per_hour: Optional[float],
                settings: PredictNetSettings, *, packet_loss: Optional[float] = None,
                latency_ratio: Optional[float] = None) -> RiskAssessment:
    if current is None and predicted is None:
        return RiskAssessment("unknown", None, None, None, growth_per_hour,
                              ["Utilization is unavailable: no utilization data and no configured capacity."])
    levels = [risk_level(v, settings) for v in (current, predicted) if v is not None]
    level = max(levels, key=RISK_ORDER.index)
    reasons = []
    if current is not None:
        reasons.append(f"Current utilization {current:.0%} ({risk_level(current, settings)}).")
    upper = None
    if predicted is not None:
        reasons.append(f"Predicted utilization {predicted:.0%} ({risk_level(predicted, settings)}).")
        upper = min(1.0, predicted + q90)
        upper_level = risk_level(upper, settings)
        if (RISK_ORDER.index(upper_level) > RISK_ORDER.index(level) and growth_per_hour is not None
                and growth_per_hour > 0 and level != "critical"):
            level = RISK_ORDER[RISK_ORDER.index(level) + 1]
            reasons.append(f"Raised one level: with typical forecast error (±{q90:.0%}) and rising traffic, "
                           f"utilization could reach {upper:.0%}.")
    degraded = []
    if packet_loss is not None and packet_loss >= LOSS_DEGRADATION:
        degraded.append(f"packet loss {packet_loss:.1%}")
    if latency_ratio is not None and latency_ratio >= LATENCY_FACTOR:
        degraded.append(f"latency {latency_ratio:.1f}× the session median")
    if degraded:
        reasons.append("Performance degradation measured: " + ", ".join(degraded) + ".")
        if level == "normal":
            level = "elevated"
    return RiskAssessment(level, current, predicted, upper, growth_per_hour, reasons)


def _latest(frame: pd.DataFrame, column: str) -> Optional[float]:
    if column not in frame.columns:
        return None
    values = frame[column].dropna()
    return float(values.iloc[-1]) if len(values) else None


def generate_forecast(principal: Principal, session_id: int, interface_name: Optional[str],
                      model_id: Optional[int] = None) -> ForecastRun:
    """Forecast every horizon of the model from the latest complete data, store predictions, raise alerts."""
    require_permission(principal, Permission.RUN_DETECTION, action="forecast.run",
                       details={"session_id": session_id, "interface": interface_name})
    settings = settings_service.get_predictnet_settings()
    record = (model_registry_service.get_model(principal, model_id) if model_id
              else model_registry_service.active_model(principal, "congestion_forecaster"))
    if record is None:
        raise PredictionError("There is no active PredictNet forecaster. Train one in the ML Laboratory and ask an "
                              "administrator to activate it.")
    if record.family != "congestion_forecaster":
        raise PredictionError("That model is not a congestion forecaster.")
    try:
        bundle = model_registry_service.load_bundle(record)
        frame = load_session_frame(session_id, interface_name)
        series = resample(frame, bundle["target"], bundle["interval_seconds"])
    except (model_registry_service.ModelRegistryError, ForecastError) as exc:
        raise PredictionError(str(exc)) from exc
    except Exception as exc:  # session/frame errors carry their own message
        raise PredictionError(str(exc)) from exc

    features = build_features(series)
    latest = features.iloc[[-1]]
    if latest.isna().any(axis=None):
        raise PredictionError(
            "Not enough recent history to forecast: the most recent "
            f"{max(12, GROWTH_STEPS)} intervals of {bundle['interval_seconds']} s must all have measurements."
        )
    base_time = series.index[-1]
    warnings: List[str] = []
    model_interval = bundle["interval_seconds"]
    observed = frame["timestamp"].sort_values().diff().dropna().dt.total_seconds().median()
    if observed and abs(observed - model_interval) / model_interval > 0.5:
        warnings.append(f"This data is sampled every {observed:.0f} s but the model expects {model_interval} s; "
                        "values were averaged onto the model's interval.")

    capacity = _latest(frame, "configured_capacity_bps")
    target = bundle["target"]
    current_value = float(series.iloc[-1])
    if target == "utilization_ratio":
        current_util = current_value
    else:
        current_util = current_value / capacity if capacity else None
    if current_util is not None and current_util > 1:
        current_util = None
        warnings.append("Throughput is above the configured capacity; check the capacity value. Utilization is "
                        "treated as unavailable.")
    previous = series.iloc[-1 - GROWTH_STEPS] if len(series) > GROWTH_STEPS else np.nan
    growth = None
    if pd.notna(previous):
        delta = current_value - float(previous)
        if target == "throughput_bps":
            delta = delta / capacity if capacity else None
        if delta is not None:
            growth = delta / (GROWTH_STEPS * model_interval) * 3600
    loss = _latest(frame, "packet_loss_ratio")
    latency = _latest(frame, "latency_ms")
    latency_median = frame["latency_ms"].median() if "latency_ms" in frame.columns else None
    latency_ratio = (latency / latency_median) if latency and latency_median else None

    forecasts: List[HorizonForecast] = []
    created: List[int] = []
    suppressed = 0
    source_name = str(frame["source_name"].iloc[-1]) if "source_name" in frame.columns else "unknown"
    iface = "(all interfaces)" if interface_name is None else (interface_name or "(unnamed interface)")
    with database_service.session(write=True) as conn:
        for horizon_seconds, spec in sorted(bundle["horizons"].items()):
            predicted = float(clip_predictions(spec["model"].predict(latest), target)[0])
            q90 = float(spec["abs_error_q90"])
            if target == "utilization_ratio":
                predicted_util, predicted_tp = predicted, None
                q90_util = q90
            else:
                predicted_tp = predicted
                predicted_util = predicted / capacity if capacity else None
                q90_util = q90 / capacity if capacity else 0.0
                if predicted_util is not None and predicted_util > 1:
                    # More throughput than the configured capacity means the capacity is wrong; never invent 100%.
                    predicted_util = None
                    message = ("Predicted throughput is above the configured capacity; check the capacity value. "
                               "Predicted utilization is treated as unavailable.")
                    if message not in warnings:
                        warnings.append(message)
            risk = assess_risk(current_util, predicted_util, q90_util, growth, settings,
                               packet_loss=loss, latency_ratio=latency_ratio)
            target_time = base_time + timedelta(seconds=int(horizon_seconds))
            metadata = {
                "base_time": base_time.isoformat(), "target_time": target_time.isoformat(),
                "target": target, "interval_seconds": model_interval, "model_kind": spec["kind"],
                "interval_90": [max(0.0, predicted - q90), predicted + q90], "current_value": current_value,
                "current_utilization": current_util, "growth_per_hour": growth,
                "capacity_bps": capacity, "capacity_provenance": "configured" if capacity else "unavailable",
                "risk_reasons": risk.reasons, "session_id": session_id, "thresholds": settings.thresholds(),
            }
            cursor = conn.execute(
                "INSERT INTO congestion_predictions (timestamp, source_name, interface_name, forecast_horizon_seconds, "
                "predicted_utilization_ratio, predicted_throughput_bps, congestion_risk, model_id, model_version, "
                "prediction_metadata_json, provenance) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'predicted')",
                (base_time.isoformat(timespec="microseconds"), source_name, interface_name, int(horizon_seconds),
                 predicted_util, predicted_tp, risk.level, record.id, record.version,
                 json.dumps(metadata, default=float)),
            )
            forecasts.append(HorizonForecast(
                horizon_seconds=int(horizon_seconds), target_time=target_time.isoformat(), predicted_value=predicted,
                predicted_utilization=predicted_util, predicted_throughput_bps=predicted_tp,
                lower=max(0.0, predicted - q90), upper=predicted + q90, model_kind=spec["kind"], risk=risk,
                prediction_id=int(cursor.lastrowid),
            ))

        # ------------------------------------------------------------ alerts
        worst = max(forecasts, key=lambda f: (RISK_ORDER.index(f.risk.level) if f.risk.level in RISK_ORDER else -1,
                                              -f.horizon_seconds))
        candidates = []
        if worst.risk.level in ("high", "critical"):
            outlook = (f"Utilization is forecast to reach {worst.predicted_utilization:.0%} within "
                       f"{worst.horizon_seconds // 60} min on {iface} ({worst.risk.level} risk)."
                       if worst.predicted_utilization is not None else
                       f"Current utilization on {iface} is {worst.risk.level} risk "
                       f"({current_util:.0%}); the forecast itself is unavailable.")
            candidates.append(("congestion", "critical" if worst.risk.level == "critical" else "high",
                               "Predicted congestion", outlook,
                               "Review the bandwidth recommendation, look for large scheduled transfers, and consider "
                               "prioritising latency-sensitive traffic."))
        if (growth is not None and current_util is not None and growth >= settings.rapid_rise_per_hour
                and current_util >= settings.elevated_threshold):
            candidates.append(("congestion", "medium", "Rapid utilization rise",
                               f"Utilization on {iface} is rising by {growth:.0%} per hour and is already "
                               f"{current_util:.0%}.", "Identify the fastest-growing traffic and confirm it is expected."))
        if target == "utilization_ratio" or capacity:
            recent = series.dropna().tail(settings.sustained_high_samples)
            recent_util = recent if target == "utilization_ratio" else recent / capacity
            if len(recent_util) == settings.sustained_high_samples and (recent_util >= settings.high_threshold).all():
                candidates.append(("congestion", "high", "Sustained high utilization",
                                   f"The last {settings.sustained_high_samples} measurements on {iface} were all at or "
                                   f"above {settings.high_threshold:.0%}.",
                                   "Check whether capacity is adequate for current demand."))
        if (loss is not None and loss >= LOSS_DEGRADATION) or (latency_ratio is not None and latency_ratio >= LATENCY_FACTOR):
            candidates.append(("performance", "medium", "Performance degradation",
                               f"Measured degradation on {iface}: "
                               + ", ".join(x for x in (f"packet loss {loss:.1%}" if loss is not None and loss >= LOSS_DEGRADATION else "",
                                                        f"latency {latency_ratio:.1f}× median" if latency_ratio and latency_ratio >= LATENCY_FACTOR else "") if x) + ".",
                               "Check the link and the devices on the path."))
        for alert_type, severity, category, reason, action in candidates:
            evidence = {
                "source_name": source_name, "interface": iface, "base_time": base_time.isoformat(),
                "current_utilization": current_util, "growth_per_hour": growth,
                "forecasts": [{"horizon_minutes": f.horizon_seconds // 60, "predicted_utilization": f.predicted_utilization,
                               "risk": f.risk.level, "prediction_id": f.prediction_id} for f in forecasts],
                "thresholds": settings.thresholds(), "recommended_action": action, "note": NOT_AN_ATTACK,
                "packet_loss_ratio": loss, "latency_ratio_to_median": latency_ratio,
            }
            alert_id = alert_service.create_alert(
                conn, alert_type=alert_type, severity=severity, category=category,
                reason=f"{reason} {action}", evidence=evidence,
                dedup_key=f"congestion:{source_name}:{iface}:{category}", session_id=session_id,
                model_id=record.id, model_version=record.version, cooldown_minutes=settings.alert_cooldown_minutes,
                created_by=principal.user_id,
            )
            if alert_id is None:
                suppressed += 1
            else:
                created.append(alert_id)
        audit_service.record(conn, user_id=principal.user_id, action="forecast.run",
                             details={"session_id": session_id, "interface": interface_name, "model_id": record.id,
                                      "predictions": [f.prediction_id for f in forecasts], "alerts": created})

    return ForecastRun(model_id=record.id, model_version=record.version, base_time=base_time.isoformat(),
                       target=target, capacity_bps=capacity, forecasts=forecasts, alerts_created=created,
                       alerts_suppressed=suppressed, warnings=warnings)


def backtest(principal: Principal, record: ModelRecord, session_id: int, interface_name: Optional[str],
             horizon_seconds: int) -> pd.DataFrame:
    """Model output for every historical point: columns target_time, actual, predicted, period."""
    require_permission(principal, Permission.VIEW_DASHBOARD, action="forecast.backtest")
    bundle = model_registry_service.load_bundle(record)
    spec = bundle["horizons"].get(horizon_seconds)
    if spec is None:
        raise PredictionError("The model has no such horizon.")
    frame = load_session_frame(session_id, interface_name)
    series = resample(frame, bundle["target"], bundle["interval_seconds"])
    features = build_features(series).dropna()
    if features.empty:
        return pd.DataFrame(columns=["target_time", "actual", "predicted", "period"])
    predicted = clip_predictions(spec["model"].predict(features), bundle["target"])
    target_times = features.index + pd.Timedelta(seconds=int(horizon_seconds))
    actual = series.reindex(target_times).to_numpy()
    out = pd.DataFrame({"target_time": target_times, "actual": actual, "predicted": predicted})
    out["period"] = "not used in training"
    if record.training_metadata.get("session_id") == session_id:
        periods = record.training_metadata.get("split_periods", {}).get(f"{horizon_seconds // 60} min")
        if periods:
            base = features.index
            for name in ("train", "validation", "test"):
                start, end = (pd.Timestamp(t) for t in periods[name])
                out.loc[(base >= start) & (base <= end), "period"] = name
    # Forecasts whose target time lies after the last measurement cannot be compared with anything yet.
    out.loc[out["target_time"] > series.index[-1], "period"] = "beyond available data"
    return out


def recent_predictions(principal: Principal, limit: int = 200) -> List[Dict[str, Any]]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="forecast.list")
    with database_service.session() as conn:
        rows = conn.execute(
            "SELECT * FROM congestion_predictions ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,)
        ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["metadata"] = json.loads(row["prediction_metadata_json"]) if row["prediction_metadata_json"] else {}
        out.append(item)
    return out


def congestion_outlook(forecasts: List[HorizonForecast], threshold: float, *,
                       capacity_bps: Optional[float] = None, target: str = "utilization_ratio") -> Dict[str, Any]:
    """Countdown for the forecast card (pure).

    * "likely":   the earliest horizon whose predicted utilization reaches the threshold.
    * "possible": no prediction reaches it, but a prediction's upper band (validation error, 90th percentile) does.
    * "clear":    neither reaches it within the forecast window.
    * "unavailable": no utilization can be judged (throughput target without a configured capacity).
    """
    def utilization(value: float) -> Optional[float]:
        if target == "utilization_ratio":
            return value
        return value / capacity_bps if capacity_bps else None

    ordered = sorted(forecasts, key=lambda f: f.horizon_seconds)
    if not ordered or all(utilization(f.predicted_value) is None for f in ordered):
        return {"status": "unavailable", "minutes": None,
                "text": "Congestion outlook unavailable: no configured capacity to turn throughput into utilization."}
    window = ordered[-1].horizon_seconds // 60
    for f in ordered:
        if (utilization(f.predicted_value) or 0) >= threshold:
            return {"status": "likely", "minutes": f.horizon_seconds // 60,
                    "text": f"Congestion likely in ~{f.horizon_seconds // 60} min"}
    for f in ordered:
        if (utilization(f.upper) or 0) >= threshold:
            return {"status": "possible", "minutes": f.horizon_seconds // 60,
                    "text": f"Congestion possible in ~{f.horizon_seconds // 60} min (upper error band)"}
    return {"status": "clear", "minutes": None, "text": f"No congestion expected in the next {window} min"}
