"""From PredictNet's forecast to what should change before the link fills.

Forecasts come only from the active, hash-verified forecaster, through generate_forecast. With no forecaster, not enough
history or no configured capacity, this says unavailable and produces nothing.

A recommendation opens when a forecast reaches the preventive threshold:
  likely    the predicted utilization reaches it.
  possible  only the prediction plus its typical (90th percentile) validation error reaches it.

The projected allocation scales each host's stored demand so the total meets the forecast. That assumes every host grows in
proportion, which the page says. Without per-host data, the recommendation is at link level only.

A forecaster counts as validated for a horizon only if machine learning was chosen over the baselines on validation data
and it did not lose to the best baseline on the held-out test data. A baseline can still be shown, but predicting "the same
as now" is no reason to change anything by itself.

Automatic change needs ALL of: the Auto rate-limit policy, the separate preventive switch (off by default), adaptive allocation
on, a validated horizon, a "likely" forecast in two runs in a row, no recent refusal, and a simulated link. It only ever
prioritizes: reversible, expiring per-sender caps. It never blocks anyone, and on a real link it stops at a recommendation,
because prioritizing is not available there. Predicted congestion is not evidence of an attack and is never labelled one.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence

from repositories import preventive_repository as repo
from services import (
    audit_service, congestion_prediction_service, database_service, mitigation_service, model_registry_service, settings_service,
)
from services.authorization import Permission, Principal, require_permission
from services.congestion_prediction_service import ForecastRun, HorizonForecast, PredictionError
from services.settings_service import MitigationSettings
from services.timeutil import parse_iso, to_iso, utc_now

WANTED_MINUTES = (5, 10)
BASELINES = ("last_value", "moving_average")
DISMISS_COOLDOWN_SECONDS = 900
MIN_CONSECUTIVE = 2


class PreventiveError(Exception):
    pass


@dataclass
class HorizonStatus:
    minutes: int
    available: bool
    chosen: Optional[str] = None
    validated: bool = False
    test_mae: Optional[float] = None
    baseline_test_mae: Optional[float] = None
    why: str = ""


@dataclass
class ModelStatus:
    available: bool
    reason: str
    model_id: Optional[int] = None
    version: Optional[str] = None
    target: Optional[str] = None
    interval_seconds: Optional[int] = None
    horizons: List[HorizonStatus] = field(default_factory=list)


@dataclass
class Outlook:
    available: bool
    reason: str = ""
    run: Optional[ForecastRun] = None
    forecasts: List[HorizonForecast] = field(default_factory=list)
    status: str = "unavailable"  # likely, possible, clear or unavailable
    recommendation_id: Optional[int] = None


# ------------------------------------------------------------------ pure

def validation_verdict(entry: Optional[Mapping[str, Any]]) -> tuple:
    """(validated, why, test MAE, best baseline's test MAE) from a horizon's training report."""
    if not entry:
        return False, "This model has no such horizon.", None, None
    chosen = entry["chosen"]
    candidates = entry["candidates"]
    test = candidates[chosen]["test"]["mae"]
    baseline = min(candidates[name]["test"]["mae"] for name in BASELINES)
    if chosen in BASELINES:
        return False, f"Machine learning did not beat the baselines, so this horizon uses {chosen.replace('_', ' ')}.", test, baseline
    if test > baseline:
        return False, "It beat the baselines on validation data but not on the held-out test data.", test, baseline
    return True, "Beat the baselines on validation data and did not lose to them on held-out test data.", test, baseline


def judge(forecasts: Sequence[HorizonForecast], threshold: float) -> tuple:
    """(status, forecast): the earliest horizon predicted to reach the threshold, else the earliest whose upper band does."""
    known = [f for f in sorted(forecasts, key=lambda f: f.horizon_seconds) if f.predicted_utilization is not None]
    if not known:
        return "unavailable", None
    for f in known:
        if f.predicted_utilization >= threshold:
            return "likely", f
    for f in known:
        if f.risk.upper_bound is not None and f.risk.upper_bound >= threshold:
            return "possible", f
    return "clear", None


def automatic_blockers(settings: MitigationSettings, *, origin: str, validated: bool, strength: str, consecutive: int,
                       refused_recently: bool) -> List[str]:
    blockers = []
    if settings.policy != "auto_rate_limit":
        blockers.append("the mitigation policy is not Auto rate-limit")
    if not settings.preventive_auto:
        blockers.append("automatic preventive changes are switched off")
    if not settings.adaptive_enabled:
        blockers.append("adaptive allocation is off")
    if not validated:
        blockers.append("the forecaster is not validated for this horizon")
    if strength != "likely":
        blockers.append("only the error band reaches the threshold")
    if consecutive < MIN_CONSECUTIVE:
        blockers.append(f"seen in {consecutive} forecast(s), needs {MIN_CONSECUTIVE}")
    if refused_recently:
        blockers.append("an administrator recently refused this")
    if origin != "simulation":
        blockers.append("prioritizing is not available on this source, so it stays a recommendation")
    return blockers


def recommended_actions(origin: str, running: bool, projected: Optional[Mapping[str, Any]], top_senders: Sequence[str]) -> List[str]:
    actions: List[str] = []
    if projected:
        short = projected["classes"]["critical"]["unmet_bps"]
        if short > 0:
            actions.append(f"Critical traffic would be short by {short / 1e6:,.1f} Mbit/s. Protect it first.")
    if origin == "simulation" and running:
        actions.append("Prioritize critical traffic before the link fills.")
    elif origin == "real" and running:
        actions.append("Apply a class policy in Enforcement, so critical traffic keeps its share.")
    else:
        actions.append("This source is not a running link, so nothing can be applied to it. Use this to plan a class policy.")
    if top_senders:
        actions.append(f"Check whether the largest senders can wait: {', '.join(top_senders)}. High demand is not evidence of an attack.")
    if not projected:
        actions.append("There is no per-host data for this source, so this is at link level only.")
    return actions


# ------------------------------------------------------------------ reading

def model_status(principal: Principal) -> ModelStatus:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="preventive.view")
    record = model_registry_service.active_model(principal, "congestion_forecaster")
    if record is None:
        return ModelStatus(False, "Forecasts are unavailable: there is no active PredictNet forecaster. Train one in the ML "
                                  "Laboratory and activate it. No prediction is shown without one.")
    per_horizon = record.metrics.get("per_horizon", {})
    by_minutes = {int(e["horizon_seconds"]) // 60: e for e in per_horizon.values()}
    horizons = []
    for minutes in sorted({*WANTED_MINUTES, *by_minutes}):
        entry = by_minutes.get(minutes)
        validated, why, test, baseline = validation_verdict(entry)
        if entry is None:
            why = "This model was not trained for this horizon. Retrain with it selected."
        horizons.append(HorizonStatus(minutes, entry is not None, entry["chosen"] if entry else None, validated, test, baseline, why))
    meta = record.training_metadata
    return ModelStatus(True, "", record.id, record.version, meta.get("target"), meta.get("interval_seconds"), horizons)


def _public(row: Mapping[str, Any]) -> Dict[str, Any]:
    item = dict(row)
    for key in ("current_allocation_json", "projected_allocation_json", "actions_json"):
        item[key[:-5]] = json.loads(item.pop(key)) if item.get(key) else None
    return item


def list_recent(principal: Principal, limit: int = 30) -> List[Dict[str, Any]]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="preventive.view")
    with database_service.session() as conn:
        return [_public(r) for r in repo.recent(conn, limit)]


def links_approaching(principal: Principal, threshold: Optional[float] = None) -> List[Dict[str, Any]]:
    """The newest forecast of each link, worst horizon first. A link with no capacity has no utilization and says so."""
    limit = threshold if threshold is not None else settings_service.get_mitigation_settings().preventive_threshold
    newest: Dict[tuple, Dict[str, Any]] = {}
    for row in congestion_prediction_service.recent_predictions(principal, 500):
        key = (row["source_name"], row["interface_name"])
        kept = newest.get(key)
        if kept is None:
            newest[key] = {"source_name": row["source_name"], "interface": row["interface_name"], "base_time": row["timestamp"],
                           "model_version": row["model_version"], "rows": [row]}
        elif kept["base_time"] == row["timestamp"]:
            kept["rows"].append(row)
    links = []
    for link in newest.values():
        known = [r for r in link["rows"] if r["predicted_utilization_ratio"] is not None]
        worst = max(known, key=lambda r: r["predicted_utilization_ratio"]) if known else None
        links.append({**{k: v for k, v in link.items() if k != "rows"},
                      "predicted_utilization": worst["predicted_utilization_ratio"] if worst else None,
                      "horizon_minutes": worst["forecast_horizon_seconds"] // 60 if worst else None,
                      "risk": worst["congestion_risk"] if worst else "unknown",
                      "approaching": bool(worst and worst["predicted_utilization_ratio"] >= limit)})
    return sorted(links, key=lambda l: (not l["approaching"], -(l["predicted_utilization"] or -1), l["source_name"]))


# ------------------------------------------------------------------ forecasting and recommending

def _session(conn, session_id: int) -> Mapping[str, Any]:
    row = conn.execute("SELECT id, source_type, status FROM monitoring_sessions WHERE id = ?", (session_id,)).fetchone()
    if row is None:
        raise PreventiveError("That monitoring session no longer exists.")
    return row


def _origin(source_type: str) -> str:
    return "simulation" if source_type == "simulation" else "replay" if source_type == "replay" else "real"


def run(principal: Principal, session_id: int, interface: Optional[str], now: Optional[datetime] = None) -> Outlook:
    """Forecast now, and act on the result. Says why if a forecast is not possible."""
    try:
        forecast = congestion_prediction_service.generate_forecast(principal, session_id, interface)
    except PredictionError as exc:
        return Outlook(False, str(exc))
    return evaluate(principal, session_id, interface, forecast, now)


def evaluate(principal: Principal, session_id: int, interface: Optional[str], forecast: ForecastRun,
             now: Optional[datetime] = None) -> Outlook:
    moment = now or utc_now()
    settings = settings_service.get_mitigation_settings()
    wanted = [f for f in forecast.forecasts if f.horizon_seconds // 60 in WANTED_MINUTES] or forecast.forecasts
    status, trigger = judge(wanted, settings.preventive_threshold)
    expire_overdue(session_id, forecast.base_time)
    if status == "unavailable":
        return Outlook(False, "Utilization is unavailable: this source has no configured capacity, so a forecast cannot be "
                              "compared with a threshold.", forecast, wanted)
    with database_service.session() as conn:
        session = dict(_session(conn, session_id))
        existing = repo.open_for(conn, session_id, interface)
    if trigger is None:
        if existing is not None:
            _close(existing["id"], "expired", "The newer forecast no longer reaches the threshold.", None, moment)
        return Outlook(True, "", forecast, wanted, status)
    recommendation_id = _record(principal, session, interface, forecast, trigger, status, settings, existing, moment)
    return Outlook(True, "", forecast, wanted, status, recommendation_id)


def _refused_recently(conn, session_id: int, interface: Optional[str], moment: datetime) -> bool:
    last = repo.last_decided(conn, session_id, interface)
    if last is None or last["status"] != "dismissed":
        return False
    return (moment - parse_iso(last["decided_at"])).total_seconds() < DISMISS_COOLDOWN_SECONDS


def _record(principal: Principal, session: Mapping[str, Any], interface: Optional[str], forecast: ForecastRun,
            trigger: HorizonForecast, strength: str, settings: MitigationSettings, existing, moment: datetime) -> Optional[int]:
    session_id = session["id"]
    origin = _origin(session["source_type"])
    running = session["status"] == "RUNNING"
    with database_service.session() as conn:
        if existing is None and _refused_recently(conn, session_id, interface, moment):
            return None
    verdict = next((h for h in model_status(principal).horizons if h.minutes * 60 == trigger.horizon_seconds), None)
    validated = bool(verdict and verdict.validated)
    predicted_bps = trigger.predicted_throughput_bps
    if predicted_bps is None and forecast.capacity_bps:
        predicted_bps = trigger.predicted_utilization * forecast.capacity_bps
    current, projected, senders = mitigation_service.project_demand(session_id, predicted_bps)
    consecutive = existing["consecutive"] + 1 if existing is not None and existing["base_time"] != forecast.base_time else (
        existing["consecutive"] if existing is not None else 1)
    with database_service.session() as conn:
        refused = _refused_recently(conn, session_id, interface, moment)
    blockers = automatic_blockers(settings, origin=origin, validated=validated, strength=strength, consecutive=consecutive,
                                  refused_recently=refused)
    values = {
        "base_time": forecast.base_time, "target_time": trigger.target_time, "horizon_seconds": trigger.horizon_seconds,
        "predicted_utilization": trigger.predicted_utilization, "upper_utilization": trigger.risk.upper_bound,
        "threshold": settings.preventive_threshold, "capacity_bps": forecast.capacity_bps, "strength": strength,
        "risk": trigger.risk.level, "model_id": forecast.model_id, "model_version": forecast.model_version,
        "prediction_id": trigger.prediction_id, "model_validated": int(validated), "consecutive": consecutive,
        "current_allocation_json": json.dumps(current, sort_keys=True) if current else None,
        "projected_allocation_json": json.dumps(projected, sort_keys=True) if projected else None,
        "actions_json": json.dumps(recommended_actions(origin, running, projected, senders)),
        "automatic_note": (f"Not applied automatically: {'; '.join(blockers)}."[:500] if blockers else None),
        "updated_at": to_iso(moment),
    }
    with database_service.session(write=True) as conn:
        if existing is not None:
            recommendation_id = existing["id"]
            repo.update(conn, recommendation_id, values)
        else:
            source = forecast_source(conn, trigger.prediction_id)
            recommendation_id = repo.insert(conn, {
                "session_id": session_id, "origin": origin, "source_name": source, "interface_name": interface,
                "status": "open", "created_at": to_iso(moment), **values})
            audit_service.record(conn, user_id=None, action="preventive.recommend",
                                 details={"recommendation_id": recommendation_id, "strength": strength, "model_id": forecast.model_id,
                                          "predicted_utilization": trigger.predicted_utilization})
    if not blockers and running:
        _apply_automatically(recommendation_id, session_id, trigger, moment)
    return recommendation_id


def forecast_source(conn, prediction_id: int) -> str:
    return conn.execute("SELECT source_name FROM congestion_predictions WHERE id = ?", (prediction_id,)).fetchone()["source_name"]


def _reason(trigger: HorizonForecast) -> str:
    return (f"PredictNet forecasts {trigger.predicted_utilization:.0%} utilization in {trigger.horizon_seconds // 60} min. "
            "This protects critical traffic; it says nothing about an attack.")


def _apply_automatically(recommendation_id: int, session_id: int, trigger: HorizonForecast, moment: datetime) -> None:
    result = mitigation_service.apply_preventive(session_id, _reason(trigger), moment)
    _close(recommendation_id, "applied", "Applied automatically under the Auto rate-limit policy.", None, moment,
           mitigation_id=result["id"])


def _close(recommendation_id: int, status: str, note: str, user_id: Optional[int], moment: datetime,
           mitigation_id: Optional[int] = None) -> None:
    with database_service.session(write=True) as conn:
        repo.update(conn, recommendation_id, {"status": status, "decided_at": to_iso(moment), "decided_by": user_id,
                                              "decision_note": note[:500], "updated_at": to_iso(moment), "mitigation_id": mitigation_id})
        audit_service.record(conn, user_id=user_id, action=f"preventive.{status}",
                             details={"recommendation_id": recommendation_id, "note": note[:200], "mitigation_id": mitigation_id})


def expire_overdue(session_id: int, moment: str) -> None:
    """A forecast whose time has passed recommends nothing any more. `moment` is in that session's own data time."""
    with database_service.session() as conn:
        rows = repo.overdue(conn, session_id, moment)
    for row in rows:
        _close(row["id"], "expired", "Its forecast time has passed.", None, parse_iso(moment))


def _validated_reason(reason: str) -> str:
    text = (reason or "").strip()
    if not 5 <= len(text) <= 500:
        raise PreventiveError("Give a reason of 5 to 500 characters.")
    return text


def _open(conn, recommendation_id: int) -> Dict[str, Any]:
    row = repo.get(conn, recommendation_id)
    if row is None:
        raise PreventiveError("Recommendation not found.")
    if row["status"] != "open":
        raise PreventiveError("This recommendation has already been decided.")
    return dict(row)


def apply(principal: Principal, recommendation_id: int, *, reason: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """An administrator's yes. Goes through the same audited, expiring, reversible path as any other prioritization."""
    require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="preventive.apply",
                       details={"recommendation_id": recommendation_id})
    text = _validated_reason(reason)
    moment = now or utc_now()
    with database_service.session() as conn:
        row = _open(conn, recommendation_id)
        session = dict(_session(conn, row["session_id"]))
    if row["origin"] != "simulation":
        raise PreventiveError("Prioritizing is only available on a simulated link. On a real link, apply a class policy in Enforcement.")
    if session["status"] != "RUNNING":
        raise PreventiveError("That session is not running any more, so there is nothing to act on.")
    result = mitigation_service.request_action(principal, row["session_id"], "prioritize", reason=text, now=moment)
    if result["status"] == "failed":
        raise PreventiveError(result["failure_reason"] or "It could not be applied.")
    _close(recommendation_id, "applied", text, principal.user_id, moment, mitigation_id=result["id"])
    return result


def dismiss(principal: Principal, recommendation_id: int, *, reason: str, now: Optional[datetime] = None) -> None:
    require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="preventive.dismiss",
                       details={"recommendation_id": recommendation_id})
    text = _validated_reason(reason)
    moment = now or utc_now()
    with database_service.session() as conn:
        _open(conn, recommendation_id)
    _close(recommendation_id, "dismissed", text, principal.user_id, moment)

