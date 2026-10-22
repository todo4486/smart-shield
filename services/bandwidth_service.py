"""Bandwidth policies and recommendations (recommendation mode, no privileges needed).

* A policy is a named set of traffic classes for one link with a configured
  capacity. Policies are configuration: admins edit them, and changes are audited.
* A recommendation runs the water-filling engine on a policy plus a demand
  estimate. Demand provenance is explicit:
    - "configured":  per-class demand typed in by the user (an estimate).
    - "derived from measurement": the class proportions scaled to the latest
      measured throughput of a telemetry session.
    - "derived from forecast": the class proportions scaled to the latest
      stored PredictNet forecast.
  Per-class demand is never presented as measured. That needs per-class
  telemetry, which does not exist yet.
* Recommending does not change any real bandwidth. Enforcement is the separate,
  opt-in traffic_shaping_service.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from repositories import bandwidth_repository, telemetry_repository
from services import audit_service, database_service
from services.authorization import Permission, Principal, require_permission
from services.bandwidth_allocation import AllocationError, AllocationResult, TrafficClass, allocate
from services.timeutil import utc_now_iso

POLICY_NAME_RE = re.compile(r"^[A-Za-z0-9 _.\-]{1,60}$")
DEMAND_MODES = {
    "manual": "configured",
    "measured": "derived from measurement",
    "forecast": "derived from forecast",
}
RECOMMENDATION_TRANSITIONS = {"proposed": {"accepted", "rejected"}, "accepted": {"applied", "superseded", "rejected"},
                              "applied": {"superseded"}, "rejected": set(), "superseded": set()}

# A starting template, clearly labelled as such. Values are fractions of capacity.
TEMPLATE_CLASSES = [
    {"traffic_class": "critical", "min_share": 0.10, "max_share": 0.50, "priority_weight": 8, "dscp": 46},
    {"traffic_class": "interactive", "min_share": 0.10, "max_share": 0.60, "priority_weight": 4, "dscp": 34},
    {"traffic_class": "standard", "min_share": 0.05, "max_share": 0.90, "priority_weight": 2, "dscp": 0},
    {"traffic_class": "background", "min_share": 0.00, "max_share": 0.70, "priority_weight": 1, "dscp": 8},
]


class BandwidthError(Exception):
    pass


@dataclass(frozen=True)
class PolicyClass:
    traffic_class: str
    minimum_bps: float
    maximum_bps: float
    priority_weight: float
    dscp: Optional[int] = None
    enabled: bool = True


@dataclass(frozen=True)
class Policy:
    name: str
    interface_name: Optional[str]
    capacity_bps: float
    classes: tuple


@dataclass
class Recommendation:
    id: Optional[int]
    policy_name: str
    interface_name: Optional[str]
    capacity_bps: float
    demand_mode: str
    demand_provenance: str
    demand_context: Dict[str, Any]
    congestion_context: Optional[Dict[str, Any]]
    result: AllocationResult
    expected_effect: List[str] = field(default_factory=list)


# ---------------------------------------------------------------- policies

def list_policies(principal: Principal) -> List[Policy]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="bandwidth.list_policies")
    with database_service.session() as conn:
        return [_policy_from_rows(name, bandwidth_repository.policy_rows(conn, name))
                for name in bandwidth_repository.policy_names(conn)]


def _policy_from_rows(name: str, rows) -> Policy:
    first = rows[0]
    classes = tuple(PolicyClass(r["traffic_class"], r["minimum_bps"], r["maximum_bps"], r["priority_weight"],
                                r["dscp"], bool(r["enabled"])) for r in rows)
    return Policy(name, first["interface_name"], first["configured_capacity_bps"], classes)


def save_policy(principal: Principal, policy: Policy) -> Policy:
    """Create or replace a policy. Validates feasibility with zero demand before saving."""
    require_permission(principal, Permission.MANAGE_SETTINGS, action="bandwidth.save_policy",
                       details={"policy": policy.name})
    name = (policy.name or "").strip()
    if not POLICY_NAME_RE.match(name):
        raise BandwidthError("Policy names use 1–60 letters, digits, spaces, '.', '_' or '-'.")
    interface = (policy.interface_name or "").strip() or None
    if interface and not re.match(r"^[A-Za-z0-9_.:\-]{1,64}$", interface):
        raise BandwidthError("Interface name contains unsupported characters.")
    enabled = [c for c in policy.classes if c.enabled]
    if not enabled:
        raise BandwidthError("Enable at least one traffic class.")
    for c in policy.classes:
        if c.dscp is not None and not 0 <= int(c.dscp) <= 63:
            raise BandwidthError(f"Class '{c.traffic_class}': DSCP must be between 0 and 63.")
    try:  # same validation the engine applies, including infeasible minimums
        allocate(policy.capacity_bps, 0.0, [TrafficClass(c.traffic_class.strip(), c.minimum_bps, c.maximum_bps,
                                                         c.priority_weight, 0.0) for c in enabled])
    except AllocationError as exc:
        raise BandwidthError(str(exc)) from exc
    now = utc_now_iso()
    with database_service.session(write=True) as conn:
        existed = bool(bandwidth_repository.policy_rows(conn, name))
        bandwidth_repository.delete_policy(conn, name)
        for c in policy.classes:
            bandwidth_repository.insert_policy_row(conn, {
                "policy_name": name, "interface_name": interface, "configured_capacity_bps": float(policy.capacity_bps),
                "traffic_class": c.traffic_class.strip(), "minimum_bps": float(c.minimum_bps),
                "maximum_bps": float(c.maximum_bps), "priority_weight": float(c.priority_weight),
                "enabled": 1 if c.enabled else 0, "dscp": None if c.dscp is None else int(c.dscp),
                "created_at": now, "updated_at": now,
            })
        audit_service.record(conn, user_id=principal.user_id, action="bandwidth.save_policy",
                             details={"policy": name, "replaced": existed, "capacity_bps": policy.capacity_bps,
                                      "classes": [c.traffic_class for c in policy.classes]})
    return Policy(name, interface, float(policy.capacity_bps), tuple(policy.classes))


def delete_policy(principal: Principal, name: str) -> None:
    require_permission(principal, Permission.MANAGE_SETTINGS, action="bandwidth.delete_policy", details={"policy": name})
    with database_service.session(write=True) as conn:
        if not bandwidth_repository.policy_rows(conn, name):
            raise BandwidthError("Policy not found.")
        bandwidth_repository.delete_policy(conn, name)
        audit_service.record(conn, user_id=principal.user_id, action="bandwidth.delete_policy", details={"policy": name})


def template_policy(capacity_bps: float, name: str = "TEMPLATE four-class policy",
                    interface: Optional[str] = None) -> Policy:
    """A labelled starting point. Shares are suggestions to edit, not standards."""
    return Policy(name, interface, capacity_bps, tuple(
        PolicyClass(t["traffic_class"], round(capacity_bps * t["min_share"]), round(capacity_bps * t["max_share"]),
                    t["priority_weight"], t["dscp"]) for t in TEMPLATE_CLASSES))


# ---------------------------------------------------------- demand sources

def latest_measured_throughput(session_id: int, interface: Optional[str]) -> Dict[str, Any]:
    with database_service.session() as conn:
        rows = telemetry_repository.metrics_for_session(conn, session_id, interface)
    for row in reversed(rows):
        if row["throughput_bps"] is not None:
            return {"throughput_bps": float(row["throughput_bps"]), "timestamp": row["timestamp"],
                    "provenance": row["throughput_provenance"] or row["provenance"], "session_id": session_id}
    raise BandwidthError("That session has no throughput values for this interface.")


def latest_forecast_throughput(interface: Optional[str], capacity_bps: float) -> Dict[str, Any]:
    with database_service.session() as conn:
        sql = "SELECT * FROM congestion_predictions"
        params: tuple = ()
        if interface:
            sql += " WHERE interface_name = ?"
            params = (interface,)
        row = conn.execute(sql + " ORDER BY timestamp DESC, forecast_horizon_seconds DESC, id DESC LIMIT 1",
                           params).fetchone()
    if row is None:
        raise BandwidthError("No stored PredictNet forecast for this interface. Generate one in the Congestion Center.")
    if row["predicted_throughput_bps"] is not None:
        value, basis = float(row["predicted_throughput_bps"]), "predicted throughput"
    elif row["predicted_utilization_ratio"] is not None:
        value, basis = float(row["predicted_utilization_ratio"]) * capacity_bps, "predicted utilization × policy capacity"
    else:
        raise BandwidthError("The latest forecast has neither throughput nor utilization.")
    return {"throughput_bps": value, "basis": basis, "prediction_id": row["id"], "timestamp": row["timestamp"],
            "horizon_seconds": row["forecast_horizon_seconds"], "model_version": row["model_version"],
            "congestion_risk": row["congestion_risk"]}


def _congestion_context(interface: Optional[str]) -> Optional[Dict[str, Any]]:
    with database_service.session() as conn:
        sql = "SELECT congestion_risk, timestamp, forecast_horizon_seconds, model_version FROM congestion_predictions"
        params: tuple = ()
        if interface:
            sql += " WHERE interface_name = ?"
            params = (interface,)
        row = conn.execute(sql + " ORDER BY timestamp DESC, id DESC LIMIT 1", params).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------- recommendations

def recommend(
    principal: Principal,
    policy_name: str,
    demand_bps: Dict[str, float],
    *,
    safety_margin: float = 0.10,
    demand_mode: str = "manual",
    session_id: Optional[int] = None,
    save: bool = True,
) -> Recommendation:
    """Compute (and by default store) a recommendation. Nothing is enforced."""
    require_permission(principal, Permission.GENERATE_RECOMMENDATIONS, action="bandwidth.recommend",
                       details={"policy": policy_name, "mode": demand_mode})
    if demand_mode not in DEMAND_MODES:
        raise BandwidthError("Unknown demand source.")
    with database_service.session() as conn:
        rows = bandwidth_repository.policy_rows(conn, policy_name)
    if not rows:
        raise BandwidthError("Policy not found.")
    policy = _policy_from_rows(policy_name, rows)
    classes = [c for c in policy.classes if c.enabled]
    entered = {c.traffic_class: float(demand_bps.get(c.traffic_class, 0.0)) for c in classes}
    if any(v < 0 for v in entered.values()):
        raise BandwidthError("Demand cannot be negative.")

    context: Dict[str, Any] = {"entered_bps": entered}
    if demand_mode == "manual":
        demand = entered
    else:
        total_entered = sum(entered.values())
        if total_entered <= 0:
            raise BandwidthError("Enter relative demand per class; it is used as the split of the total.")
        if demand_mode == "measured":
            if session_id is None:
                raise BandwidthError("Choose a telemetry session for measured throughput.")
            source = latest_measured_throughput(session_id, policy.interface_name)
        else:
            source = latest_forecast_throughput(policy.interface_name, policy.capacity_bps)
        context.update(source)
        context["note"] = ("The total comes from the source below. The split between classes comes from your "
                           "entries, because per-class demand is not measured.")
        demand = {name: source["throughput_bps"] * value / total_entered for name, value in entered.items()}

    try:
        result = allocate(policy.capacity_bps, safety_margin,
                          [TrafficClass(c.traffic_class, c.minimum_bps, c.maximum_bps, c.priority_weight,
                                        demand[c.traffic_class]) for c in classes])
    except AllocationError as exc:
        raise BandwidthError(str(exc)) from exc

    congestion = _congestion_context(policy.interface_name)
    effect = []
    for a in result.allocations:
        served = a.allocated_bps / a.demand_bps if a.demand_bps else 1.0
        effect.append(f"{a.name}: {min(served, 1):.0%} of estimated demand served"
                      + (f", {a.unmet_demand_bps / 1e6:,.2f} Mbit/s unmet" if a.unmet_demand_bps else ""))
    if congestion and congestion["congestion_risk"] in ("high", "critical"):
        if result.unmet_demand_bps:
            effect.append(f"PredictNet currently forecasts {congestion['congestion_risk']} congestion risk. "
                          "Higher-weight classes are protected first; lower-weight classes absorb the shortfall.")
        else:
            effect.append(f"PredictNet currently forecasts {congestion['congestion_risk']} congestion risk, but the "
                          "estimated demand still fits the usable capacity. The safety margin is the remaining headroom.")
    recommendation = Recommendation(
        id=None, policy_name=policy_name, interface_name=policy.interface_name, capacity_bps=policy.capacity_bps,
        demand_mode=demand_mode, demand_provenance=DEMAND_MODES[demand_mode], demand_context=context,
        congestion_context=congestion, result=result, expected_effect=effect,
    )
    if save:
        payload = {
            "policy_name": policy_name, "demand_mode": demand_mode, "demand_provenance": DEMAND_MODES[demand_mode],
            "demand_context": context, "congestion_context": congestion, "result": result.as_dict(),
            "expected_effect": effect,
            "dscp": {c.traffic_class: c.dscp for c in classes},
            "enforcement": "none: recommendation only",
        }
        with database_service.session(write=True) as conn:
            recommendation.id = bandwidth_repository.insert_recommendation(conn, {
                "timestamp": utc_now_iso(), "source_name": f"policy:{policy_name}",
                "interface_name": policy.interface_name, "capacity_bps": policy.capacity_bps,
                "recommendation_json": json.dumps(payload, default=str), "unmet_demand_bps": result.unmet_demand_bps,
                "rationale": " ".join(result.rationale), "status": "proposed", "created_by": principal.user_id,
            })
            audit_service.record(conn, user_id=principal.user_id, action="bandwidth.recommend",
                                 details={"recommendation_id": recommendation.id, "policy": policy_name,
                                          "unmet_demand_bps": result.unmet_demand_bps})
    return recommendation


def list_recommendations(principal: Principal, limit: int = 200) -> List[Dict[str, Any]]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="bandwidth.list_recommendations")
    with database_service.session() as conn:
        rows = bandwidth_repository.list_recommendations(conn, limit)
    out = []
    for r in rows:
        item = dict(r)
        item["payload"] = json.loads(r["recommendation_json"])
        out.append(item)
    return out


def set_recommendation_status(principal: Principal, recommendation_id: int, status: str) -> None:
    """Admins accept or reject proposals. Accepting does not enforce anything."""
    require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="bandwidth.review_recommendation",
                       details={"recommendation_id": recommendation_id, "status": status})
    with database_service.session(write=True) as conn:
        row = bandwidth_repository.get_recommendation(conn, recommendation_id)
        if row is None:
            raise BandwidthError("Recommendation not found.")
        if status not in RECOMMENDATION_TRANSITIONS.get(row["status"], set()):
            raise BandwidthError(f"A {row['status']} recommendation cannot become {status}.")
        bandwidth_repository.set_recommendation_status(conn, recommendation_id, status)
        audit_service.record(conn, user_id=principal.user_id, action="bandwidth.review_recommendation",
                             details={"recommendation_id": recommendation_id, "from": row["status"], "to": status})


def policy_from_entries(name: str, interface: Optional[str], capacity_bps: float,
                        entries: Sequence[Dict[str, Any]]) -> Policy:
    """Build a Policy from editor rows (values in Mbit/s), skipping blank rows."""
    classes = []
    for e in entries:
        label = str(e.get("traffic_class") or "").strip()
        if not label:
            continue
        try:
            dscp = e.get("dscp")
            dscp = None if dscp in (None, "") or (isinstance(dscp, float) and dscp != dscp) else int(dscp)
            classes.append(PolicyClass(label, float(e.get("minimum_mbps") or 0) * 1e6,
                                       float(e.get("maximum_mbps") or 0) * 1e6, float(e.get("priority_weight") or 0),
                                       dscp, bool(e.get("enabled", True))))
        except (TypeError, ValueError) as exc:
            raise BandwidthError(f"Class '{label}': {exc}") from exc
    return Policy(name, interface, capacity_bps, tuple(classes))
