"""The mitigation engine: from model verdicts to decisions, enforcement, expiry, rollback and recovery checks.

Policy levels (settings: mitigation.settings)
* Off: the engine proposes and applies nothing.
* Recommend (default): the engine proposes; an administrator approves or rejects each one.
* Auto rate-limit: the engine may apply a rate limit by itself, only when confidence, severity, repetition and
  false-positive risk all meet their thresholds. It always expires and can be rolled back.

Blocking and isolation are never automatic, at any level: the engine can only propose them, and approving one needs an
administrator, a reason, an expiry, and the target typed out. On a real link, isolation also needs a lab interface.

A congested link never starts anything here. Only flows flagged by the registered models do.

Enforcement goes through an Enforcer chosen by origin. Simulation has its own: the simulated link reads the active
mitigations each interval, so the effect is calculated by the link model and shown as simulated. Real networks use
enforcement_service: `tc`, `pf` + `dnctl`, or a dry run that changes nothing and is labelled so everywhere.

The engine has no user: its actions are audited with no user id and `initiated_by = engine`.
"""
from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence, Set

from config import get_settings
from repositories import incident_repository, mitigation_repository as repo
from services import (
    audit_service, database_service, enforcement_service, host_allocation, incident_correlation_service, live_network_service,
    mitigation_scoring, settings_service, traffic_shaping_service,
)
from services.authorization import Permission, Principal, require_permission
from services.bandwidth_allocation import AllocationError
from services.enforcement_adapters import EnforcementError
from services.enforcement_service import DRY_RUN, RealEnforcer
from services.host_allocation import AllocationPolicy, HostAllocation, HostDemand
from services.mitigation_scoring import Assessment, FlaggedFlow, Thresholds
from services.settings_service import MitigationSettings
from services.traffic_shaping_service import ShapingError
from services.timeutil import parse_iso, to_iso, utc_now

ACTION_TYPES = ("rate_limit", "prioritize", "block", "isolate")
HIGH_IMPACT = ("block", "isolate")
ASSESS_WINDOW_SECONDS = 60
SUSPICIOUS_WINDOW_SECONDS = 60
BEFORE_WINDOW_SECONDS = 3  # short, so a quick decision does not average in the time before the attack
VERIFY_AFTER_SECONDS = 10
SETTLE_SECONDS = 2  # the first moments after an action are left out of the 'after' figures
REFUSAL_COOLDOWN_SECONDS = 300  # an administrator's no is not asked again straight away
PROPOSAL_TTL_SECONDS = 900
MIN_LIMIT_BPS = 8_000
MAX_LIMIT_BPS = 400e9


class MitigationError(Exception):
    pass


class Enforcer(Protocol):
    name: str

    def apply(self, mitigation: Mapping[str, Any]) -> Optional[List[Dict[str, Any]]]: ...  # the commands, if any

    def remove(self, mitigation: Mapping[str, Any]) -> None: ...


class SimulatedEnforcer:
    """Nothing to run: the simulation reads the active mitigations from the database each interval."""
    name = "simulated-link"

    def apply(self, mitigation: Mapping[str, Any]) -> None:
        pass

    def remove(self, mitigation: Mapping[str, Any]) -> None:
        pass


_enforcers: Dict[str, Enforcer] = {"simulation": SimulatedEnforcer(), "real": RealEnforcer()}


def set_enforcer_for_tests(origin: str, enforcer: Optional[Enforcer]) -> None:
    _enforcers[origin] = enforcer or (SimulatedEnforcer() if origin == "simulation" else RealEnforcer())


# ------------------------------------------------------------------ what a link should do this interval

@dataclass(frozen=True)
class LinkPolicy:
    """The active mitigations of one session, in the form a link model or an adapter needs."""
    source_limits: Mapping[str, float] = field(default_factory=dict)
    destination_limits: Mapping[str, float] = field(default_factory=dict)
    blocked: frozenset = frozenset()
    isolated: frozenset = frozenset()
    sender_caps: Mapping[str, float] = field(default_factory=dict)  # allocator grants, only while prioritizing

    @property
    def enforcing(self) -> bool:
        return bool(self.source_limits or self.destination_limits or self.blocked or self.isolated or self.sender_caps)


@dataclass(frozen=True)
class SenderDemand:
    host: str
    receiver: str
    declared_class: str  # "critical" or "normal": what the traffic is, before any verdict
    demand_bps: float


@dataclass
class IntervalPlan:
    policy: LinkPolicy
    allocation: HostAllocation


def _allocation_policy(settings: MitigationSettings) -> AllocationPolicy:
    return AllocationPolicy(settings.safety_margin, settings.critical_min_share, settings.normal_min_share,
                            settings.suspicious_max_share, settings.critical_max_share, settings.normal_max_share,
                            settings.critical_weight, settings.normal_weight)


def critical_ports(settings: MitigationSettings) -> Set[int]:
    """Destination ports of the services an administrator marked critical."""
    return {port for port, name in live_network_service.SERVICE_PORTS.items() if name in settings.critical_services}


def _thresholds(settings: MitigationSettings) -> Thresholds:
    return Thresholds(settings.min_confidence, settings.min_severity, settings.min_repetition,
                      settings.max_false_positive_risk)


def _policy_from(active: Sequence[Mapping[str, Any]]) -> LinkPolicy:
    source_limits: Dict[str, float] = {}
    destination_limits: Dict[str, float] = {}
    blocked: Set[str] = set()
    isolated: Set[str] = set()
    for m in active:
        if m["adapter"] == DRY_RUN:  # a dry run changed nothing, so it must not look like a limit
            continue
        if m["action_type"] == "rate_limit":
            (source_limits if m["target_kind"] == "source" else destination_limits)[m["target"]] = float(m["limit_bps"])
        elif m["action_type"] == "block":
            blocked.add(m["target"])
        elif m["action_type"] == "isolate":
            isolated.add(m["target"])
    return LinkPolicy(source_limits, destination_limits, frozenset(blocked), frozenset(isolated))


def classify_demands(demands: Sequence[SenderDemand], policy: LinkPolicy, flagged: Set[str]) -> List[HostDemand]:
    """Restricted if a mitigation acts on the host, else suspicious if the models flagged it, else what it declares."""
    to_destination: Dict[str, float] = {}
    for d in demands:
        to_destination[d.receiver] = to_destination.get(d.receiver, 0.0) + d.demand_bps
    merged: Dict[str, Dict[str, Any]] = {}
    for d in demands:
        limit: Optional[float] = None
        if d.host in policy.blocked or d.host in policy.isolated or d.receiver in policy.isolated:
            limit = 0.0
        elif d.host in policy.source_limits:
            limit = policy.source_limits[d.host]
        elif d.receiver in policy.destination_limits and to_destination[d.receiver] > 0:
            limit = policy.destination_limits[d.receiver] * d.demand_bps / to_destination[d.receiver]
        entry = merged.setdefault(d.host, {"demand": 0.0, "limit": None, "critical": False})
        entry["demand"] += d.demand_bps
        entry["critical"] = entry["critical"] or d.declared_class == host_allocation.CRITICAL
        if limit is not None:
            entry["limit"] = limit if entry["limit"] is None else entry["limit"] + limit
    result = []
    for host, entry in merged.items():
        if entry["limit"] is not None:
            name = host_allocation.RESTRICTED
        elif host in flagged:
            name = host_allocation.SUSPICIOUS
        else:
            name = host_allocation.CRITICAL if entry["critical"] else host_allocation.NORMAL
        result.append(HostDemand(host, name, entry["demand"], entry["limit"]))
    return result


def _flagged_sources(conn, session_id: int, now: datetime) -> Set[str]:
    since = to_iso(now - timedelta(seconds=SUSPICIOUS_WINDOW_SECONDS))
    return {r["src_ip"] for r in repo.flagged_flows_since(conn, session_id, since)}


def plan_interval(session_id: int, capacity_bps: float, demands: Sequence[SenderDemand], now: datetime) -> IntervalPlan:
    """Called by a running engine before each interval: ends what is due, then works out limits and the allocation."""
    settings = settings_service.get_mitigation_settings()
    expire_due(now)
    with database_service.session() as conn:
        active = [dict(r) for r in repo.of_session(conn, session_id, ("active",))]
        flagged = _flagged_sources(conn, session_id, now)
    policy = _policy_from(active)
    allocation = host_allocation.allocate_hosts(capacity_bps, _allocation_policy(settings),
                                                classify_demands(demands, policy, flagged))
    if settings.adaptive_enabled and any(m["action_type"] == "prioritize" and m["adapter"] != DRY_RUN for m in active):
        policy = LinkPolicy(policy.source_limits, policy.destination_limits, policy.blocked, policy.isolated,
                            {h.host: float(h.allocated_bps) for h in allocation.hosts.values()})
    return IntervalPlan(policy, allocation)


def _allocation_summary(allocation: HostAllocation) -> Dict[str, Any]:
    return {"capacity_bps": allocation.capacity_bps, "available_bps": allocation.available_bps,
            "total_allocated_bps": allocation.total_allocated_bps,
            "classes": {name: asdict(grant) for name, grant in allocation.classes.items()}}


def record_interval(session_id: int, plan: IntervalPlan, hosts: Sequence[Mapping[str, Any]],
                    critical_hosts: Set[str], now: datetime) -> None:
    """Called after an interval's samples are stored: keep the allocation, check earlier actions, assess new threats."""
    if settings_service.get_mitigation_settings().adaptive_enabled:
        summary = _allocation_summary(plan.allocation)
        with database_service.session(write=True) as conn:
            repo.insert_allocation(
                conn, session_id=session_id, timestamp=to_iso(now), capacity_bps=plan.allocation.capacity_bps,
                enforced=plan.policy.enforcing, classes_json=json.dumps(summary, sort_keys=True),
                hosts_json=json.dumps([asdict(h) for h in plan.allocation.hosts.values()], sort_keys=True))
    _after_interval(session_id, plan.allocation.capacity_bps, hosts, critical_hosts, now)


def _after_interval(session_id: int, capacity_bps: Optional[float], hosts: Sequence[Mapping[str, Any]],
                    critical_hosts: Set[str], now: datetime) -> None:
    _verify_due(session_id, now)
    _evaluate(session_id, capacity_bps, hosts, critical_hosts, now)
    _link_incidents(session_id, now)


def run_live_interval(session_id: int, capacity_bps: Optional[float], hosts: Sequence[Mapping[str, Any]], now: datetime) -> None:
    """One interval of a live capture. Without a configured capacity there is no allocation, and nothing is invented:
    threats are still assessed, and a limit is proposed from the host's measured rate alone."""
    settings = settings_service.get_mitigation_settings()
    since = to_iso(now - timedelta(seconds=ASSESS_WINDOW_SECONDS))
    with database_service.session() as conn:
        receivers = repo.top_receivers_since(conn, session_id, since)
        ports = repo.destination_ports_since(conn, session_id, since) if settings.critical_services else {}
    critical = set(settings.critical_hosts) | {host for host, seen in ports.items()
                                               if live_network_service.traffic_class(seen) in settings.critical_services}
    if not capacity_bps:
        expire_due(now)
        _after_interval(session_id, None, hosts, critical, now)
        return
    demands = [SenderDemand(h["host"], receivers.get(h["host"], ""),
                            host_allocation.CRITICAL if h["host"] in critical else host_allocation.NORMAL, float(h["sent_bps"]))
               for h in hosts]
    record_interval(session_id, plan_interval(session_id, capacity_bps, demands, now), hosts, critical, now)


# ------------------------------------------------------------------ the engine's decisions

def _flagged_flows(rows: Sequence[Mapping[str, Any]]) -> List[FlaggedFlow]:
    flows = []
    for r in rows:
        moment = parse_iso(r["timestamp"])
        flows.append(FlaggedFlow(r["src_ip"], r["dst_ip"], r["intrusion_prediction"],
                                 None if r["score"] is None else float(r["score"]), moment.timestamp()))
    return flows


def _proposed_limit(assessment: Assessment, capacity_bps: Optional[float], settings: MitigationSettings) -> Optional[float]:
    """The configured share of the link, or half the current rate if that is lower, since a limit above it does nothing.
    None when neither is known: there is nothing to base a limit on."""
    options = []
    if capacity_bps:
        options.append(capacity_bps * settings.rate_limit_share)
    if assessment.traffic_bps:
        options.append(assessment.traffic_bps / 2)
    return max(MIN_LIMIT_BPS, min(options)) if options else None


def _reason_for(a: Assessment) -> str:
    who = f"{a.distinct_sources} sources towards {a.target}" if a.target_kind == "destination" else a.target
    return (f"{a.flagged_flows} flow(s) from {who} flagged as '{a.category}' in {a.repetition} window(s).")[:500]


def _evaluate(session_id: int, capacity_bps: Optional[float], hosts: Sequence[Mapping[str, Any]], critical_hosts: Set[str],
              now: datetime) -> None:
    settings = settings_service.get_mitigation_settings()
    if settings.policy == "off":
        return
    since = to_iso(now - timedelta(seconds=ASSESS_WINDOW_SECONDS))
    with database_service.session() as conn:
        flagged = [dict(r) for r in repo.flagged_flows_since(conn, session_id, since)]
        if not flagged:
            return
        totals = repo.flow_totals_since(conn, session_id, since)
        origin = _session_origin(conn, session_id)
    sent = {h["host"]: float(h["sent_bps"]) for h in hosts}
    received = {h["host"]: float(h["received_bps"]) for h in hosts}
    assessments = mitigation_scoring.assess_targets(_flagged_flows(flagged), totals, sent, received,
                                                    capacity_bps, critical_hosts, _thresholds(settings))
    for assessment in assessments:
        if assessment.target in settings.protected_hosts:
            continue
        if assessment.recommended_action == "rate_limit" and _proposed_limit(assessment, capacity_bps, settings) is None:
            continue
        with database_service.session(write=True) as conn:
            existing = repo.open_for_target(conn, session_id, assessment.target_kind, assessment.target)
            if existing:
                # Evidence builds up: keep an unanswered proposal current, so it can qualify for Auto later.
                waiting = next((r for r in existing if r["status"] == "proposed" and r["initiated_by"] == "engine"
                                and r["action_type"] == assessment.recommended_action), None)
                if waiting is None or any(r["status"] == "active" for r in existing):
                    continue
                mitigation_id = waiting["id"]
                repo.update(conn, mitigation_id, _evidence_values(assessment))
            else:
                refused = repo.last_refused(conn, session_id, assessment.target_kind, assessment.target)
                if refused is not None and _within_cooldown(refused, now):
                    continue
                mitigation_id = _insert_proposal(conn, session_id, origin, assessment, capacity_bps, settings, now)
        if settings.policy == "auto_rate_limit" and assessment.auto_eligible:
            _apply_automatically(mitigation_id, now)


def _within_cooldown(row: Mapping[str, Any], now: datetime) -> bool:
    moment = parse_iso(row["ended_at"] or row["decided_at"])
    return moment is not None and (now - moment).total_seconds() < REFUSAL_COOLDOWN_SECONDS


def _evidence_values(a: Assessment) -> Dict[str, Any]:
    return {"reason": _reason_for(a), "severity": a.severity, "confidence": a.confidence,
            "confidence_basis": a.confidence_basis, "false_positive_risk": a.false_positive_risk,
            "repetition": a.repetition, "flagged_flows": a.flagged_flows, "traffic_bps": a.traffic_bps,
            "assessment_json": json.dumps(a.as_dict(), sort_keys=True), "upstream_required": int(a.upstream_required)}


def _insert_proposal(conn, session_id: int, origin: str, a: Assessment, capacity_bps: Optional[float], settings: MitigationSettings,
                     now: datetime) -> int:
    action = a.recommended_action
    mitigation_id = repo.insert(conn, {
        "origin": origin, "session_id": session_id, "action_type": action, "target_kind": a.target_kind, "target": a.target,
        "status": "proposed", "initiated_by": "engine",
        "limit_bps": _proposed_limit(a, capacity_bps, settings) if action == "rate_limit" else None,
        "duration_seconds": 60 * (settings.rate_limit_minutes if action == "rate_limit" else settings.block_minutes),
        "category": a.category, "source_ip": a.source_ip, "destination_ip": a.destination_ip, **_evidence_values(a),
        "recovery_status": "not_applied", "created_at": to_iso(now),
    })
    audit_service.record(conn, user_id=None, action="mitigation.propose",
                         details={"mitigation_id": mitigation_id, "action": action, "target": a.target,
                                  "confidence": a.confidence, "severity": a.severity, "repetition": a.repetition,
                                  "false_positive_risk": a.false_positive_risk})
    return mitigation_id


def _apply_automatically(mitigation_id: int, now: datetime) -> None:
    with database_service.session() as conn:
        row = dict(repo.get(conn, mitigation_id))
    if row["action_type"] != "rate_limit":  # a block or isolation must never get here, whatever calls this
        raise MitigationError("Only a rate limit can be applied automatically.")
    _apply(row, decided_by=None, note="Applied automatically under the Auto rate-limit policy.", now=now)


# ------------------------------------------------------------------ applying and ending

def _session_origin(conn, session_id: int) -> str:
    row = conn.execute("SELECT source_type FROM monitoring_sessions WHERE id = ?", (session_id,)).fetchone()
    if row is None:
        raise MitigationError("That monitoring session no longer exists.")
    return "simulation" if row["source_type"] == "simulation" else "real"


def _session_interface(conn, session_id: Optional[int]) -> Optional[str]:
    row = conn.execute("SELECT source_type, interface_name FROM monitoring_sessions WHERE id = ?", (session_id,)).fetchone()
    return row["interface_name"] if row is not None and row["source_type"] == "live_capture" else None


def _condition(conn, session_id: int, start: datetime, end: datetime, target_kind: str, target: str,
               action_type: str) -> Dict[str, Any]:
    """Mean link and target figures over a stored window. Anything not stored stays None, never 0."""
    metrics = [dict(r) for r in repo.metrics_between(conn, session_id, to_iso(start), to_iso(end))]
    if not metrics:
        return {"samples": 0, "start": to_iso(start), "end": to_iso(end)}

    def mean(key: str, factor: float = 1.0) -> Optional[float]:
        values = [float(m[key]) * factor for m in metrics if m[key] is not None]
        return sum(values) / len(values) if values else None

    samples = len(metrics)
    host_rows = [dict(r) for r in repo.host_metrics_between(conn, session_id, to_iso(start), to_iso(end))]
    target_bps = other_bps = None
    if host_rows:  # a host with no row in an interval sent nothing then, so dividing by all samples is right
        total = sum(float(r["sent_bps"]) for r in host_rows) / samples
        if target_kind == "link":
            other_bps = total
        else:
            of_target = [r for r in host_rows if r["host"] == target]
            if target_kind == "source":
                target_bps = sum(float(r["sent_bps"]) for r in of_target) / samples
            else:
                target_bps = sum(float(r["received_bps"]) for r in of_target) / samples
            if action_type == "isolate":
                target_bps = sum(float(r["sent_bps"]) + float(r["received_bps"]) for r in of_target) / samples
            other_bps = max(0.0, total - target_bps)
    return {"samples": samples, "start": to_iso(start), "end": to_iso(end), "throughput_bps": mean("throughput_bps"),
            "incoming_bps": mean("incoming_bytes_per_second", 8.0), "outgoing_bps": mean("outgoing_bytes_per_second", 8.0),
            "loss_ratio": mean("packet_loss_ratio"), "utilization": mean("utilization_ratio"),
            "latency_ms": mean("latency_ms"), "target_bps": target_bps, "other_bps": other_bps,
            "provenance": metrics[-1]["provenance"]}


def _allocations_around(conn, row: Mapping[str, Any]) -> tuple:
    """(allocation now, what it becomes with this action), both from the newest stored demands."""
    latest = repo.latest_allocation(conn, row["session_id"]) if row["session_id"] else None
    if latest is None:
        return None, None
    settings = settings_service.get_mitigation_settings()
    capacity = float(latest["capacity_bps"])
    stored = json.loads(latest["hosts_json"])
    limit = {"block": 0.0, "isolate": 0.0}.get(row["action_type"], row["limit_bps"])
    demands = []
    for h in stored:
        host_limit, name = h["limit_bps"], h["traffic_class"]
        if row["target_kind"] == "source" and h["host"] == row["target"]:
            host_limit, name = limit, host_allocation.RESTRICTED
        demands.append(HostDemand(h["host"], name, float(h["demand_bps"]), host_limit))
    try:
        after = host_allocation.allocate_hosts(capacity, _allocation_policy(settings), demands)
    except AllocationError:
        return json.loads(latest["classes_json"]), None
    return json.loads(latest["classes_json"]), _allocation_summary(after)


def _apply(row: Dict[str, Any], *, decided_by: Optional[int], note: str, now: datetime) -> Dict[str, Any]:
    enforcer = _enforcers[row["origin"]]
    with database_service.session() as conn:
        row["interface_name"] = _session_interface(conn, row["session_id"])
    started = time.perf_counter()
    failure: Optional[str] = None
    commands = None
    adapter = enforcer.name  # read once: the same answer goes in the record as was used to act
    try:
        commands = enforcer.apply(row)
    except EnforcementError as exc:
        failure = str(exc)[:500]
    elapsed_ms = (time.perf_counter() - started) * 1000
    dry_run = adapter == DRY_RUN
    enforcement = {"adapter": adapter, "execution_ms": elapsed_ms, "interface_name": row["interface_name"],
                   "commands_json": json.dumps(commands) if commands else None}
    expires = now + timedelta(seconds=int(row["duration_seconds"]))
    with database_service.session(write=True) as conn:
        current = repo.get(conn, row["id"])
        if current is None or current["status"] != "proposed":  # someone else decided first: undo ours
            if failure is None:
                enforcer.remove({**row, "adapter": adapter})
            raise MitigationError("This action was already decided.")
        if failure is not None:
            repo.update(conn, row["id"], {"status": "failed", "failure_reason": failure, "decided_at": to_iso(now),
                                          "decided_by": decided_by, "decision_note": note[:500], **enforcement})
            audit_service.record(conn, user_id=decided_by, action="mitigation.apply", outcome="failure",
                                 details={"mitigation_id": row["id"], "error": failure})
            _note_incident(conn, row, f"Mitigation #{row['id']} failed: {failure}", decided_by, now)
        else:
            before = None
            if row["session_id"]:
                before = _condition(conn, row["session_id"], now - timedelta(seconds=BEFORE_WINDOW_SECONDS), now,
                                    row["target_kind"], row["target"], row["action_type"])
            previous, new = _allocations_around(conn, row)
            repo.update(conn, row["id"], {
                "status": "active", "decided_at": to_iso(now), "decided_by": decided_by, "decision_note": note[:500],
                "applied_at": to_iso(now), "expires_at": to_iso(expires), **enforcement,
                "recovery_status": "not_applied" if dry_run else "pending",
                "recovery_note": "Dry run: nothing was changed on the network, so there is nothing to measure." if dry_run else None,
                "before_json": json.dumps(before, sort_keys=True) if before else None,
                "previous_allocation_json": json.dumps(previous, sort_keys=True) if previous else None,
                "new_allocation_json": json.dumps(new, sort_keys=True) if new else None})
            audit_service.record(conn, user_id=decided_by, action="mitigation.apply",
                                 details={"mitigation_id": row["id"], "action": row["action_type"], "target": row["target"],
                                          "limit_bps": row["limit_bps"], "expires_at": to_iso(expires),
                                          "initiated_by": row["initiated_by"], "automatic": decided_by is None,
                                          "adapter": adapter, "interface": row["interface_name"], "commands": commands})
            verb = "dry run only, nothing changed" if dry_run else "applied"
            _note_incident(conn, row, f"Mitigation #{row['id']} {verb}: {describe(row)}.", decided_by, now)
        return dict(repo.get(conn, row["id"]))


def _end(row: Mapping[str, Any], *, status: str, user_id: Optional[int], reason: str, now: datetime, action: str) -> None:
    """Take an active action off, or close a proposal. Removal happens first: a failed removal keeps it active."""
    if row["status"] == "active":
        _enforcers[row["origin"]].remove(row)
    with database_service.session(write=True) as conn:
        current = repo.get(conn, row["id"])
        if current is None or current["status"] not in repo.OPEN_STATUSES:
            return
        values: Dict[str, Any] = {"status": status, "ended_at": to_iso(now), "ended_by": user_id, "end_reason": reason[:500]}
        if current["recovery_status"] == "pending":
            values.update(recovery_status="unavailable",
                          recovery_note="The action ended before recovery could be checked.")
        repo.update(conn, row["id"], values)
        audit_service.record(conn, user_id=user_id, action=action,
                             details={"mitigation_id": row["id"], "from": current["status"], "to": status, "reason": reason[:200]})
        if current["status"] == "active":
            _note_incident(conn, row, f"Mitigation #{row['id']} ended ({status.replace('_', ' ')}): {reason}", user_id, now)


def _end_or_keep(row: Mapping[str, Any], *, status: str, user_id: Optional[int], reason: str, now: datetime, action: str) -> bool:
    """For ends nobody is waiting on. A removal that fails leaves the action active, on show, and retried next time."""
    try:
        _end(row, status=status, user_id=user_id, reason=reason, now=now, action=action)
        return True
    except EnforcementError as exc:
        message = f"Could not be removed: {exc}"[:500]
        with database_service.session(write=True) as conn:
            if row.get("failure_reason") != message:  # one audit row per problem, not one per retry
                repo.update(conn, row["id"], {"failure_reason": message})
                audit_service.record(conn, user_id=user_id, action=action, outcome="failure",
                                     details={"mitigation_id": row["id"], "error": message})
        return False


def expire_due(now: datetime) -> int:
    """End every active action past its expiry and every proposal nobody answered in time."""
    cutoff = to_iso(now - timedelta(seconds=PROPOSAL_TTL_SECONDS))
    with database_service.session() as conn:
        due = [dict(r) for r in conn.execute(
            "SELECT * FROM mitigation_actions WHERE (status = 'active' AND expires_at <= ?) "
            "OR (status = 'proposed' AND created_at <= ?)", (to_iso(now), cutoff)).fetchall()]
    for row in due:
        reason = "Its time limit ended." if row["status"] == "active" else "Nobody answered this proposal in time."
        _end_or_keep(row, status="expired", user_id=None, reason=reason, now=now, action="mitigation.expire")
    return len(due)


def end_session(session_id: int, reason: str, now: Optional[datetime] = None) -> None:
    """A finished session has no traffic left to act on."""
    moment = now or utc_now()
    with database_service.session() as conn:
        rows = [dict(r) for r in repo.of_session(conn, session_id, repo.OPEN_STATUSES)]
    for row in rows:
        _end_or_keep(row, status="ended", user_id=None, reason=reason, now=moment, action="mitigation.end")


def close_orphans() -> int:
    """After a restart nothing watches the actions of sessions that stopped with the old process, so close them.
    Limits on a real link outlive the process, so this also removes them from the kernel if it can."""
    moment = utc_now()
    with database_service.session() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT m.* FROM mitigation_actions m LEFT JOIN monitoring_sessions s ON s.id = m.session_id "
            "WHERE m.status IN ('proposed', 'active') AND (s.id IS NULL OR s.status <> 'RUNNING')").fetchall()]
    for row in rows:
        _end_or_keep(row, status="ended", user_id=None, reason="Its session is no longer running.", now=moment, action="mitigation.end")
    return len(rows)


def _verify_due(session_id: int, now: datetime) -> None:
    with database_service.session(write=True) as conn:
        for row in repo.of_session(conn, session_id, ("active",)):
            if row["recovery_status"] != "pending":
                continue
            applied = parse_iso(row["applied_at"])
            if (now - applied).total_seconds() < VERIFY_AFTER_SECONDS:
                continue
            after = _condition(conn, session_id, applied + timedelta(seconds=SETTLE_SECONDS), now, row["target_kind"],
                               row["target"], row["action_type"])
            before = json.loads(row["before_json"]) if row["before_json"] else {}
            status, note = mitigation_scoring.verify_recovery(row["action_type"], before, after, row["limit_bps"])
            if row["origin"] == "real" and not enforcement_service.measurable_after_enforcement(row["target_kind"], row["target"]):
                status, note = "unavailable", ("The rule is installed, but capture sees incoming packets before it acts, "
                                               "so its effect on this traffic cannot be measured here.")
            values: Dict[str, Any] = {"after_json": json.dumps(after, sort_keys=True), "recovery_status": status,
                                      "recovery_note": note[:500]}
            if "upstream" in note:
                values["upstream_required"] = 1
            repo.update(conn, row["id"], values)
            audit_service.record(conn, user_id=None, action="mitigation.verify",
                                 details={"mitigation_id": row["id"], "recovery": status})
            _note_incident(conn, dict(row), f"Mitigation #{row['id']} recovery check: {note}", None, now)


def _note_incident(conn, row: Mapping[str, Any], text: str, user_id: Optional[int], now: datetime) -> None:
    if row.get("incident_id"):
        incident_repository.insert_event(conn, incident_id=row["incident_id"], event_type="note", user_id=user_id,
                                         now=to_iso(now), note=text[:2000])


def _new_incident(conn, session_id: int, m: Mapping[str, Any], now: datetime) -> int:
    """Every mitigation has an incident. If correlation has not made one yet it can still join this one later, because
    it groups by time. Without a model verdict this makes no claim about what the traffic is."""
    source = conn.execute("SELECT source_type FROM monitoring_sessions WHERE id = ?", (session_id,)).fetchone()
    source_type = source["source_type"] if source else None
    moment = to_iso(now)
    what = m["category"] or "Administrator action"
    return incident_repository.insert(conn, {
        "title": f"{what} on {m['target']}"[:200], "classification": "security" if m["category"] else "undetermined",
        "status": "open", "window_start": moment, "window_end": moment,
        "correlation_rationale": (f"Opened by mitigation #{m['id']}: {m['reason']}" if m["category"]
                                  else f"Opened by an administrator's action, with no model verdict behind it: {m['reason']}"),
        "investigation_steps_json": json.dumps(["Review the action's evidence below.", "Confirm whether this host and traffic are expected.",
                                                "Roll the action back, or mark the incident a false positive, if it was wrong."]),
        "created_at": moment, "updated_at": moment, "is_replay": source_type == "replay",
        "is_simulation": source_type == "simulation"})


def _link_incidents(session_id: int, now: datetime) -> None:
    with database_service.session() as conn:
        unlinked = [dict(r) for r in repo.of_session(conn, session_id) if r["incident_id"] is None]
    if not unlinked:
        return
    with database_service.session(write=True) as conn:
        for m in unlinked:
            incident_id = repo.incident_for_category(conn, session_id, m["category"]) or _new_incident(conn, session_id, m, now)
            repo.update(conn, m["id"], {"incident_id": incident_id})
            m["incident_id"] = incident_id
            _note_incident(conn, m, f"Mitigation #{m['id']} ({m['status'].replace('_', ' ')}): {describe(m)}. {m['reason']}",
                           None, now)


# ------------------------------------------------------------------ administrators

def describe(m: Mapping[str, Any]) -> str:
    target = m["target"]
    if m["action_type"] == "rate_limit":
        side = "traffic from" if m["target_kind"] == "source" else "traffic towards"
        return f"limit {side} {target} to {float(m['limit_bps']) / 1e6:,.2f} Mbit/s"
    if m["action_type"] == "block":
        return f"block {target}"
    if m["action_type"] == "isolate":
        return f"isolate {target}"
    return "prioritize critical traffic and share the link by class"


def _validated_reason(reason: str) -> str:
    text = (reason or "").strip()
    if not 5 <= len(text) <= 500:
        raise MitigationError("Give a reason of 5 to 500 characters.")
    return text


def _validated_limit(limit_bps: float) -> float:
    if not MIN_LIMIT_BPS <= float(limit_bps) <= MAX_LIMIT_BPS:
        raise MitigationError(f"A rate limit must be at least {MIN_LIMIT_BPS / 1000:.0f} kbit/s.")
    return float(limit_bps)


def _validated_minutes(minutes: float) -> int:
    if not 1 <= int(minutes) <= 1440:
        raise MitigationError("The duration must be between 1 and 1440 minutes.")
    return int(minutes) * 60


def _validated_host(host: str) -> str:
    try:
        return str(ipaddress.ip_address((host or "").strip()))
    except ValueError as exc:
        raise MitigationError("The target must be a single IP address.") from exc


def _check_high_impact(row: Mapping[str, Any], confirm_target: Optional[str]) -> None:
    if row["action_type"] not in HIGH_IMPACT:
        return
    if (confirm_target or "").strip() != row["target"]:
        raise MitigationError(f"Type the address {row['target']} to confirm this action.")
    if row["action_type"] == "isolate" and row["origin"] != "simulation":
        with database_service.session() as conn:
            interface = _session_interface(conn, row["session_id"])
        if not enforcement_service.isolation_allowed(interface):
            raise MitigationError("Host isolation on a real link needs an interface marked as a lab network "
                                  "(SMART_SHIELD_ENFORCEMENT_LAB_INTERFACES).")


def _check_session_running(row: Mapping[str, Any]) -> None:
    with database_service.session() as conn:
        session = conn.execute("SELECT status FROM monitoring_sessions WHERE id = ?", (row["session_id"],)).fetchone()
    if session is None or session["status"] != "RUNNING":
        raise MitigationError("That session is not running any more, so there is nothing to act on.")


def _load(conn, mitigation_id: int) -> Dict[str, Any]:
    row = repo.get(conn, mitigation_id)
    if row is None:
        raise MitigationError("Mitigation not found.")
    return dict(row)


def _acted(result: Dict[str, Any], session_id: Optional[int], now: datetime) -> Dict[str, Any]:
    """An administrator's decision should reach its incident at once, with or without an engine running."""
    if session_id is None:
        return result
    _link_incidents(session_id, now)
    with database_service.session() as conn:
        return dict(repo.get(conn, result["id"]))


def approve(principal: Principal, mitigation_id: int, *, reason: str, confirm_target: Optional[str] = None,
            limit_bps: Optional[float] = None, duration_minutes: Optional[float] = None,
            now: Optional[datetime] = None) -> Dict[str, Any]:
    require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="mitigation.approve",
                       details={"mitigation_id": mitigation_id})
    text = _validated_reason(reason)
    moment = now or utc_now()
    with database_service.session(write=True) as conn:
        row = _load(conn, mitigation_id)
        if row["status"] != "proposed":
            raise MitigationError("Only a proposed action can be approved.")
        _check_high_impact(row, confirm_target)
        _check_session_running(row)
        changes: Dict[str, Any] = {}
        if limit_bps is not None and row["action_type"] == "rate_limit":
            changes["limit_bps"] = _validated_limit(limit_bps)
        if duration_minutes is not None:
            changes["duration_seconds"] = _validated_minutes(duration_minutes)
        if changes:
            repo.update(conn, mitigation_id, changes)
            row.update(changes)
    return _acted(_apply(row, decided_by=principal.user_id, note=text, now=moment), row["session_id"], moment)


def reject(principal: Principal, mitigation_id: int, *, reason: str, now: Optional[datetime] = None) -> None:
    require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="mitigation.reject",
                       details={"mitigation_id": mitigation_id})
    text = _validated_reason(reason)
    moment = now or utc_now()
    with database_service.session(write=True) as conn:
        row = _load(conn, mitigation_id)
        if row["status"] != "proposed":
            raise MitigationError("Only a proposed action can be rejected.")
        repo.update(conn, mitigation_id, {"status": "rejected", "decided_at": to_iso(moment), "decided_by": principal.user_id,
                                          "decision_note": text})
        audit_service.record(conn, user_id=principal.user_id, action="mitigation.reject",
                             details={"mitigation_id": mitigation_id, "reason": text[:200]})
        _note_incident(conn, row, f"Mitigation #{mitigation_id} rejected: {text}", principal.user_id, moment)


def rollback(principal: Principal, mitigation_id: int, *, reason: str, now: Optional[datetime] = None) -> None:
    """One click: the limit is removed at once and the engine will not ask again about this target for a while."""
    require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="mitigation.rollback",
                       details={"mitigation_id": mitigation_id})
    text = _validated_reason(reason)
    with database_service.session() as conn:
        row = _load(conn, mitigation_id)
    if row["status"] != "active":
        raise MitigationError("Only an active action can be rolled back.")
    try:
        _end(row, status="rolled_back", user_id=principal.user_id, reason=text, now=now or utc_now(),
             action="mitigation.rollback")
    except EnforcementError as exc:
        audit_service.record_standalone(user_id=principal.user_id, action="mitigation.rollback", outcome="failure",
                                        details={"mitigation_id": mitigation_id, "error": str(exc)[:300]})
        raise MitigationError(f"Rollback failed, so the action is still active: {exc}") from exc


def request_action(principal: Principal, session_id: int, action_type: str, *, target: Optional[str] = None,
                   target_kind: str = "source", limit_bps: Optional[float] = None, duration_minutes: float = 15,
                   reason: str, confirm_target: Optional[str] = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    """An administrator's own decision, applied at once."""
    require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="mitigation.request",
                       details={"session_id": session_id, "action": action_type})
    if action_type not in ACTION_TYPES:
        raise MitigationError("Unknown action.")
    text = _validated_reason(reason)
    seconds = _validated_minutes(duration_minutes)
    moment = now or utc_now()
    if action_type == "prioritize":
        target_kind, target = "link", "link"
    else:
        if target_kind not in ("source", "destination"):
            raise MitigationError("The target must be a source or a destination.")
        if action_type in HIGH_IMPACT and target_kind != "source":
            raise MitigationError("Only a source address can be blocked or isolated.")
        target = _validated_host(target or "")
    limit = None
    if action_type == "rate_limit":
        if limit_bps is None:
            raise MitigationError("Give a rate limit.")
        limit = _validated_limit(limit_bps)
    with database_service.session(write=True) as conn:
        origin = _session_origin(conn, session_id)
        row = {"origin": origin, "session_id": session_id, "action_type": action_type, "target": target}
        _check_high_impact(row, confirm_target)
        _check_session_running(row)
        if repo.open_for_target(conn, session_id, target_kind, target):
            raise MitigationError("This target already has an open action. Decide or roll that back first.")
        mitigation_id = repo.insert(conn, {
            "origin": origin, "session_id": session_id, "action_type": action_type, "target_kind": target_kind,
            "target": target, "status": "proposed", "initiated_by": "admin", "limit_bps": limit, "duration_seconds": seconds,
            "reason": text, "source_ip": target if target_kind == "source" else None,
            "destination_ip": target if target_kind == "destination" else None, "created_at": to_iso(moment)})
        fresh = dict(repo.get(conn, mitigation_id))
    return _acted(_apply(fresh, decided_by=principal.user_id, note=text, now=moment), session_id, moment)


def emergency_disable(principal: Principal, *, reason: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Everything off at once: the engine is set to Off so it cannot re-apply, then every limit and block is removed,
    on all backends, including class policies from traffic_shaping_service. Failures are reported, never hidden."""
    require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="mitigation.emergency_disable")
    text = _validated_reason(reason)
    moment = now or utc_now()
    settings_service.update_mitigation_settings(principal, replace(settings_service.get_mitigation_settings(), policy="off"))
    failures = list(_enforcers["real"].clear()) if hasattr(_enforcers["real"], "clear") else []
    with database_service.session() as conn:
        rows = [dict(r) for r in repo.all_active(conn)]
    ended = 0
    for row in rows:
        if _end_or_keep(row, status="rolled_back", user_id=principal.user_id, reason=f"Emergency disable: {text}", now=moment,
                        action="mitigation.rollback"):
            ended += 1
        else:
            failures.append(f"Mitigation #{row['id']} could not be removed.")
    if get_settings().tc_enabled:
        try:
            traffic_shaping_service.emergency_disable(principal)
        except ShapingError as exc:
            failures.append(f"Class shaping: {exc}")
    audit_service.record_standalone(user_id=principal.user_id, action="mitigation.emergency_disable",
                                    outcome="failure" if failures else "success",
                                    details={"ended": ended, "failures": failures[:10], "reason": text[:200]})
    return {"ended": ended, "failures": failures}


def close_as_false_positive(principal: Principal, incident_id: int, *, reason: str, now: Optional[datetime] = None) -> None:
    """Take off whatever the incident's actions are doing, then record the false positive. If a removal fails it stops
    there, so an incident is never called a false positive while its limit is still in force."""
    with database_service.session() as conn:
        rows = [dict(r) for r in repo.of_incident(conn, incident_id) if r["status"] in repo.OPEN_STATUSES]
    text = f"False positive: {(reason or '').strip()}"[:500]
    if rows:
        require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="mitigation.false_positive",
                           details={"incident_id": incident_id})
    if len((reason or "").strip()) < 5:
        raise MitigationError("Give a reason of at least 5 characters.")
    for row in rows:
        if row["status"] == "active":
            rollback(principal, row["id"], reason=text, now=now)
        else:
            reject(principal, row["id"], reason=text, now=now)
    try:
        incident_correlation_service.mark_false_positive(principal, incident_id, reason)
    except incident_correlation_service.IncidentError as exc:
        raise MitigationError(str(exc)) from exc


# ------------------------------------------------------------------ reading

JSON_FIELDS = ("assessment_json", "previous_allocation_json", "new_allocation_json", "before_json", "after_json",
               "commands_json")


def _public(row: Mapping[str, Any]) -> Dict[str, Any]:
    item = dict(row)
    for key in JSON_FIELDS:
        item[key[:-5]] = json.loads(item.pop(key)) if item.get(key) else None
    item["description"] = describe(item)
    return item


def list_for_session(principal: Principal, session_id: int) -> List[Dict[str, Any]]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="mitigation.view")
    with database_service.session() as conn:
        return [_public(r) for r in repo.of_session(conn, session_id)]


def list_for_incident(principal: Principal, incident_id: int) -> List[Dict[str, Any]]:
    require_permission(principal, Permission.VIEW_ALERTS, action="mitigation.view")
    with database_service.session() as conn:
        return [_public(r) for r in repo.of_incident(conn, incident_id)]


def list_recent_applied(principal: Principal, limit: int = 30) -> List[Dict[str, Any]]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="mitigation.view")
    with database_service.session() as conn:
        return [_public(r) for r in repo.recent_applied(conn, limit)]


def get_action(principal: Principal, mitigation_id: int) -> Dict[str, Any]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="mitigation.view")
    with database_service.session() as conn:
        return _public(_load(conn, mitigation_id))


def allocation_history(principal: Principal, session_id: int, limit: int = 300) -> List[Dict[str, Any]]:
    """Oldest first: each interval's class shares, with what no class asked for as `available_bps`."""
    require_permission(principal, Permission.VIEW_DASHBOARD, action="mitigation.view")
    with database_service.session() as conn:
        rows = repo.allocation_history(conn, session_id, limit)
    return [{**json.loads(r["classes_json"]), "timestamp": r["timestamp"], "enforced": bool(r["enforced"])} for r in reversed(rows)]


def host_rows(principal: Principal, session_id: int, hosts: Sequence[Any]) -> List[Dict[str, Any]]:
    """The host table: each host's use with its allocation, status and what to do next.

    Restricted means a mitigation is really limiting this host (a dry run does not count). Suspicious is a model verdict.
    Allocated is None when there is no allocation, never 0.
    """
    require_permission(principal, Permission.VIEW_DASHBOARD, action="mitigation.view")
    with database_service.session() as conn:
        latest = repo.latest_allocation(conn, session_id)
        actions = [dict(r) for r in repo.of_session(conn, session_id, repo.OPEN_STATUSES)]
    grants = {h["host"]: h for h in json.loads(latest["hosts_json"])} if latest else {}
    rows = []
    for host in hosts:
        mine = [a for a in actions if a["target"] == host.host]
        active = next((a for a in mine if a["status"] == "active"), None)
        dry_run = active is not None and active["adapter"] == DRY_RUN
        status = "restricted" if active and not dry_run else host.status
        grant = grants.get(host.host)
        rows.append({"host": host.host, "kind": host.kind, "sent_bps": host.sent_bps, "received_bps": host.received_bps,
                     "usage_bps": host.total_bps, "allocated_bps": None if grant is None else float(grant["allocated_bps"]),
                     "has_allocation": latest is not None,
                     "status": status, "dry_run": dry_run, "action": "Investigate" if status == "suspicious" else "Manage",
                     "active_id": active["id"] if active else None, "incident_id": mine[0]["incident_id"] if mine else None,
                     "flagged_flows": host.flagged_flows, "top_category": host.top_category,
                     "active_connections": host.active_connections, "traffic": host.traffic})
    return rows


def enforcement_status(principal: Principal) -> enforcement_service.Capability:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="mitigation.view")
    return enforcement_service.capability()


def list_active_real(principal: Principal) -> List[Dict[str, Any]]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="mitigation.view")
    with database_service.session() as conn:
        return [_public(r) for r in repo.active_real(conn)]


def latest_allocation(principal: Principal, session_id: int) -> Optional[Dict[str, Any]]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="mitigation.view")
    with database_service.session() as conn:
        row = repo.latest_allocation(conn, session_id)
    if row is None:
        return None
    return {**json.loads(row["classes_json"]), "timestamp": row["timestamp"], "enforced": bool(row["enforced"]),
            "hosts": json.loads(row["hosts_json"]), "provenance": row["provenance"]}


def data_count(conn) -> int:
    return repo.count_simulation(conn)


def clear_simulation(conn) -> None:
    repo.delete_simulation(conn)

