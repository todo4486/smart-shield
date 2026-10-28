"""Security / performance event correlation and incident investigation.

How alerts become incidents (deterministic)
1. Each unresolved alert not yet in an incident gets an event interval in
   network (data) time: a detection's flow time window, a forecast's base time
   up to its longest horizon, or the alert's creation time when neither is known.
2. Intervals are padded by the correlation window and merged when they overlap.
   A group that overlaps an open incident joins it; otherwise it becomes a new
   incident.
3. Classification (SPEC §9):
   * combined:    security evidence (classifier or anomaly) AND congestion or
                  performance evidence in the same window (scenario A).
   * performance: congestion or performance alerts only. Never labelled an
                  attack (scenarios B and D).
   * security:    security or anomaly alerts only (scenario C when the traffic
                  stayed normal).
   Congestion is never treated as evidence of an attack. A combined incident
   needs independent security evidence from Smart Shield.
4. Measured traffic changes compare stored telemetry inside the window with the
   window of equal length just before it. Without telemetry they are reported
   as unavailable.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from repositories import incident_repository
from services import alert_service, audit_service, database_service
from services.authorization import Permission, Principal, require_permission
from services.timeutil import parse_iso, to_iso, utc_now_iso

DEFAULT_WINDOW_MINUTES = 15
SHARP_RISE = 0.50  # +50% mean throughput vs the preceding window
NORMAL_BAND = 0.20  # within ±20% counts as normal
SECURITY_TYPES = ("security", "anomaly")
PERFORMANCE_TYPES = ("congestion", "performance")
STATUSES = ("open", "investigating", "resolved", "closed")
TRANSITIONS = {"open": {"investigating", "resolved"}, "investigating": {"resolved", "open"},
               "resolved": {"closed", "open"}, "closed": set()}


class IncidentError(Exception):
    pass


@dataclass
class Event:
    alert_id: int
    alert_type: str
    category: str
    severity: str
    start: datetime
    end: datetime
    basis: str  # "network time" or "alert creation time"
    interface: Optional[str]
    model_version: Optional[str]


@dataclass
class CorrelationRun:
    incidents_created: List[int] = field(default_factory=list)
    incidents_updated: List[int] = field(default_factory=list)
    alerts_linked: int = 0


@dataclass
class Incident:
    id: int
    title: str
    classification: str
    status: str
    window_start: str
    window_end: str
    measured_changes: Dict[str, Any]
    model_outputs: Dict[str, Any]
    rationale: str
    steps: List[str]
    notes: Optional[str]
    created_at: str
    updated_at: str
    alerts: List[alert_service.Alert] = field(default_factory=list)
    assigned_to: Optional[int] = None
    assigned_email: Optional[str] = None

    @property
    def not_an_attack(self) -> bool:
        """Congestion/performance evidence only: shown with a "Not an attack" badge."""
        return self.classification == "performance"


# ------------------------------------------------------------------ events

def event_for(row) -> Event:
    evidence = json.loads(row["evidence_json"]) if row["evidence_json"] else {}
    created = parse_iso(row["created_at"])
    start = end = created
    basis = "alert creation time"
    interface = evidence.get("interface")
    window = evidence.get("time_window_utc")
    if row["alert_type"] in SECURITY_TYPES and isinstance(window, list) and len(window) == 2:
        start, end = parse_iso(window[0]), parse_iso(window[1])
        basis = "network time"
    elif row["alert_type"] in PERFORMANCE_TYPES and evidence.get("base_time"):
        start = parse_iso(evidence["base_time"])
        horizons = [f.get("horizon_minutes", 0) for f in evidence.get("forecasts", [])]
        end = start + timedelta(minutes=max(horizons or [0]))
        basis = "network time"
    return Event(row["id"], row["alert_type"], row["category"], row["severity"], start, end, basis,
                 interface if interface not in (None, "(all)") else None, row["model_version"])


def cluster(events: List[Event], window: timedelta) -> List[List[Event]]:
    """Single-linkage grouping of padded intervals, ordered by start time (deterministic)."""
    groups: List[List[Event]] = []
    group_end: Optional[datetime] = None
    for event in sorted(events, key=lambda e: (e.start, e.alert_id)):
        if groups and group_end is not None and event.start - window <= group_end:
            groups[-1].append(event)
            group_end = max(group_end, event.end + window)
        else:
            groups.append([event])
            group_end = event.end + window
    return groups


# ------------------------------------------------------------ measurements

def measured_changes(conn, start: datetime, end: datetime) -> Dict[str, Any]:
    span = max(end - start, timedelta(minutes=5))
    during = incident_repository.metrics_between(conn, to_iso(start), to_iso(start + span))
    # The baseline window ends just before `start`, so no sample is counted in both windows.
    before = incident_repository.metrics_between(conn, to_iso(start - span), to_iso(start), end_inclusive=False)
    result: Dict[str, Any] = {"window": [to_iso(start), to_iso(start + span)],
                              "baseline_window": [to_iso(start - span), to_iso(start)], "interfaces": {}}
    if not during:
        result["summary"] = "unavailable: no stored telemetry covers this window"
        result["traffic_trend"] = "unknown"
        return result
    trends = []
    for interface in sorted({r["interface_name"] or "(unnamed)" for r in during}):
        now_rows = [r for r in during if (r["interface_name"] or "(unnamed)") == interface]
        old_rows = [r for r in before if (r["interface_name"] or "(unnamed)") == interface]
        mean_now = _mean([r["throughput_bps"] for r in now_rows])
        mean_before = _mean([r["throughput_bps"] for r in old_rows])
        change = (mean_now - mean_before) / mean_before if mean_now is not None and mean_before else None
        peak_util = max((r["utilization_ratio"] for r in now_rows if r["utilization_ratio"] is not None), default=None)
        trend = "unknown" if change is None else "sharp rise" if change >= SHARP_RISE else \
            "normal" if abs(change) <= NORMAL_BAND else "rise" if change > 0 else "drop"
        trends.append(trend)
        result["interfaces"][interface] = {
            "mean_throughput_bps": mean_now, "baseline_mean_throughput_bps": mean_before, "change": change,
            "peak_utilization": peak_util, "samples": len(now_rows), "trend": trend,
            "provenance": sorted({r["throughput_provenance"] or r["provenance"] for r in now_rows}),
        }
    order = ["sharp rise", "rise", "drop", "normal", "unknown"]
    result["traffic_trend"] = min(trends, key=order.index)
    result["summary"] = f"traffic {result['traffic_trend']} (stored telemetry, {len(during)} samples)"
    return result


def _mean(values) -> Optional[float]:
    numbers = [float(v) for v in values if v is not None]
    return sum(numbers) / len(numbers) if numbers else None


# ---------------------------------------------------------- classification

def classify(events: List[Event], changes: Dict[str, Any], recommendation=None) -> Dict[str, Any]:
    security = [e for e in events if e.alert_type == "security"]
    anomaly = [e for e in events if e.alert_type == "anomaly"]
    performance = [e for e in events if e.alert_type in PERFORMANCE_TYPES]
    trend = changes.get("traffic_trend", "unknown")
    interfaces = sorted({e.interface for e in events if e.interface})
    where = f" on {', '.join(interfaces)}" if interfaces else ""
    rationale: List[str] = []
    steps: List[str] = []
    bases = {e.basis for e in events}
    if "alert creation time" in bases:
        rationale.append("Some alerts carry no network timestamp, so their creation time was used. Correlation "
                         "for those alerts is approximate.")
    if (security or anomaly) and performance:
        classification = "combined"
        kinds = sorted({e.category for e in security + anomaly})
        title = f"Security and congestion{where}: " + ", ".join(kinds[:3])
        rationale.insert(0, f"Smart Shield raised {len(security + anomaly)} security alert(s) ({', '.join(kinds)}) "
                            f"and PredictNet raised {len(performance)} congestion/performance alert(s) in the same "
                            f"time window. Traffic trend: {trend}.")
        rationale.append("The two kinds of evidence are independent. Congestion by itself is not evidence of an "
                         "attack; this incident is combined because Smart Shield found security evidence too.")
        if not security:
            rationale.append("The security evidence is anomaly-only (unusual, not classified as an attack), so it "
                             "is weaker.")
        if not interfaces or any(e.interface is None for e in security + anomaly):
            rationale.append("Security alerts do not identify an interface, so they were linked to the congestion "
                             "by time only.")
        steps += ["Check whether the flagged sources and destinations account for the traffic increase.",
                  "Compare the flagged flows' volume with the measured throughput change.",
                  "If the attack traffic explains the load, contain it first; congestion should then ease.",
                  "Otherwise treat them as two separate problems and handle the congestion as a performance issue."]
    elif performance:
        classification = "performance"
        kinds = sorted({e.category for e in performance})
        title = f"Performance warning{where}: " + ", ".join(kinds[:3])
        rationale.insert(0, f"PredictNet raised {len(performance)} congestion/performance alert(s) and Smart Shield "
                            f"has no security alerts in this window. Traffic trend: {trend}.")
        rationale.append("This is treated as a performance issue, not an attack: no security evidence was found.")
        steps += ["Identify the largest flows or transfers in the window (backups, updates, video).",
                  "If a legitimate large transfer is responsible, consider rescheduling it or prioritising "
                  "latency-sensitive traffic with a bandwidth recommendation.",
                  "Check whether capacity is adequate for normal peaks."]
        if recommendation is not None:
            steps.append(f"A bandwidth recommendation exists for this interface (#{recommendation['id']}, "
                         f"{recommendation['status']}). Review it in Bandwidth Management.")
        else:
            steps.append("Generate a bandwidth recommendation for this link in Bandwidth Management.")
    elif security or anomaly:
        classification = "security"
        kinds = sorted({e.category for e in security + anomaly})
        title = "Security investigation: " + ", ".join(kinds[:3])
        if anomaly and not security:
            rationale.insert(0, f"An anomaly detector flagged unusual flows while traffic was {trend}; no classifier "
                                "detection and no congestion. The flows are unusual, not proven malicious.")
        else:
            rationale.insert(0, f"Smart Shield raised {len(security + anomaly)} security alert(s) with no related "
                                f"congestion. Traffic trend: {trend}.")
        steps += ["Review the alert evidence: top sources, destinations and ports.",
                  "Confirm whether the hosts involved are known and the traffic expected.",
                  "Mark false positives so later investigations are not misled."]
    else:  # pragma: no cover - a group always has at least one event
        classification, title = "undetermined", "Undetermined"
        rationale.insert(0, "No classifiable evidence.")
    return {"classification": classification, "title": title[:200], "rationale": " ".join(rationale), "steps": steps}


# ---------------------------------------------------------------- engine

def correlate(principal: Principal, window_minutes: int = DEFAULT_WINDOW_MINUTES) -> CorrelationRun:
    require_permission(principal, Permission.RUN_DETECTION, action="incident.correlate")
    if not 1 <= int(window_minutes) <= 24 * 60:
        raise IncidentError("Correlation window must be between 1 minute and 24 hours.")
    window = timedelta(minutes=int(window_minutes))
    run = CorrelationRun()
    now = utc_now_iso()
    with database_service.session(write=True) as conn:
        events = [event_for(r) for r in incident_repository.unlinked_alerts(conn)]
        if not events:
            return run
        open_incidents = [dict(r) for r in incident_repository.active_incidents(conn)]
        for group in cluster(events, window):
            start = min(e.start for e in group)
            end = max(e.end for e in group)
            target = next((i for i in open_incidents
                           if parse_iso(i["window_start"]) - window <= end and start <= parse_iso(i["window_end"]) + window),
                          None)
            if target is not None:
                existing = [event_for(r) for r in incident_repository.alerts_for(conn, target["id"])]
                group = existing + group
                start = min(start, parse_iso(target["window_start"]))
                end = max(end, parse_iso(target["window_end"]))
            changes = measured_changes(conn, start, end)
            interfaces = sorted({e.interface for e in group if e.interface})
            recommendation = incident_repository.latest_recommendation_for(conn, interfaces[0] if interfaces else None)
            verdict = classify(group, changes, dict(recommendation) if recommendation else None)
            predictions = [dict(p) for p in incident_repository.predictions_between(
                conn, to_iso(start - window), to_iso(end + window))]
            model_outputs = {
                "alert_models": sorted({e.model_version for e in group if e.model_version}),
                "forecasts_in_window": predictions[-20:],
                "note": "Model outputs are predictions or detections, not measurements.",
            }
            values = {
                "title": verdict["title"], "classification": verdict["classification"],
                "window_start": to_iso(start), "window_end": to_iso(max(end, start)),
                "measured_changes_json": json.dumps(changes, default=str),
                "model_outputs_json": json.dumps(model_outputs, default=str),
                "correlation_rationale": verdict["rationale"],
                "investigation_steps_json": json.dumps(verdict["steps"]), "updated_at": now,
            }
            if target is not None:
                incident_repository.update(conn, target["id"], values)
                incident_id = target["id"]
                run.incidents_updated.append(incident_id)
                target.update(values)
            else:
                incident_id = incident_repository.insert(conn, {**values, "status": "open",
                                                                 "created_by": principal.user_id, "created_at": now})
                run.incidents_created.append(incident_id)
                open_incidents.append({"id": incident_id, **values})
            for event in group:
                incident_repository.link(conn, incident_id, event.alert_id)
            run.alerts_linked += sum(1 for e in group if e in events)
        audit_service.record(conn, user_id=principal.user_id, action="incident.correlate",
                             details={"created": run.incidents_created, "updated": run.incidents_updated,
                                      "alerts_linked": run.alerts_linked, "window_minutes": int(window_minutes)})
    return run


# ----------------------------------------------------------------- queries

def _incident(row, alerts=None) -> Incident:
    return Incident(
        id=row["id"], title=row["title"], classification=row["classification"], status=row["status"],
        window_start=row["window_start"], window_end=row["window_end"],
        measured_changes=json.loads(row["measured_changes_json"]) if row["measured_changes_json"] else {},
        model_outputs=json.loads(row["model_outputs_json"]) if row["model_outputs_json"] else {},
        rationale=row["correlation_rationale"],
        steps=json.loads(row["investigation_steps_json"]) if row["investigation_steps_json"] else [],
        notes=row["investigation_notes"], created_at=row["created_at"], updated_at=row["updated_at"],
        alerts=alerts or [],
        assigned_to=row["assigned_to"] if "assigned_to" in row.keys() else None,
        assigned_email=row["assigned_email"] if "assigned_email" in row.keys() else None,
    )


def list_incidents(principal: Principal, statuses: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    require_permission(principal, Permission.VIEW_ALERTS, action="incident.list")
    with database_service.session() as conn:
        return [dict(r) for r in incident_repository.list_incidents(conn, statuses)]


def get_incident(principal: Principal, incident_id: int) -> Incident:
    require_permission(principal, Permission.VIEW_ALERTS, action="incident.view")
    with database_service.session() as conn:
        row = incident_repository.get(conn, incident_id)
        if row is None:
            raise IncidentError("Incident not found.")
        alerts = [alert_service.Alert.from_row(a) for a in incident_repository.alerts_for(conn, incident_id)]
    return _incident(row, alerts)


def timeline(principal: Principal, incident: Incident) -> Dict[str, Any]:
    """Telemetry around the incident window (padded by its own length) for charting."""
    require_permission(principal, Permission.VIEW_ALERTS, action="incident.view")
    start, end = parse_iso(incident.window_start), parse_iso(incident.window_end)
    pad = max(end - start, timedelta(minutes=30))
    with database_service.session() as conn:
        metrics = [dict(r) for r in incident_repository.metrics_between(conn, to_iso(start - pad), to_iso(end + pad))]
    events = []
    with database_service.session() as conn:
        for a in incident_repository.alerts_for(conn, incident.id):
            e = event_for(a)
            events.append({"alert_id": e.alert_id, "type": e.alert_type, "category": e.category,
                           "severity": e.severity, "start": e.start, "end": e.end, "basis": e.basis})
    return {"metrics": metrics, "events": events, "range": [start - pad, end + pad]}


def change_status(principal: Principal, incident_id: int, new_status: str, note: Optional[str] = None) -> None:
    require_permission(principal, Permission.TRIAGE_ALERTS, action="incident.change_status",
                       details={"incident_id": incident_id, "to": new_status})
    if new_status not in STATUSES:
        raise IncidentError("Unknown status.")
    now = utc_now_iso()
    with database_service.session(write=True) as conn:
        row = incident_repository.get(conn, incident_id)
        if row is None:
            raise IncidentError("Incident not found.")
        if new_status not in TRANSITIONS[row["status"]]:
            raise IncidentError(f"An incident cannot move from {row['status']} to {new_status}.")
        values: Dict[str, Any] = {"status": new_status, "updated_at": now}
        note = (note or "").strip()[:2000]
        incident_repository.insert_event(conn, incident_id=incident_id, event_type="status_change",
                                         from_status=row["status"], to_status=new_status, note=note or None,
                                         user_id=principal.user_id, now=now)
        if note:
            values["investigation_notes"] = ((row["investigation_notes"] + "\n\n") if row["investigation_notes"] else "") + \
                f"[{now[:16].replace('T', ' ')} UTC · {principal.email} · {row['status']} → {new_status}] {note}"
        incident_repository.update(conn, incident_id, values)
        audit_service.record(conn, user_id=principal.user_id, action="incident.change_status",
                             details={"incident_id": incident_id, "from": row["status"], "to": new_status})


def add_note(principal: Principal, incident_id: int, note: str) -> None:
    require_permission(principal, Permission.TRIAGE_ALERTS, action="incident.add_note", details={"incident_id": incident_id})
    note = (note or "").strip()[:2000]
    if not note:
        raise IncidentError("The note is empty.")
    now = utc_now_iso()
    with database_service.session(write=True) as conn:
        row = incident_repository.get(conn, incident_id)
        if row is None:
            raise IncidentError("Incident not found.")
        notes = ((row["investigation_notes"] + "\n\n") if row["investigation_notes"] else "") + \
            f"[{now[:16].replace('T', ' ')} UTC · {principal.email}] {note}"
        incident_repository.update(conn, incident_id, {"investigation_notes": notes[-20000:], "updated_at": now})
        incident_repository.insert_event(conn, incident_id=incident_id, event_type="note", note=note,
                                         user_id=principal.user_id, now=now)
        audit_service.record(conn, user_id=principal.user_id, action="incident.add_note",
                             details={"incident_id": incident_id})


# ------------------------------------------------------------------ triage

def acknowledge(principal: Principal, incident_id: int, note: Optional[str] = None) -> None:
    """Acknowledge = an analyst has picked the incident up (open → investigating)."""
    change_status(principal, incident_id, "investigating", note)


def assign(principal: Principal, incident_id: int, assignee_id: Optional[int]) -> None:
    """Assign an incident to an active user (or unassign with None). Audited and kept in the history."""
    require_permission(principal, Permission.TRIAGE_ALERTS, action="incident.assign",
                       details={"incident_id": incident_id, "assignee_id": assignee_id})
    now = utc_now_iso()
    with database_service.session(write=True) as conn:
        row = incident_repository.get(conn, incident_id)
        if row is None:
            raise IncidentError("Incident not found.")
        if row["status"] == "closed":
            raise IncidentError("A closed incident cannot be reassigned.")
        if assignee_id is not None and not incident_repository.is_active_user(conn, assignee_id):
            raise IncidentError("Incidents can only be assigned to an active user.")
        if row["assigned_to"] == assignee_id:
            return
        incident_repository.update(conn, incident_id, {"assigned_to": assignee_id, "updated_at": now})
        incident_repository.insert_event(conn, incident_id=incident_id, event_type="assignment",
                                         assigned_to=assignee_id, user_id=principal.user_id, now=now)
        audit_service.record(conn, user_id=principal.user_id, action="incident.assign",
                             details={"incident_id": incident_id, "from": row["assigned_to"], "to": assignee_id})


def assignable_users(principal: Principal) -> List[Dict[str, Any]]:
    require_permission(principal, Permission.TRIAGE_ALERTS, action="incident.assign")
    with database_service.session() as conn:
        return [dict(r) for r in incident_repository.active_users(conn)]


def events(principal: Principal, incident_id: int) -> List[Dict[str, Any]]:
    """The incident's history: status changes, assignments and the analyst notes thread (oldest first)."""
    require_permission(principal, Permission.VIEW_ALERTS, action="incident.view")
    with database_service.session() as conn:
        return [dict(r) for r in incident_repository.events(conn, incident_id)]


def swimlanes(principal: Principal, start: Optional[datetime] = None, end: Optional[datetime] = None,
              limit: int = 2000) -> Dict[str, Any]:
    """The newest alerts split into a security lane and a congestion lane, plus the incidents grouping them.

    Alerts are placed in network time (see event_for), so a range is applied after placing them. Without a
    range, the span of the alerts themselves is used. Each alert carries the incident it belongs to, if any.
    """
    require_permission(principal, Permission.VIEW_ALERTS, action="incident.view")
    lanes: Dict[str, List[Dict[str, Any]]] = {"security": [], "congestion": []}
    with database_service.session() as conn:
        membership = incident_repository.alert_incident_map(conn)
        placed = [(row, event_for(row)) for row in incident_repository.latest_alerts(conn, limit)]
        if placed and (start is None or end is None):
            start = start or min(e.start for _, e in placed)
            end = end or max(e.end for _, e in placed)
        for row, e in placed:
            if e.end < start or e.start > end:
                continue
            lane = "security" if e.alert_type in SECURITY_TYPES else "congestion"
            lanes[lane].append({"alert_id": e.alert_id, "type": e.alert_type, "category": e.category,
                                "severity": e.severity, "start": e.start, "end": e.end, "basis": e.basis,
                                "status": row["status"], "incident_id": membership.get(e.alert_id)})
        incidents = [dict(r) for r in incident_repository.incidents_overlapping(conn, to_iso(start), to_iso(end))] \
            if placed else []
    for lane in lanes.values():
        lane.sort(key=lambda a: (a["start"], a["alert_id"]))
    return {"lanes": lanes, "incidents": incidents, "range": [start, end] if placed else None}


def affected_hosts(alerts: List[alert_service.Alert]) -> List[str]:
    """Hosts named in the alerts' evidence (top sources and destinations, ports removed), most frequent first."""
    counts: Dict[str, int] = {}
    for alert in alerts:
        for key in ("top_sources", "top_destinations"):
            for item in alert.evidence.get(key) or []:
                value = str(item.get("value", "")) if isinstance(item, dict) else str(item)
                host = value.rsplit(":", 1)[0] if value.count(":") == 1 else value  # keep IPv6 addresses whole
                if host:
                    counts[host] = counts.get(host, 0) + int(item.get("flows", 1) if isinstance(item, dict) else 1)
    return [h for h, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]


def evidence_strength(alerts: List[alert_service.Alert]) -> Dict[str, Any]:
    """Rule-based strength of an incident's evidence (not a probability).

    * high:   a classifier (security) detection placed in network time
    * medium: anomaly-only security evidence, or congestion forecasts placed in network time
    * low:    every alert placed only by its creation time
    """
    if not alerts:
        return {"level": "low", "reasons": ["No alerts are linked."]}
    placed = [event_for(_alert_row(a)) for a in alerts]
    network_time = [e for e in placed if e.basis == "network time"]
    reasons = []
    if any(e.alert_type == "security" for e in network_time):
        level = "high"
        reasons.append("A trained classifier flagged flows, placed by their own network time.")
    elif network_time:
        level = "medium"
        if any(e.alert_type == "anomaly" for e in network_time):
            reasons.append("Anomaly evidence only: unusual, not classified as an attack.")
        if any(e.alert_type in PERFORMANCE_TYPES for e in network_time):
            reasons.append("Congestion forecasts are model predictions placed by the data time they were made from.")
    else:
        level = "low"
        reasons.append("Every alert is placed by its creation time, so grouping is approximate.")
    if len(network_time) < len(placed):
        reasons.append(f"{len(placed) - len(network_time)} alert(s) have no network timestamp.")
    return {"level": level, "reasons": reasons}


def _alert_row(alert: alert_service.Alert) -> Dict[str, Any]:
    """The fields event_for needs, from an Alert object."""
    return {"id": alert.id, "alert_type": alert.alert_type, "category": alert.category, "severity": alert.severity,
            "created_at": alert.created_at, "model_version": alert.model_version,
            "evidence_json": json.dumps(alert.evidence, default=str)}
