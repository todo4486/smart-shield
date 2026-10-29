"""One-click incident report and the weekly summary, as self-contained, script-free HTML.

Everything comes from stored data: the incident, its alerts and their evidence, the audit log, analyst notes,
stored forecasts and measurements. No PDF library is installed, so reports are HTML pages made to print well
(browser → Print → Save as PDF). Every value is HTML-escaped; the timeline is an inline SVG built here.

Weekly summary
* Covers alerts and incidents raised in the 7 days before the chosen end, and forecasts made in that period.
* DATASET REPLAY data is left out (it is not network activity), and the report says how much was left out.
* Forecast accuracy compares each stored forecast with the measurement stored for the same link closest to
  the forecast's target time (within a tolerance). Forecasts with no matching measurement are counted, not
  guessed. Utilization forecasts are compared with measured utilization, throughput with throughput.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from html import escape
from typing import Any, Dict, List, Optional, Sequence

from repositories.incident_repository import IS_REPLAY_ALERT, REPLAY_SOURCE_NAME
from services import (
    audit_service, database_service, explainability_service, incident_correlation_service as correlation,
    mitre,
)
from services.authorization import Permission, Principal, require_permission
from services.network_map_service import SEVERITY_POINTS, hosts_in_evidence
from services.severity import highest, rank
from services.timeutil import parse_iso, to_iso, utc_now_iso

MAX_EXPLAINED_ALERTS = 3
FORECAST_TOLERANCE_SECONDS = 150

_STYLE = ("<style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:32px;color:#111827;"
          "max-width:1100px}h1{margin:0 0 4px}h2{margin-top:28px;border-bottom:2px solid #3B82F6;padding-bottom:4px}"
          ".meta{color:#4B5563}table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}"
          "th,td{border:1px solid #D1D5DB;padding:4px 6px;text-align:left;vertical-align:top}th{background:#F3F4F6}"
          ".na{color:#9CA3AF;font-style:italic}.note{background:#EFF6FF;padding:8px 12px;border-left:4px solid "
          "#3B82F6;margin:6px 0}.badge{display:inline-block;padding:1px 8px;border-radius:10px;border:1px solid "
          "#9CA3AF;font-size:11px;margin-right:4px}.warn{border-color:#F59E0B;background:#FFFBEB}"
          ".crit{border-color:#EF4444;background:#FEF2F2}@media print{body{margin:12px}}</style>")
_SEV_COLORS = {"critical": "#EF4444", "high": "#F97316", "medium": "#F59E0B", "low": "#3B82F6"}


# ------------------------------------------------------------------ pure helpers

def _cell(value: Any) -> str:
    if value is None or value == "":
        return "<span class='na'>unavailable</span>"
    if isinstance(value, float):
        return escape(f"{value:,.4g}")
    return escape(str(value))


def _table(rows: Sequence[Dict[str, Any]], empty: str = "None.") -> str:
    if not rows:
        return f"<p class='na'>{escape(empty)}</p>"
    columns = list(rows[0])
    head = "".join(f"<th>{escape(c)}</th>" for c in columns)
    body = "".join("<tr>" + "".join(f"<td>{_cell(r[c])}</td>" for c in columns) + "</tr>" for r in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


def svg_timeline(events: Sequence[Dict[str, Any]], start: datetime, end: datetime, width: int = 1000) -> str:
    """Inline SVG: one bar per alert interval on a shared time axis (pure; labels escaped)."""
    if not events:
        return "<p class='na'>No alerts to draw.</p>"
    span = max((end - start).total_seconds(), 1.0)
    left, row_h = 220, 22
    height = 30 + row_h * len(events)
    x = lambda t: left + (width - left - 20) * max(0.0, min(1.0, (t - start).total_seconds() / span))  # noqa: E731
    parts = [f"<svg xmlns='http://www.w3.org/2000/svg' width='100%' viewBox='0 0 {width} {height}' role='img' "
             "aria-label='Alert timeline'>",
             f"<text x='{left}' y='14' font-size='11' fill='#4B5563'>{escape(to_iso(start)[:19])} UTC</text>",
             f"<text x='{width - 20}' y='14' font-size='11' fill='#4B5563' text-anchor='end'>"
             f"{escape(to_iso(end)[:19])} UTC</text>"]
    for i, e in enumerate(events):
        y = 24 + i * row_h
        x0, x1 = x(e["start"]), x(e["end"])
        color = _SEV_COLORS.get(e["severity"], "#6B7280")
        parts.append(f"<text x='{left - 8}' y='{y + 12}' font-size='11' text-anchor='end'>"
                     f"#{int(e['alert_id'])} {escape(str(e['category']))[:28]} ({escape(e['severity'])})</text>")
        parts.append(f"<rect x='{x0:.1f}' y='{y + 2}' width='{max(3.0, x1 - x0):.1f}' height='14' rx='3' "
                     f"fill='{color}'/>")
    parts.append("</svg>")
    return "".join(parts)


def host_risk_from_alerts(alerts: Sequence[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
    """Hosts named in alert evidence, scored 40/20/8/3 per critical/high/medium/low alert (pure)."""
    hosts: Dict[str, Dict[str, Any]] = {}
    for alert in alerts:
        for host in hosts_in_evidence(alert["evidence"]):
            entry = hosts.setdefault(host, {"host": host, "score": 0, "alerts": 0, "worst": None})
            entry["score"] += SEVERITY_POINTS.get(alert["severity"], 0)
            entry["alerts"] += 1
            entry["worst"] = highest([entry["worst"], alert["severity"]])
    return sorted(hosts.values(), key=lambda h: (-h["score"], -h["alerts"], h["host"]))[:limit]


def forecast_accuracy(predictions: Sequence[Dict[str, Any]], measurements: Sequence[Dict[str, Any]],
                      tolerance_seconds: float = FORECAST_TOLERANCE_SECONDS) -> List[Dict[str, Any]]:
    """MAE per horizon and quantity of stored forecasts against the closest measurement to each target time (pure).

    Utilization and throughput forecasts are scored separately (their errors are in different units). A forecast
    counts as matched only if a measurement of the same link and quantity lies within the tolerance.
    """
    by_link: Dict[Optional[str], List[tuple]] = {}
    for m in measurements:
        by_link.setdefault(m["interface_name"], []).append((parse_iso(m["timestamp"]), m))
    out: Dict[tuple, Dict[str, Any]] = {}
    for p in predictions:
        horizon = int(p["forecast_horizon_seconds"])
        if p.get("predicted_utilization_ratio") is not None:
            quantity, predicted, column = "utilization", p["predicted_utilization_ratio"], "utilization_ratio"
        elif p.get("predicted_throughput_bps") is not None:
            quantity, predicted, column = "throughput (bit/s)", p["predicted_throughput_bps"], "throughput_bps"
        else:
            continue
        row = out.setdefault((horizon, quantity), {"horizon_minutes": horizon // 60, "quantity": quantity,
                                                   "forecasts": 0, "matched": 0, "errors": []})
        row["forecasts"] += 1
        target = parse_iso(p["timestamp"]) + timedelta(seconds=horizon)
        candidates = [c for c in by_link.get(p["interface_name"], []) if c[1].get(column) is not None]
        if not candidates:
            continue
        moment, measured = min(candidates, key=lambda c: abs((c[0] - target).total_seconds()))
        if abs((moment - target).total_seconds()) > tolerance_seconds:
            continue
        row["matched"] += 1
        row["errors"].append(abs(predicted - measured[column]))
    result = []
    for key in sorted(out):
        row = out[key]
        errors = row.pop("errors")
        row["mae"] = sum(errors) / len(errors) if errors else None
        result.append(row)
    return result


# ------------------------------------------------------------------ incident report

@dataclass
class IncidentReport:
    incident: correlation.Incident
    generated_at: str
    generated_by: str
    severity: Optional[str]
    strength: Dict[str, Any]
    hosts: List[str]
    techniques: List[mitre.Technique]
    timeline: List[Dict[str, Any]]
    explanations: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    notes: List[Dict[str, Any]]
    caveats: List[str] = field(default_factory=list)


def build_incident_report(principal: Principal, incident_id: int) -> IncidentReport:
    require_permission(principal, Permission.VIEW_REPORTS, action="report.incident", details={"incident_id": incident_id})
    incident = correlation.get_incident(principal, incident_id)
    alert_ids = [a.id for a in incident.alerts]
    timeline = []
    for alert in incident.alerts:
        e = correlation.event_for({"id": alert.id, "alert_type": alert.alert_type, "category": alert.category,
                                   "severity": alert.severity, "created_at": alert.created_at,
                                   "evidence_json": json.dumps(alert.evidence), "model_version": alert.model_version})
        timeline.append({"alert_id": alert.id, "category": alert.category, "severity": alert.severity,
                         "start": e.start, "end": e.end, "basis": e.basis})
    explanations = []
    candidates = sorted((a for a in incident.alerts if a.alert_type in ("security", "anomaly")),
                        key=lambda a: (-rank(a.severity), a.id))[:MAX_EXPLAINED_ALERTS]
    for alert in candidates:
        try:
            explanations.append({"alert_id": alert.id,
                                 "summary": explainability_service.explain_alert(principal, alert.id).summary})
        except explainability_service.ExplainError as exc:
            explanations.append({"alert_id": alert.id, "summary": f"No explanation: {exc}"})
    with database_service.session() as conn:
        placeholders = ", ".join("?" for _ in alert_ids) or "NULL"
        actions = [dict(r) for r in conn.execute(
            "SELECT a.created_at AS \"When\", u.email AS \"Who\", a.action AS \"Action\", a.outcome AS \"Outcome\", "
            "a.details_json AS \"Details\" FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id "
            "WHERE (a.action LIKE 'incident.%' AND json_extract(a.details_json, '$.incident_id') = ?) "
            f"OR (a.action LIKE 'alert.%' AND json_extract(a.details_json, '$.alert_id') IN ({placeholders})) "
            "ORDER BY a.created_at, a.id", (incident_id, *alert_ids))]
    notes = [{"When": e["created_at"], "Who": e["user_email"] or "system", "Note": e["note"]}
             for e in correlation.events(principal, incident_id) if e["event_type"] == "note" and e["note"]]
    notes += [{"When": a.created_at, "Who": f"alert #{a.id}", "Note": a.investigation_notes}
              for a in incident.alerts if a.investigation_notes]
    caveats = ["Every value comes from data stored in Smart Shield. Model scores are uncalibrated and forecasts are "
               "predictions, not measurements. ATT&CK techniques are a label-level mapping, not confirmed techniques."]
    if incident.is_replay:
        caveats.insert(0, "DATASET REPLAY: this incident was built from recorded, labelled data replayed through the "
                          "pipeline. It is not live network activity.")
    if incident.not_an_attack:
        caveats.insert(0, "Not an attack: this incident contains only congestion or performance evidence.")
    report = IncidentReport(
        incident=incident, generated_at=utc_now_iso(), generated_by=principal.email,
        severity=highest(a.severity for a in incident.alerts), strength=correlation.evidence_strength(incident.alerts),
        hosts=correlation.affected_hosts(incident.alerts),
        techniques=mitre.primaries_for(a.category for a in incident.alerts if a.alert_type == "security"),
        timeline=timeline, explanations=explanations, actions=actions, notes=notes, caveats=caveats)
    audit_service.record_standalone(user_id=principal.user_id, action="report.incident", outcome="success",
                                    details={"incident_id": incident_id})
    return report


def incident_report_html(report: IncidentReport) -> str:
    i = report.incident
    start, end = parse_iso(i.window_start), parse_iso(i.window_end)
    if report.timeline:
        start = min([start] + [t["start"] for t in report.timeline])
        end = max([end] + [t["end"] for t in report.timeline])
    badges = "".join(f"<span class='badge'>{escape(b)}</span>" for b in (
        [f"Severity: {report.severity or 'none'}", f"Status: {i.status}", f"Classification: {i.classification}",
         f"Evidence: {report.strength['level']} (rule-based)"]
        + (["DATASET REPLAY"] if i.is_replay else []) + (["Not an attack"] if i.not_an_attack else [])))
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        f"<title>{escape(f'Incident #{i.id} report')}</title>{_STYLE}</head><body>",
        f"<h1>Incident #{i.id}: {escape(i.title)}</h1>",
        f"<div class='meta'>Window {escape(i.window_start)} → {escape(i.window_end)} (network time, UTC) · assigned to "
        f"{escape(i.assigned_email or 'nobody')} · generated {escape(report.generated_at)} by "
        f"{escape(report.generated_by)}</div><p>{badges}</p>",
    ]
    parts += [f"<div class='note'>{escape(c)}</div>" for c in report.caveats]
    parts.append(f"<h2>Summary</h2><p>{escape(i.rationale)}</p>")
    parts.append("<p>" + " ".join(escape(r) for r in report.strength.get("reasons", [])) + "</p>")
    parts.append("<h2>Timeline</h2>" + svg_timeline(report.timeline, start, end))
    parts.append(_table([{"Alert": f"#{t['alert_id']}", "Category": t["category"], "Severity": t["severity"],
                          "From": to_iso(t["start"])[:19], "To": to_iso(t["end"])[:19], "Time basis": t["basis"]}
                         for t in report.timeline]))
    parts.append("<h2>Affected hosts</h2>" + (_table([{"Host": h} for h in report.hosts]) if report.hosts
                                              else "<p class='na'>The alerts name no hosts.</p>"))
    parts.append("<h2>MITRE ATT&amp;CK</h2>" + _table(
        [{"Tactic": t.tactic, "Technique": f"{t.technique_id} {t.technique}", "Reference": t.url}
         for t in report.techniques], "No attack category in this incident maps to a technique."))
    parts.append("<h2>Why the alerts were raised</h2>" + _table(
        [{"Alert": f"#{e['alert_id']}", "Explanation": e["summary"]} for e in report.explanations],
        "No security or anomaly alerts to explain."))
    parts.append("<h2>Measured traffic changes</h2><p>" + escape(i.measured_changes.get("summary", "unavailable"))
                 + "</p>")
    parts.append("<h2>Investigation steps suggested</h2>" + (
        "<ol>" + "".join(f"<li>{escape(s)}</li>" for s in i.steps) + "</ol>" if i.steps else "<p class='na'>None.</p>"))
    parts.append("<h2>Actions taken (audit log)</h2>" + _table(report.actions, "No actions recorded yet."))
    parts.append("<h2>Analyst notes</h2>" + _table(report.notes, "No notes yet."))
    parts.append("</body></html>")
    return "".join(parts)


# ------------------------------------------------------------------ weekly summary

@dataclass
class WeeklySummary:
    start: str
    end: str
    generated_at: str
    generated_by: str
    alerts_by_type: Dict[str, int]
    alerts_by_severity: Dict[str, int]
    suppressed_alerts: int
    replay_alerts_left_out: int
    top_incidents: List[Dict[str, Any]]
    risky_hosts: List[Dict[str, Any]]
    congestion_alerts: List[Dict[str, Any]]
    forecasts_by_risk: Dict[str, int]
    accuracy: List[Dict[str, Any]]
    notes: List[str] = field(default_factory=list)


def build_weekly_summary(principal: Principal, end: datetime) -> WeeklySummary:
    require_permission(principal, Permission.VIEW_REPORTS, action="report.weekly")
    start = end - timedelta(days=7)
    s, e = to_iso(start), to_iso(end)
    with database_service.session() as conn:
        rows = [dict(r) for r in conn.execute(
            f"SELECT a.*, {IS_REPLAY_ALERT} AS is_replay FROM alerts a WHERE a.created_at >= ? AND a.created_at < ?",
            (s, e))]
        incidents = [dict(r) for r in conn.execute(
            "SELECT i.id, i.title, i.classification, i.status, i.window_start, i.created_at, "
            "(SELECT COUNT(*) FROM incident_alerts ia WHERE ia.incident_id = i.id) AS alerts, "
            "(SELECT a.severity FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id WHERE ia.incident_id = i.id "
            " ORDER BY CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END "
            " LIMIT 1) AS severity FROM incidents i WHERE i.is_replay = 0 AND i.created_at >= ? AND i.created_at < ?",
            (s, e))]
        predictions = [dict(r) for r in conn.execute(
            "SELECT timestamp, interface_name, forecast_horizon_seconds, predicted_utilization_ratio, "
            "predicted_throughput_bps, congestion_risk FROM congestion_predictions WHERE timestamp >= ? "
            "AND timestamp < ? AND source_name != ?", (s, e, REPLAY_SOURCE_NAME))]
        measurements = [dict(r) for r in conn.execute(
            "SELECT timestamp, interface_name, utilization_ratio, throughput_bps FROM network_metrics "
            "WHERE timestamp >= ? AND timestamp < ? AND COALESCE(session_id IN (SELECT id FROM monitoring_sessions "
            "WHERE source_type = 'replay'), 0) = 0", (s, to_iso(end + timedelta(days=1))))]
    real = [r for r in rows if not r["is_replay"]]
    for r in real:
        r["evidence"] = json.loads(r["evidence_json"]) if r["evidence_json"] else {}
    active = [r for r in real if r["suppressed_by_rule"] is None]

    def count(items, key):
        out: Dict[str, int] = {}
        for item in items:
            out[str(item[key])] = out.get(str(item[key]), 0) + 1
        return out

    incidents.sort(key=lambda i: (-rank(i["severity"]), -i["alerts"], i["id"]))
    summary = WeeklySummary(
        start=s, end=e, generated_at=utc_now_iso(), generated_by=principal.email,
        alerts_by_type=count(active, "alert_type"), alerts_by_severity=count(active, "severity"),
        suppressed_alerts=len(real) - len(active), replay_alerts_left_out=len(rows) - len(real),
        top_incidents=incidents[:5], risky_hosts=host_risk_from_alerts(active),
        congestion_alerts=[{"When": r["created_at"], "Severity": r["severity"], "Category": r["category"],
                            "Link": r["evidence"].get("interface"), "Status": r["status"]}
                           for r in active if r["alert_type"] in ("congestion", "performance")][:20],
        forecasts_by_risk=count(predictions, "congestion_risk"),
        accuracy=forecast_accuracy(predictions, measurements))
    summary.notes.append("Alerts and incidents are counted by when Smart Shield raised them; forecasts by the network "
                         "time they were made for.")
    if summary.replay_alerts_left_out:
        summary.notes.append(f"{summary.replay_alerts_left_out:,} DATASET REPLAY alert(s) were left out: replays are "
                             "not network activity.")
    if summary.suppressed_alerts:
        summary.notes.append(f"{summary.suppressed_alerts:,} alert(s) were suppressed by rules and are not counted "
                             "above; they are still stored.")
    summary.notes.append("Host risk here = 40/20/8/3 points per critical/high/medium/low alert naming the host this "
                         "week (alerts only; the Network Map score also uses flows).")
    audit_service.record_standalone(user_id=principal.user_id, action="report.weekly", outcome="success",
                                    details={"start": s, "end": e})
    return summary


def weekly_summary_html(summary: WeeklySummary) -> str:
    def counts(d: Dict[str, int]) -> str:
        return ", ".join(f"{k}: {v}" for k, v in sorted(d.items())) or "none"

    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        f"<title>{escape('Smart Shield weekly summary ' + summary.start[:10] + ' to ' + summary.end[:10])}</title>",
        f"{_STYLE}</head><body><h1>Weekly summary</h1>",
        f"<div class='meta'>{escape(summary.start)} → {escape(summary.end)} (UTC) · generated "
        f"{escape(summary.generated_at)} by {escape(summary.generated_by)}</div>",
    ]
    parts += [f"<div class='note'>{escape(n)}</div>" for n in summary.notes]
    parts.append("<h2>Alerts</h2>" + _table([{"By type": counts(summary.alerts_by_type),
                                               "By severity": counts(summary.alerts_by_severity),
                                               "Suppressed (not counted)": summary.suppressed_alerts}]))
    parts.append("<h2>Top incidents</h2>" + _table(
        [{"Incident": f"#{i['id']}", "Title": i["title"], "Severity": i["severity"], "Classification":
          i["classification"] + (" (not an attack)" if i["classification"] == "performance" else ""),
          "Alerts": i["alerts"], "Status": i["status"]} for i in summary.top_incidents], "No incidents this week."))
    parts.append("<h2>Riskiest hosts</h2>" + _table(
        [{"Host": h["host"], "Score": h["score"], "Alerts": h["alerts"], "Worst severity": h["worst"]}
         for h in summary.risky_hosts], "No alerts named a host this week."))
    parts.append("<h2>Congestion</h2><p>Forecasts by risk: " + escape(counts(summary.forecasts_by_risk)) + "</p>"
                 + _table(summary.congestion_alerts, "No congestion alerts this week."))
    parts.append("<h2>Forecast accuracy</h2>" + _table(
        [{"Horizon (min)": a["horizon_minutes"], "Forecasts": a["forecasts"], "With a matching measurement":
          a["matched"], "Compared quantity": a["quantity"], "Mean absolute error": a["mae"]} for a in summary.accuracy],
        "No forecasts were stored this week."))
    parts.append(f"<p class='meta'>A forecast is matched to the stored measurement of the same link closest to its "
                 f"target time, within {FORECAST_TOLERANCE_SECONDS} s. Unmatched forecasts are counted, not scored.</p>")
    parts.append("</body></html>")
    return "".join(parts)
