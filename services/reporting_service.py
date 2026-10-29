"""Reports built only from persisted data, for a chosen period.

Exports
* CSV per section. Cells that a spreadsheet would treat as a formula
  (starting with = + - @ tab or CR) are prefixed with an apostrophe
  (CSV/formula injection), since alert reasons, notes and dataset names can
  contain user-supplied text.
* One self-contained HTML report (inline CSS, every value HTML-escaped, no
  scripts) that can be printed to PDF from the browser.
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime
from html import escape
from typing import Any, Dict, List

from services import audit_service, database_service
from services.authorization import Permission, Principal, require_permission
from services.timeutil import to_iso, utc_now_iso

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


@dataclass
class Report:
    start: str
    end: str
    generated_at: str
    generated_by: str
    summary: Dict[str, Any]
    sections: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


def _rows(conn, sql: str, params: tuple) -> List[Dict[str, Any]]:
    return [dict(r) for r in conn.execute(sql, params)]


def build_report(principal: Principal, start: datetime, end: datetime) -> Report:
    require_permission(principal, Permission.VIEW_REPORTS, action="report.generate")
    if end <= start:
        raise ValueError("The report end must be after its start.")
    s, e = to_iso(start), to_iso(end)
    p = (s, e)
    with database_service.session() as conn:
        alerts = _rows(conn, "SELECT id, created_at, alert_type, severity, category, status, model_version, reason "
                             "FROM alerts WHERE created_at >= ? AND created_at < ? ORDER BY created_at", p)
        incidents = _rows(conn, "SELECT id, created_at, classification, status, title, window_start, window_end, "
                                "(SELECT COUNT(*) FROM incident_alerts ia WHERE ia.incident_id = i.id) AS alerts "
                                "FROM incidents i WHERE created_at >= ? AND created_at < ? ORDER BY created_at", p)
        sessions = _rows(conn, "SELECT s.id, s.source_type, s.interface_name, s.started_at, s.ended_at, s.status, "
                               "(SELECT COUNT(*) FROM network_metrics m WHERE m.session_id = s.id) AS measurements, "
                               "(SELECT COUNT(*) FROM network_flows f WHERE f.session_id = s.id) AS flows "
                               "FROM monitoring_sessions s WHERE s.started_at >= ? AND s.started_at < ? "
                               "ORDER BY s.started_at", p)
        traffic = _rows(conn, "SELECT interface_name, COUNT(*) AS samples, AVG(throughput_bps) AS mean_throughput_bps, "
                              "MAX(throughput_bps) AS peak_throughput_bps, MAX(utilization_ratio) AS peak_utilization, "
                              "AVG(latency_ms) AS mean_latency_ms, MIN(timestamp) AS first_sample, "
                              "MAX(timestamp) AS last_sample FROM network_metrics "
                              "WHERE timestamp >= ? AND timestamp < ? GROUP BY interface_name ORDER BY interface_name", p)
        forecasts = _rows(conn, "SELECT timestamp, interface_name, forecast_horizon_seconds, "
                                "predicted_utilization_ratio, predicted_throughput_bps, congestion_risk, model_version "
                                "FROM congestion_predictions WHERE timestamp >= ? AND timestamp < ? ORDER BY timestamp", p)
        recommendations = _rows(conn, "SELECT id, timestamp, interface_name, capacity_bps, unmet_demand_bps, status "
                                      "FROM bandwidth_recommendations WHERE timestamp >= ? AND timestamp < ? "
                                      "ORDER BY timestamp", p)
        actions = _rows(conn, "SELECT executed_at, action_type, target_interface, status, recommendation_id, "
                              "error_message FROM policy_actions WHERE executed_at >= ? AND executed_at < ? "
                              "ORDER BY executed_at", p)
        models = _rows(conn, "SELECT id, model_family, model_name, version, trained_at, is_active, metrics_json, "
                             "training_metadata_json FROM model_registry ORDER BY model_family, trained_at", ())
    model_rows = []
    for m in models:
        metrics = json.loads(m.pop("metrics_json") or "{}")
        meta = json.loads(m.pop("training_metadata_json") or "{}")
        test = metrics.get("test") or {}
        summary = metrics.get("summary") or {}
        m.update({
            "is_active": bool(m["is_active"]),
            "test_f1": test.get("f1"), "test_false_positive_rate": test.get("false_positive_rate"),
            "test_mae_by_horizon": "; ".join(f"{k}: {v['test']['mae']:.4g}" for k, v in summary.items()) or None,
            "trained_on": ", ".join(d.get("name", "") for d in meta.get("datasets", [])) or
                          (f"session #{meta['session_id']}" if meta.get("session_id") else None),
            "split": meta.get("split") or ("chronological" if meta.get("split_periods") else None),
        })
        model_rows.append(m)

    def count(rows, key):
        out: Dict[str, int] = {}
        for r in rows:
            out[str(r[key])] = out.get(str(r[key]), 0) + 1
        return out

    report = Report(
        start=s, end=e, generated_at=utc_now_iso(), generated_by=principal.email,
        summary={
            "alerts_by_type": count(alerts, "alert_type"), "alerts_by_severity": count(alerts, "severity"),
            "alerts_by_status": count(alerts, "status"), "incidents_by_classification": count(incidents, "classification"),
            "monitoring_sessions": len(sessions), "forecasts": len(forecasts),
            "forecasts_by_risk": count(forecasts, "congestion_risk"), "recommendations": len(recommendations),
            "enforcement_actions": len(actions), "active_models": sum(1 for m in model_rows if m["is_active"]),
        },
        sections={
            "alerts": alerts, "incidents": incidents, "monitoring_sessions": sessions, "traffic_by_interface": traffic,
            "forecasts": forecasts, "bandwidth_recommendations": recommendations, "enforcement_actions": actions,
            "models": model_rows,
        },
    )
    report.notes.append("Every figure comes from data stored in Smart Shield for this period; nothing is estimated "
                        "or simulated. Forecasts are model predictions, not measurements.")
    if not traffic:
        report.notes.append("No traffic measurements were stored in this period, so traffic statistics are unavailable.")
    report.notes.append("Alerts and incidents are included by the time they were raised in Smart Shield; traffic and "
                        "forecasts by the network time they describe.")
    report.notes.append("The model registry lists every model, whatever its training date, with its held-out test metrics.")
    with database_service.session(write=True) as conn:
        audit_service.record(conn, user_id=principal.user_id, action="report.generate",
                             details={"start": s, "end": e, "alerts": len(alerts), "incidents": len(incidents)})
    return report


def safe_cell(value: Any) -> Any:
    """Neutralise spreadsheet formulas in exported text."""
    if isinstance(value, str) and value.startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def to_csv(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return ""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]))
    writer.writeheader()
    for row in rows:
        writer.writerow({k: safe_cell(v) for k, v in row.items()})
    return buffer.getvalue()


SECTION_TITLES = {
    "traffic_by_interface": "Traffic by interface (measured / derived)",
    "alerts": "Alerts",
    "incidents": "Incidents",
    "forecasts": "Congestion forecasts (predicted)",
    "bandwidth_recommendations": "Bandwidth recommendations",
    "enforcement_actions": "Enforcement actions",
    "monitoring_sessions": "Monitoring sessions",
    "models": "Model registry",
}


def _cell_html(value: Any) -> str:
    if value is None:
        return "<span class='na'>unavailable</span>"
    if isinstance(value, float):
        return escape(f"{value:,.4g}")
    return escape(str(value))


def to_html(report: Report, max_rows: int = 500) -> str:
    """Self-contained, script-free HTML. Every value is escaped."""
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        f"<title>{escape('Smart Shield report ' + report.start[:10] + ' to ' + report.end[:10])}</title>",
        "<style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:32px;color:#111827}"
        "h1{margin:0 0 4px}h2{margin-top:32px;border-bottom:2px solid #3B82F6;padding-bottom:4px}"
        ".meta{color:#4B5563}table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}"
        "th,td{border:1px solid #D1D5DB;padding:4px 6px;text-align:left;vertical-align:top}"
        "th{background:#F3F4F6}.na{color:#9CA3AF;font-style:italic}.note{background:#EFF6FF;padding:8px 12px;"
        "border-left:4px solid #3B82F6;margin:4px 0}@media print{body{margin:12px}}</style></head><body>",
        "<h1>Smart Shield report</h1>",
        f"<div class='meta'>Period {escape(report.start)} → {escape(report.end)} (UTC) · generated "
        f"{escape(report.generated_at)} by {escape(report.generated_by)}</div>",
    ]
    for note in report.notes:
        parts.append(f"<div class='note'>{escape(note)}</div>")
    parts.append("<h2>Summary</h2><table>")
    for key, value in report.summary.items():
        shown = ", ".join(f"{k}: {v}" for k, v in value.items()) if isinstance(value, dict) else value
        parts.append(f"<tr><th>{escape(key.replace('_', ' '))}</th><td>{_cell_html(shown if shown != '' else 'none')}</td></tr>")
    parts.append("</table>")
    for key, title in SECTION_TITLES.items():
        rows = report.sections.get(key, [])
        parts.append(f"<h2>{escape(title)} ({len(rows)})</h2>")
        if not rows:
            parts.append("<p class='na'>No records in this period.</p>")
            continue
        columns = list(rows[0])
        parts.append("<table><tr>" + "".join(f"<th>{escape(c.replace('_', ' '))}</th>" for c in columns) + "</tr>")
        for row in rows[:max_rows]:
            parts.append("<tr>" + "".join(f"<td>{_cell_html(row[c])}</td>" for c in columns) + "</tr>")
        parts.append("</table>")
        if len(rows) > max_rows:
            parts.append(f"<p class='na'>Showing the first {max_rows} of {len(rows)} rows; the CSV export has all.</p>")
    parts.append("</body></html>")
    return "".join(parts)
