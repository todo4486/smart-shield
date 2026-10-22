"""Network health summary: plain-language statements computed only from persisted data.

Each statement has a level (ok / warn / critical / info) and says where its
facts came from. Nothing is inferred beyond what the stored rows show.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from services import database_service
from services.authorization import Permission, Principal, require_permission
from services.timeutil import parse_iso, utc_now


@dataclass(frozen=True)
class Statement:
    level: str  # ok | info | warn | critical
    text: str
    source: str


def summarize(principal: Principal) -> List[Statement]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="dashboard.view")
    out: List[Statement] = []
    with database_service.session() as conn:
        alerts = {r["severity"]: r["n"] for r in conn.execute(
            "SELECT severity, COUNT(*) AS n FROM alerts WHERE status IN ('open', 'acknowledged') GROUP BY severity")}
        by_type = {r["alert_type"]: r["n"] for r in conn.execute(
            "SELECT alert_type, COUNT(*) AS n FROM alerts WHERE status IN ('open', 'acknowledged') GROUP BY alert_type")}
        incidents = {r["classification"]: r["n"] for r in conn.execute(
            "SELECT classification, COUNT(*) AS n FROM incidents WHERE status IN ('open', 'investigating') "
            "GROUP BY classification")}
        unlinked = conn.execute(
            "SELECT COUNT(*) FROM alerts a WHERE a.status IN ('open', 'acknowledged') AND NOT EXISTS "
            "(SELECT 1 FROM incident_alerts ia WHERE ia.alert_id = a.id)").fetchone()[0]
        risks = conn.execute(
            "SELECT p.interface_name, p.congestion_risk, p.timestamp FROM congestion_predictions p "
            "WHERE p.id = (SELECT p2.id FROM congestion_predictions p2 WHERE "
            "COALESCE(p2.interface_name, '') = COALESCE(p.interface_name, '') "
            "ORDER BY p2.timestamp DESC, p2.forecast_horizon_seconds DESC, p2.id DESC LIMIT 1) "
            "ORDER BY p.interface_name").fetchall()
        models = {r["model_family"]: r["version"] for r in conn.execute(
            "SELECT model_family, version FROM model_registry WHERE is_active = 1")}
        latest_metric = conn.execute("SELECT MAX(timestamp) FROM network_metrics").fetchone()[0]
        live = conn.execute("SELECT COUNT(*) FROM monitoring_sessions WHERE status = 'RUNNING' "
                            "AND source_type = 'live_capture'").fetchone()[0]

    critical = alerts.get("critical", 0) + alerts.get("high", 0)
    total = sum(alerts.values())
    if total == 0:
        out.append(Statement("ok", "No unresolved alerts.", "alerts"))
    else:
        level = "critical" if alerts.get("critical") else "warn" if critical else "info"
        parts = ", ".join(f"{n} {t}" for t, n in sorted(by_type.items()))
        out.append(Statement(level, f"{total} unresolved alert(s) ({parts}); {critical} high or critical.", "alerts"))
    if incidents:
        parts = ", ".join(f"{n} {c}" for c, n in sorted(incidents.items()))
        level = "warn" if incidents.get("combined") or incidents.get("security") else "info"
        out.append(Statement(level, f"Open incidents: {parts}.", "incidents"))
    if unlinked:
        out.append(Statement("info", f"{unlinked} unresolved alert(s) are not yet grouped into incidents. Run "
                                     "correlation in the Incident Center.", "alerts"))
    for row in risks:
        level = {"critical": "critical", "high": "warn", "elevated": "info"}.get(row["congestion_risk"], "ok")
        out.append(Statement(level, f"Latest congestion forecast for {row['interface_name'] or 'all interfaces'}: "
                                    f"{row['congestion_risk']} risk (predicted, data up to "
                                    f"{row['timestamp'][:16].replace('T', ' ')} UTC).", "PredictNet forecasts"))
    missing = [label for family, label in (("intrusion_classifier", "intrusion classifier"),
                                           ("congestion_forecaster", "congestion forecaster")) if family not in models]
    if missing:
        out.append(Statement("info", "No active " + " or ".join(missing) + ".", "model registry"))
    if latest_metric:
        age = utc_now() - parse_iso(latest_metric)
        hours = age.total_seconds() / 3600
        freshness = f"{hours:,.0f} hours" if hours < 72 else f"{hours / 24:,.0f} days"
        out.append(Statement("info", f"Newest stored measurement is {freshness} old"
                                     + ("" if live else ": data comes from imports, not live capture") + ".",
                             "telemetry"))
    return out
