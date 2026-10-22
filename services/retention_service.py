"""Data retention: delete data older than the configured ages (SPEC §11).

* Disabled by default. Nothing is deleted until an admin enables retention.
* Ages are measured from each row's own timestamp (network time for metrics,
  flows and forecasts; creation or update time for alerts and incidents).
  Imported historical data can therefore be "old" as soon as it is imported;
  the preview shows exactly what would go.
* Never deleted: open or acknowledged alerts, alerts linked to an open or
  investigating incident, open incidents, models, users, settings, policies.
* Audit logs are kept for at least 365 days. Every run, preview or real, is audited.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Dict, Optional

from services import audit_service, database_service, settings_service
from services.authorization import Permission, Principal, require_permission
from services.timeutil import to_iso, utc_now

RULES = {
    # name: (settings field, SQL with ? = cutoff)
    "network_metrics": ("metrics_days", "DELETE FROM network_metrics WHERE timestamp < ?"),
    "network_flows": ("flows_days", "DELETE FROM network_flows WHERE timestamp < ?"),
    "congestion_predictions": ("predictions_days", "DELETE FROM congestion_predictions WHERE timestamp < ?"),
    "closed_alerts": ("closed_alerts_days",
                      "DELETE FROM alerts WHERE status IN ('resolved', 'false_positive') AND created_at < ? "
                      "AND id NOT IN (SELECT ia.alert_id FROM incident_alerts ia JOIN incidents i ON i.id = ia.incident_id "
                      "WHERE i.status IN ('open', 'investigating'))"),
    "closed_incidents": ("closed_incidents_days",
                         "DELETE FROM incidents WHERE status IN ('resolved', 'closed') AND updated_at < ?"),
    "login_attempts": ("login_attempts_days", "DELETE FROM login_attempts WHERE attempted_at < ?"),
    "audit_logs": ("audit_days", "DELETE FROM audit_logs WHERE created_at < ?"),
}


class RetentionError(Exception):
    pass


@dataclass
class RetentionResult:
    dry_run: bool
    counts: Dict[str, int]
    cutoffs: Dict[str, str]


def _count_sql(delete_sql: str) -> str:
    return "SELECT COUNT(*) " + delete_sql[len("DELETE "):]


def run(*, dry_run: bool, actor_user_id: Optional[int], force: bool = False) -> RetentionResult:
    """Shared by the admin UI and the operator CLI. `force` runs a preview even when retention is disabled."""
    settings = settings_service.get_retention_settings()
    if not settings.enabled and not (dry_run and force):
        raise RetentionError("Data retention is disabled. Enable it in Administration → Data retention first.")
    now = utc_now()
    counts: Dict[str, int] = {}
    cutoffs: Dict[str, str] = {}
    with database_service.session(write=not dry_run) as conn:
        for name, (field, sql) in RULES.items():
            cutoff = to_iso(now - timedelta(days=getattr(settings, field)))
            cutoffs[name] = cutoff
            if dry_run:
                counts[name] = conn.execute(_count_sql(sql), (cutoff,)).fetchone()[0]
            else:
                counts[name] = conn.execute(sql, (cutoff,)).rowcount
        if not dry_run:
            audit_service.record(conn, user_id=actor_user_id, action="retention.apply",
                                 details={"deleted": counts, "cutoffs": cutoffs})
    if dry_run:
        audit_service.record_standalone(user_id=actor_user_id, action="retention.preview", outcome="success",
                                        details={"would_delete": counts})
    return RetentionResult(dry_run, counts, cutoffs)


def preview(principal: Principal) -> RetentionResult:
    require_permission(principal, Permission.DELETE_DATA, action="retention.preview")
    return run(dry_run=True, actor_user_id=principal.user_id, force=True)


def apply(principal: Principal) -> RetentionResult:
    require_permission(principal, Permission.DELETE_DATA, action="retention.apply")
    return run(dry_run=False, actor_user_id=principal.user_id)
