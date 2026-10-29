"""Validated application settings stored in app_settings (JSON values).

Defaults are documented starting points, not universal network standards.
Only administrators can change them; every change is audited with before/after.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, List

from services import audit_service, database_service
from services.authorization import Permission, Principal, require_permission
from services.timeutil import utc_now_iso


class SettingsError(ValueError):
    pass


@dataclass(frozen=True)
class PredictNetSettings:
    elevated_threshold: float = 0.60
    high_threshold: float = 0.75
    critical_threshold: float = 0.90
    horizons_minutes: tuple = (1, 5, 15)
    alert_cooldown_minutes: int = 30
    rapid_rise_per_hour: float = 0.20  # utilization ratio gained per hour that counts as a rapid rise
    sustained_high_samples: int = 3
    min_training_samples: int = 200

    def validate(self) -> "PredictNetSettings":
        e, h, c = self.elevated_threshold, self.high_threshold, self.critical_threshold
        if not 0 < e < h < c <= 1:
            raise SettingsError("Thresholds must increase: 0 < elevated < high < critical ≤ 100%.")
        horizons = tuple(sorted({int(m) for m in self.horizons_minutes}))
        if not horizons or len(horizons) > 6 or not all(1 <= m <= 1440 for m in horizons):
            raise SettingsError("Choose 1–6 forecast horizons between 1 and 1440 minutes.")
        if not 1 <= int(self.alert_cooldown_minutes) <= 1440:
            raise SettingsError("Alert cooldown must be between 1 and 1440 minutes.")
        if not 0.01 <= float(self.rapid_rise_per_hour) <= 1:
            raise SettingsError("Rapid-rise rate must be between 1% and 100% per hour.")
        if not 1 <= int(self.sustained_high_samples) <= 100:
            raise SettingsError("Sustained-high sample count must be between 1 and 100.")
        if not 50 <= int(self.min_training_samples) <= 100_000:
            raise SettingsError("Minimum training samples must be between 50 and 100,000.")
        return PredictNetSettings(float(e), float(h), float(c), horizons, int(self.alert_cooldown_minutes),
                                  float(self.rapid_rise_per_hour), int(self.sustained_high_samples),
                                  int(self.min_training_samples))

    def thresholds(self) -> Dict[str, float]:
        return {"elevated": self.elevated_threshold, "high": self.high_threshold, "critical": self.critical_threshold}


PREDICTNET_KEY = "predictnet.settings"


def get_predictnet_settings() -> PredictNetSettings:
    """Internal read used by services (no principal needed: settings are not sensitive)."""
    with database_service.session() as conn:
        row = conn.execute("SELECT value_json FROM app_settings WHERE key = ?", (PREDICTNET_KEY,)).fetchone()
    if row is None:
        return PredictNetSettings()
    stored = json.loads(row["value_json"])
    stored["horizons_minutes"] = tuple(stored.get("horizons_minutes", PredictNetSettings.horizons_minutes))
    return PredictNetSettings(**{k: v for k, v in stored.items() if k in PredictNetSettings.__dataclass_fields__}).validate()


def settings_source() -> str:
    with database_service.session() as conn:
        row = conn.execute("SELECT updated_at FROM app_settings WHERE key = ?", (PREDICTNET_KEY,)).fetchone()
    return "configured" if row else "default"


def update_predictnet_settings(principal: Principal, new: PredictNetSettings) -> PredictNetSettings:
    require_permission(principal, Permission.MANAGE_SETTINGS, action="settings.update", details={"key": PREDICTNET_KEY})
    validated = new.validate()
    before = get_predictnet_settings()
    value = asdict(validated)
    value["horizons_minutes"] = list(validated.horizons_minutes)
    with database_service.session(write=True) as conn:
        conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at, "
            "updated_by = excluded.updated_by",
            (PREDICTNET_KEY, json.dumps(value, sort_keys=True), utc_now_iso(), principal.user_id),
        )
        audit_service.record(conn, user_id=principal.user_id, action="settings.update",
                             details={"key": PREDICTNET_KEY, "before": _diffable(before), "after": value})
    return validated


def _diffable(settings: PredictNetSettings) -> Dict[str, Any]:
    value = asdict(settings)
    value["horizons_minutes"] = list(settings.horizons_minutes)
    return value


def risk_level(utilization: float, settings: PredictNetSettings) -> str:
    if utilization >= settings.critical_threshold:
        return "critical"
    if utilization >= settings.high_threshold:
        return "high"
    if utilization >= settings.elevated_threshold:
        return "elevated"
    return "normal"


RISK_ORDER: List[str] = ["normal", "elevated", "high", "critical"]


# ------------------------------------------------------------ monitoring

@dataclass(frozen=True)
class MonitoringSettings:
    """Which interfaces may be monitored, and optional measurements. Nothing is allowed by default."""

    allowed_interfaces: tuple = ()
    latency_target: str = ""  # "host:port" for a TCP connect-time probe; empty = latency unavailable
    default_interval_seconds: int = 5
    max_flows_per_session: int = 100_000

    def validate(self) -> "MonitoringSettings":
        import re

        from services.interface_counters import validate_latency_target

        names = tuple(sorted({str(i).strip() for i in self.allowed_interfaces if str(i).strip()}))
        if any(not re.match(r"^[A-Za-z0-9_.:\-]{1,32}$", n) for n in names):
            raise SettingsError("Interface names contain unsupported characters.")
        try:
            validate_latency_target(self.latency_target or None)
        except ValueError as exc:
            raise SettingsError(str(exc)) from exc
        if not 1 <= int(self.default_interval_seconds) <= 60:
            raise SettingsError("Sampling interval must be between 1 and 60 seconds.")
        if not 1_000 <= int(self.max_flows_per_session) <= 1_000_000:
            raise SettingsError("Flow storage limit must be between 1,000 and 1,000,000 per session.")
        return MonitoringSettings(names, (self.latency_target or "").strip(), int(self.default_interval_seconds),
                                  int(self.max_flows_per_session))


MONITORING_KEY = "monitoring.settings"


def get_monitoring_settings() -> MonitoringSettings:
    with database_service.session() as conn:
        row = conn.execute("SELECT value_json FROM app_settings WHERE key = ?", (MONITORING_KEY,)).fetchone()
    if row is None:
        return MonitoringSettings()
    stored = json.loads(row["value_json"])
    stored["allowed_interfaces"] = tuple(stored.get("allowed_interfaces", ()))
    return MonitoringSettings(**{k: v for k, v in stored.items() if k in MonitoringSettings.__dataclass_fields__}).validate()


def update_monitoring_settings(principal: Principal, new: MonitoringSettings) -> MonitoringSettings:
    require_permission(principal, Permission.MANAGE_SETTINGS, action="settings.update", details={"key": MONITORING_KEY})
    validated = new.validate()
    before = asdict(get_monitoring_settings())
    value = asdict(validated)
    value["allowed_interfaces"] = list(validated.allowed_interfaces)
    before["allowed_interfaces"] = list(before["allowed_interfaces"])
    with database_service.session(write=True) as conn:
        conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at, "
            "updated_by = excluded.updated_by",
            (MONITORING_KEY, json.dumps(value, sort_keys=True), utc_now_iso(), principal.user_id),
        )
        audit_service.record(conn, user_id=principal.user_id, action="settings.update",
                             details={"key": MONITORING_KEY, "before": before, "after": value})
    return validated


# ------------------------------------------------------------- retention

MIN_AUDIT_RETENTION_DAYS = 365


@dataclass(frozen=True)
class RetentionSettings:
    """How long data is kept. Off by default: nothing is ever deleted until an admin enables it."""

    enabled: bool = False
    metrics_days: int = 365
    flows_days: int = 90
    predictions_days: int = 365
    closed_alerts_days: int = 365
    closed_incidents_days: int = 365
    login_attempts_days: int = 30
    audit_days: int = 730

    def validate(self) -> "RetentionSettings":
        values = asdict(self)
        for key, days in values.items():
            if key != "enabled" and not 1 <= int(days) <= 3650:
                raise SettingsError(f"{key.replace('_', ' ')} must be between 1 and 3650 days.")
        if int(self.audit_days) < MIN_AUDIT_RETENTION_DAYS:
            raise SettingsError(f"Audit logs must be kept for at least {MIN_AUDIT_RETENTION_DAYS} days.")
        return RetentionSettings(bool(self.enabled), *(int(values[k]) for k in list(values)[1:]))


RETENTION_KEY = "retention.settings"


def get_retention_settings() -> RetentionSettings:
    with database_service.session() as conn:
        row = conn.execute("SELECT value_json FROM app_settings WHERE key = ?", (RETENTION_KEY,)).fetchone()
    if row is None:
        return RetentionSettings()
    stored = json.loads(row["value_json"])
    return RetentionSettings(**{k: v for k, v in stored.items() if k in RetentionSettings.__dataclass_fields__}).validate()


def update_retention_settings(principal: Principal, new: RetentionSettings) -> RetentionSettings:
    require_permission(principal, Permission.MANAGE_SETTINGS, action="settings.update", details={"key": RETENTION_KEY})
    validated = new.validate()
    before = asdict(get_retention_settings())
    with database_service.session(write=True) as conn:
        conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at, "
            "updated_by = excluded.updated_by",
            (RETENTION_KEY, json.dumps(asdict(validated), sort_keys=True), utc_now_iso(), principal.user_id),
        )
        audit_service.record(conn, user_id=principal.user_id, action="settings.update",
                             details={"key": RETENTION_KEY, "before": before, "after": asdict(validated)})
    return validated


# ------------------------------------------------------------ model health

@dataclass(frozen=True)
class DriftSettings:
    """When the Model health page warns about feature drift. Read-only checks: nothing is retrained."""

    psi_threshold: float = 0.25
    top_features: int = 10

    def validate(self) -> "DriftSettings":
        if not 0.05 <= float(self.psi_threshold) <= 2.0:
            raise SettingsError("The PSI warning threshold must be between 0.05 and 2.0.")
        if not 3 <= int(self.top_features) <= 50:
            raise SettingsError("Check between 3 and 50 top features.")
        return DriftSettings(float(self.psi_threshold), int(self.top_features))


DRIFT_KEY = "model_health.drift"


def get_drift_settings() -> DriftSettings:
    with database_service.session() as conn:
        row = conn.execute("SELECT value_json FROM app_settings WHERE key = ?", (DRIFT_KEY,)).fetchone()
    if row is None:
        return DriftSettings()
    stored = json.loads(row["value_json"])
    return DriftSettings(**{k: v for k, v in stored.items() if k in DriftSettings.__dataclass_fields__}).validate()


def update_drift_settings(principal: Principal, new: DriftSettings) -> DriftSettings:
    require_permission(principal, Permission.MANAGE_SETTINGS, action="settings.update", details={"key": DRIFT_KEY})
    validated = new.validate()
    before = asdict(get_drift_settings())
    with database_service.session(write=True) as conn:
        conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at, "
            "updated_by = excluded.updated_by",
            (DRIFT_KEY, json.dumps(asdict(validated), sort_keys=True), utc_now_iso(), principal.user_id),
        )
        audit_service.record(conn, user_id=principal.user_id, action="settings.update",
                             details={"key": DRIFT_KEY, "before": before, "after": asdict(validated)})
    return validated
