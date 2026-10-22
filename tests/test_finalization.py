from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from config import PROJECT_ROOT
from scripts import manage
from services import (
    alert_service, auth_service, database_service, reporting_service, retention_service, settings_service,
)
from services.authorization import PermissionDenied
from tests.conftest import STRONG_PASSWORD, audit_rows

NEW_PASSWORD = "BrandNewPass77"


# ------------------------------------------------------------- passwords

def test_change_password_success_and_old_password_stops_working(analyst):
    auth_service.change_password(analyst, STRONG_PASSWORD, NEW_PASSWORD)
    assert auth_service.login("alan@example.com", NEW_PASSWORD).id == analyst.user_id
    with pytest.raises(auth_service.LoginError):
        auth_service.login("alan@example.com", STRONG_PASSWORD)
    assert len(audit_rows("auth.change_password", "success")) == 1


@pytest.mark.parametrize("current, new, message", [
    ("WrongCurrent99", NEW_PASSWORD, "current password is incorrect"),
    (STRONG_PASSWORD, "weak", "must contain"),
    (STRONG_PASSWORD, STRONG_PASSWORD, "different"),
])
def test_change_password_rejections(analyst, current, new, message):
    with pytest.raises(auth_service.AuthError, match=message):
        auth_service.change_password(analyst, current, new)


def test_wrong_current_password_counts_toward_lockout(analyst):
    for _ in range(5):
        with pytest.raises(auth_service.AuthError):
            auth_service.change_password(analyst, "WrongCurrent99", NEW_PASSWORD)
    with pytest.raises(auth_service.AccountLockedError):
        auth_service.change_password(analyst, STRONG_PASSWORD, NEW_PASSWORD)


def test_cli_reset_password_clears_lockout(analyst_user):
    for _ in range(5):
        with pytest.raises(auth_service.LoginError):
            auth_service.login("alan@example.com", "WrongPassword9")
    args = manage.build_parser().parse_args(["reset-password", "--email", "alan@example.com"])
    secrets = iter([NEW_PASSWORD, NEW_PASSWORD])
    assert manage.cmd_reset_password(args, secret=lambda _: next(secrets)) == 0
    assert auth_service.login("alan@example.com", NEW_PASSWORD).id == analyst_user.id
    assert len(audit_rows("cli.reset_password", "success")) == 1


# --------------------------------------------------------------- reports

def _alert(reason, created_offset_days=0, status="open", key="k"):
    with database_service.session(write=True) as conn:
        alert_id = alert_service.create_alert(conn, alert_type="security", severity="high", category="DDoS",
                                              reason=reason, evidence={"flows": 1}, dedup_key=key)
        created = datetime.now(timezone.utc) - timedelta(days=created_offset_days)
        conn.execute("UPDATE alerts SET created_at = ?, status = ? WHERE id = ?", (created.isoformat(), status, alert_id))
    return alert_id


def test_report_counts_only_persisted_data_in_period(analyst):
    _alert("recent", key="a")
    _alert("old", created_offset_days=100, key="b")
    now = datetime.now(timezone.utc)
    report = reporting_service.build_report(analyst, now - timedelta(days=7), now + timedelta(days=1))
    assert report.summary["alerts_by_type"] == {"security": 1}
    assert [a["reason"] for a in report.sections["alerts"]] == ["recent"]
    assert any("unavailable" in n for n in report.notes)  # no traffic stored
    assert len(audit_rows("report.generate", "success")) == 1
    with pytest.raises(PermissionDenied):
        reporting_service.build_report(None, now - timedelta(days=1), now)


def test_csv_export_neutralises_formulas():
    csv_text = reporting_service.to_csv([{"reason": "=HYPERLINK(\"http://evil\")", "n": 1}, {"reason": "+1-1", "n": -5}])
    assert "'=HYPERLINK" in csv_text and "'+1-1" in csv_text
    assert ",-5" in csv_text  # numbers are untouched


def test_html_report_escapes_everything(analyst):
    _alert("<script>alert('x')</script>", key="x")
    now = datetime.now(timezone.utc)
    html = reporting_service.to_html(reporting_service.build_report(analyst, now - timedelta(days=1), now + timedelta(days=1)))
    assert "<script>" not in html and "&lt;script&gt;" in html


# ------------------------------------------------------------- retention

def test_retention_is_off_by_default(admin):
    assert not settings_service.get_retention_settings().enabled
    with pytest.raises(retention_service.RetentionError, match="disabled"):
        retention_service.apply(admin)
    assert retention_service.preview(admin).dry_run  # preview works while disabled


def test_retention_deletes_only_old_closed_data(admin, analyst):
    from services import incident_correlation_service as correlation

    old_resolved = _alert("old resolved", created_offset_days=400, status="resolved", key="r1")
    old_open = _alert("old open", created_offset_days=400, status="open", key="r2")
    linked = _alert("linked to open incident", created_offset_days=400, status="open", key="r3")
    correlation.correlate(analyst)  # puts open alerts into an open incident
    with database_service.session(write=True) as conn:
        conn.execute("UPDATE alerts SET status = 'resolved' WHERE id = ?", (linked,))
    settings_service.update_retention_settings(admin, settings_service.RetentionSettings(enabled=True))
    preview = retention_service.preview(admin)
    assert preview.counts["closed_alerts"] == 1
    result = retention_service.apply(admin)
    assert result.counts["closed_alerts"] == 1
    remaining = {a.id for a in alert_service.list_alerts(admin)}
    assert old_resolved not in remaining and {old_open, linked} <= remaining
    assert len(audit_rows("retention.apply", "success")) == 1


def test_retention_needs_admin_and_keeps_a_year_of_audit_logs(analyst, admin):
    with pytest.raises(PermissionDenied):
        retention_service.preview(analyst)
    with pytest.raises(settings_service.SettingsError, match="at least 365"):
        settings_service.update_retention_settings(admin, settings_service.RetentionSettings(enabled=True, audit_days=30))


def test_cli_retention_dry_run(capsys):
    assert manage.main(["apply-retention", "--dry-run"]) == 0
    assert "Would delete" in capsys.readouterr().out
    assert manage.main(["apply-retention"]) == 1  # disabled by default


# ------------------------------------------------------------ hardening

def test_streamlit_config_hides_error_details_and_keeps_xsrf():
    config = (PROJECT_ROOT / ".streamlit" / "config.toml").read_text()
    assert 'showErrorDetails = "none"' in config
    assert "enableXsrfProtection = true" in config


def test_gitignore_keeps_secrets_and_data_out_of_git():
    ignored = (PROJECT_ROOT / ".gitignore").read_text()
    for pattern in (".env", "*.db", "artifacts/*", "data/*", ".streamlit/secrets.toml"):
        assert pattern in ignored
