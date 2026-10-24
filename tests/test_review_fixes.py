"""Regression tests for the nine code-review findings (one section per finding)."""
from __future__ import annotations

import subprocess
import sys

import pytest

from components.ui import format_bits_rate, format_bytes_rate, format_ratio
from services import (
    auth_service, bandwidth_service, congestion_prediction_service, congestion_training_service, database_service,
    dataset_service, intrusion_training_service, session_service, telemetry_service, telemetry_view_service,
    traffic_shaping_service,
)
from services.congestion_training_service import ForecastTrainingOptions
from services.intrusion_training_service import IntrusionTrainingOptions, TrainingError
from services.telemetry_service import TelemetryImportOptions
from tests.conftest import STRONG_PASSWORD, audit_rows
from tests.synthetic import cic_like_frame, telemetry_csv, to_cic_csv

NEW_PASSWORD = "BrandNewPass77"


# 1. Training with too few rows of a class: clear TrainingError, not an sklearn crash.
def test_training_with_a_single_attack_row_fails_cleanly(analyst):
    frame = cic_like_frame(300, with_timestamp=False)
    frame["label"] = "BENIGN"
    frame.loc[frame.index[0], "label"] = "DDoS"
    dataset_id = dataset_service.register_intrusion_dataset(analyst, to_cic_csv(frame), "one.csv", "one").dataset_id
    with pytest.raises(TrainingError, match="Only 1 attack row"):
        intrusion_training_service.train_intrusion_models(
            analyst, IntrusionTrainingOptions(dataset_ids=(dataset_id,), n_estimators=10))
    assert len(audit_rows("model.train_intrusion", "failure")) == 1


# 2. Sign-in, sign-out and expiry wipe the tab's page state.
def test_logout_and_login_clear_previous_users_page_state(admin_user, analyst_user):
    state = {}
    session_service.start(state, admin_user)
    state["report"] = "admin-only report"
    state["retention_preview"] = "preview"
    session_service.logout(state)
    assert set(state) == {session_service.FLASH_KEY}
    state["report"] = "left over"
    session_service.start(state, analyst_user)
    assert "report" not in state and session_service.FLASH_KEY not in state


def test_idle_timeout_also_clears_page_state(admin_user):
    from datetime import timedelta

    from services.timeutil import utc_now

    state = {}
    session_service.start(state, admin_user, now=utc_now() - timedelta(hours=2))
    state["last_forecast_run"] = "old"
    assert session_service.resolve(state) is None
    assert "last_forecast_run" not in state and "expired" in state[session_service.FLASH_KEY]


# 3. A password change or reset signs out every other session.
def test_password_change_revokes_other_sessions_but_keeps_this_one(analyst_user):
    other_tab, this_tab = {}, {}
    session_service.start(other_tab, analyst_user)
    session_service.start(this_tab, analyst_user)
    auth_service.change_password(analyst_user.to_principal(), STRONG_PASSWORD, NEW_PASSWORD)
    session_service.refresh_epoch(this_tab)
    assert session_service.resolve(this_tab).user_id == analyst_user.id
    assert session_service.resolve(other_tab) is None
    assert "password was changed" in other_tab[session_service.FLASH_KEY]


def test_cli_password_reset_revokes_sessions(analyst_user):
    tab = {}
    session_service.start(tab, analyst_user)
    auth_service.reset_password_cli(analyst_user.email, NEW_PASSWORD)
    assert session_service.resolve(tab) is None


def test_login_rehash_does_not_revoke_sessions(analyst_user):
    """Only real password changes bump the epoch; an automatic rehash on login must not."""
    from argon2 import PasswordHasher

    tab = {}
    session_service.start(tab, analyst_user)
    with database_service.session(write=True) as conn:
        weak = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(STRONG_PASSWORD)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (weak, analyst_user.id))
    auth_service.login(analyst_user.email, STRONG_PASSWORD)
    assert session_service.resolve(tab) is not None


# 4. Formatters treat NaN / infinity as "no measurement".
@pytest.mark.parametrize("fmt", [format_bytes_rate, format_bits_rate, format_ratio])
def test_formatters_never_print_nan(fmt):
    assert fmt(float("nan")) is None and fmt(float("inf")) is None and fmt(None) is None
    assert fmt(0.5) is not None


# 5. Applying or rolling back a tc policy starts from a clean root.
class FakeTc:
    def __init__(self):
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        missing = argv[2] == "del"  # no previous root qdisc on a fresh interface
        return subprocess.CompletedProcess(argv, 2 if missing else 0, stdout="",
                                           stderr="Error: Cannot delete qdisc with handle of zero." if missing else "")


def test_tc_apply_deletes_old_root_first_and_tolerates_none(admin, monkeypatch):
    monkeypatch.setenv("SMART_SHIELD_TC_ENABLED", "true")
    monkeypatch.setenv("SMART_SHIELD_TC_INTERFACES", "eth0")
    monkeypatch.setenv("SMART_SHIELD_TC_BINARY", sys.executable)
    monkeypatch.setattr(traffic_shaping_service.platform, "system", lambda: "Linux")
    fake = FakeTc()
    traffic_shaping_service.set_runner_for_tests(fake)
    try:
        bandwidth_service.save_policy(admin, bandwidth_service.template_policy(1e8, name="p", interface="eth0"))
        rec = bandwidth_service.recommend(admin, "p", {"critical": 1e7})
        bandwidth_service.set_recommendation_status(admin, rec.id, "accepted")
        traffic_shaping_service.apply_recommendation(admin, rec.id, "eth0", confirm_interface="eth0")
    finally:
        traffic_shaping_service.set_runner_for_tests(None)
    assert fake.calls[0][1:] == ["qdisc", "del", "dev", "eth0", "root"]
    assert all(c[2] in ("del", "add") for c in fake.calls)  # never "replace", which keeps stale classes


# 6. "" means rows without an interface; None means all interfaces.
def test_unnamed_interface_is_not_all_interfaces(analyst):
    csv = (b"timestamp,interface_name,latency_ms\n"
           b"2026-10-01T00:00:00Z,eth0,1\n2026-10-01T00:05:00Z,eth0,2\n"
           b"2026-10-01T00:00:00Z,,50\n")
    session_id = telemetry_service.import_telemetry_csv(
        analyst, csv, "mixed.csv", TelemetryImportOptions(source_name="mixed")).session_id
    unnamed = telemetry_view_service.session_telemetry(analyst, session_id, "").metrics
    everything = telemetry_view_service.session_telemetry(analyst, session_id, None).metrics
    assert list(unnamed["latency_ms"]) == [50] and len(everything) == 3
    assert "" in telemetry_view_service.session_interfaces(analyst, session_id)


# 7. A throughput forecast above the configured capacity is "unavailable", not 100%.
def test_over_capacity_forecast_is_not_clamped_to_100_percent(admin):
    session_id = telemetry_service.import_telemetry_csv(
        admin, telemetry_csv(days=2, with_utilization=False), "tp.csv", TelemetryImportOptions(source_name="tp")).session_id
    congestion_training_service.train_forecaster(admin, ForecastTrainingOptions(
        session_id=session_id, interface_name="eth0", target="throughput_bps", horizons_minutes=(5,), activate=True))
    with database_service.session(write=True) as conn:  # capacity far below the measured throughput
        conn.execute("UPDATE network_metrics SET configured_capacity_bps = 1000 WHERE session_id = ?", (session_id,))
    run = congestion_prediction_service.generate_forecast(admin, session_id, "eth0")
    assert run.forecasts[0].predicted_utilization is None and run.forecasts[0].risk.level == "unknown"
    assert any("above the configured capacity" in w for w in run.warnings)
    with database_service.session() as conn:
        stored = conn.execute("SELECT predicted_utilization_ratio FROM congestion_predictions").fetchone()[0]
    assert stored is None


# 8. The live panel reads only the newest rows.
def test_recent_metrics_returns_newest_rows_in_time_order(analyst):
    lines = ["timestamp,latency_ms"] + [f"2026-10-01T00:{m:02d}:00Z,{m}" for m in range(30)]
    session_id = telemetry_service.import_telemetry_csv(
        analyst, ("\n".join(lines) + "\n").encode(), "r.csv", TelemetryImportOptions(source_name="r")).session_id
    recent = telemetry_view_service.recent_metrics(analyst, session_id, limit=5)
    assert list(recent["latency_ms"]) == [25, 26, 27, 28, 29]


# 9. The sign-up error does not reveal whether an email has an account.
def test_duplicate_signup_message_does_not_confirm_the_account(admin_user):
    with pytest.raises(auth_service.RegistrationError) as err:
        auth_service.register("Copy", admin_user.email, STRONG_PASSWORD)
    assert "already exists" not in str(err.value) and str(err.value) == auth_service.DUPLICATE_SIGNUP_ERROR
    assert "duplicate_email" in audit_rows("auth.register", "failure")[0]["details_json"]  # admins still see why
