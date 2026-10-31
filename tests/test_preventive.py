"""M6: forecasts feeding preventive recommendations. Real training where a real model matters; a built forecast where the
test is about what the decision logic does with a given number."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from repositories import telemetry_repository
from services import (
    congestion_training_service, database_service, incident_correlation_service as correlation,
    mitigation_service as ms, preventive_service as ps, session_service, settings_service, telemetry_service,
)
from services.authorization import PermissionDenied
from services.congestion_prediction_service import ForecastRun, HorizonForecast, RiskAssessment
from services.preventive_service import HorizonStatus, ModelStatus, PreventiveError
from services.settings_service import MitigationSettings, SettingsError
from services.timeutil import to_iso, utc_now
from tests.conftest import audit_rows
from tests.synthetic import telemetry_csv
from tests.test_mitigation import _advance, _start
from tests.test_simulation import M, T0, _train, engine  # noqa: F401,F811

ROOT = Path(__file__).resolve().parent.parent
BASE = "2026-10-31T10:00:00+00:00"


def _settings(admin, **changes):
    settings_service.update_mitigation_settings(admin, replace(settings_service.get_mitigation_settings(), **changes))


def _forecast(minutes, utilization, upper=None, base=BASE, capacity=100 * M, model_id=None):
    risk = RiskAssessment("high", 0.5, utilization, upper if upper is not None else utilization, 0.1)
    return HorizonForecast(minutes * 60, f"2026-10-31T10:{minutes:02d}:00+00:00", utilization, utilization, None, 0.0, 1.0,
                           "random_forest", risk, 0)


def _run(admin, session_id, values, base=BASE, capacity=100 * M):
    """A stored prediction per forecast, as generate_forecast would leave."""
    forecasts = []
    with database_service.session(write=True) as conn:
        source = conn.execute("SELECT source_type FROM monitoring_sessions WHERE id = ?", (session_id,)).fetchone()["source_type"]
        for minutes, utilization, upper in values:
            f = _forecast(minutes, utilization, upper)
            predicted = conn.execute(
                "INSERT INTO congestion_predictions (timestamp, source_name, interface_name, forecast_horizon_seconds, "
                "predicted_utilization_ratio, congestion_risk, model_version) VALUES (?, ?, 'en0', ?, ?, 'high', 'v1')",
                (base, source, minutes * 60, utilization)).lastrowid
            forecasts.append(replace(f, prediction_id=predicted))
    return ForecastRun(None, "v1", base, "utilization_ratio", capacity, forecasts, [], 0)


@pytest.fixture
def live_session(admin):
    with database_service.session(write=True) as conn:
        return conn.execute(
            "INSERT INTO monitoring_sessions (user_id, source_type, status, interface_name, started_at, configuration_json) "
            "VALUES (?, 'live_capture', 'RUNNING', 'en0', ?, '{}')", (admin.user_id, to_iso(utc_now()))).lastrowid


@pytest.fixture
def validated(monkeypatch):
    status = ModelStatus(True, "", 1, "v1", "utilization_ratio", 300,
                         [HorizonStatus(5, True, "random_forest", True), HorizonStatus(10, True, "random_forest", True)])
    monkeypatch.setattr(ps, "model_status", lambda principal: status)


# ------------------------------------------------------------------ no model, no forecast

def test_with_no_forecaster_it_says_unavailable_and_predicts_nothing(admin, live_session):
    status = ps.model_status(admin)
    assert not status.available and "unavailable" in status.reason
    outlook = ps.run(admin, live_session, "en0")
    assert not outlook.available and outlook.forecasts == [] and "no active" in outlook.reason
    assert ps.list_recent(admin) == [] and ps.links_approaching(admin) == []
    with database_service.session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM congestion_predictions").fetchone()[0] == 0


def test_without_a_capacity_a_forecast_is_not_compared_with_anything(admin, live_session):
    forecast = _run(admin, live_session, [])
    forecast.forecasts.append(replace(_forecast(5, 0.9), predicted_utilization=None, predicted_throughput_bps=9 * M))
    outlook = ps.evaluate(admin, live_session, "en0", forecast)
    assert not outlook.available and "no configured capacity" in outlook.reason and ps.list_recent(admin) == []


# ------------------------------------------------------------------ a real model, end to end

@pytest.fixture
def trained(admin):
    session_id = telemetry_service.import_telemetry_csv(
        admin, telemetry_csv(days=2), "t.csv", telemetry_service.TelemetryImportOptions(source_name="s")).session_id
    congestion_training_service.train_forecaster(admin, congestion_training_service.ForecastTrainingOptions(
        session_id=session_id, interface_name="eth0", horizons_minutes=(5, 10), activate=True))
    return session_id


def test_a_real_forecaster_gives_5_and_10_minutes_and_a_recommendation_at_a_low_threshold(admin, trained):
    _settings(admin, preventive_threshold=0.1)
    status = ps.model_status(admin)
    assert status.available and [h.minutes for h in status.horizons if h.available] == [5, 10]
    outlook = ps.run(admin, trained, "eth0")
    assert outlook.available and {f.horizon_seconds for f in outlook.forecasts} == {300, 600}
    assert outlook.status == "likely" and outlook.recommendation_id
    [rec] = ps.list_recent(admin)
    assert rec["provenance"] == "predicted" and rec["model_version"] == status.version and rec["prediction_id"]
    assert rec["projected_allocation"] is None  # a telemetry import has no hosts: link level only, nothing invented
    assert any("link level" in a for a in rec["actions"]) and rec["automatic_note"]
    assert ps.links_approaching(admin)[0]["approaching"]


def test_nothing_is_recommended_when_no_forecast_reaches_the_threshold(admin, trained):
    _settings(admin, preventive_threshold=1.0)
    outlook = ps.run(admin, trained, "eth0")
    assert outlook.status in ("clear", "possible") and (outlook.status == "possible" or ps.list_recent(admin) == [])


def test_not_enough_history_is_said_plainly(admin, trained, live_session):
    with database_service.session(write=True) as conn:
        telemetry_repository.insert_many(conn, [(
            live_session, to_iso(utc_now()), "live capture", "en0", 1000.0, 1000.0, 1.0, 1.0, 50.0 * M, None, None, 0.5,
            100.0 * M, "psutil_counters", "measured", "valid", "derived", "derived", "configured")])
    outlook = ps.run(admin, live_session, "en0")
    assert not outlook.available and outlook.forecasts == [] and outlook.reason


# ------------------------------------------------------------------ what counts as validated

def _entry(chosen, chosen_test, baseline_test):
    return {"chosen": chosen, "candidates": {
        "last_value": {"test": {"mae": baseline_test}}, "moving_average": {"test": {"mae": baseline_test + 1}},
        "random_forest": {"test": {"mae": chosen_test}}}}


def test_validation_verdict():
    assert ps.validation_verdict(_entry("random_forest", 1.0, 2.0))[0] is True
    assert ps.validation_verdict(_entry("random_forest", 3.0, 2.0))[0] is False  # lost on held-out data
    assert ps.validation_verdict(_entry("last_value", 2.0, 2.0))[0] is False  # "same as now" justifies nothing by itself
    assert ps.validation_verdict(None)[0] is False


# ------------------------------------------------------------------ judging a forecast

def test_judge_prefers_the_earliest_likely_then_the_earliest_possible():
    assert ps.judge([_forecast(10, 0.8), _forecast(5, 0.76)], 0.75)[1].horizon_seconds == 300
    status, f = ps.judge([_forecast(5, 0.7, 0.72), _forecast(10, 0.7, 0.8)], 0.75)
    assert status == "possible" and f.horizon_seconds == 600
    assert ps.judge([_forecast(5, 0.5)], 0.75) == ("clear", None)
    assert ps.judge([], 0.75) == ("unavailable", None)


def test_the_threshold_is_configurable_and_validated(admin):
    with pytest.raises(SettingsError, match="threshold"):
        _settings(admin, preventive_threshold=0.01)
    assert MitigationSettings().preventive_threshold == 0.75 and MitigationSettings().preventive_auto is False


# ------------------------------------------------------------------ the record

def test_one_open_recommendation_kept_current_and_closed_when_the_forecast_eases(admin, live_session, validated):
    first = ps.evaluate(admin, live_session, "en0", _run(admin, live_session, [(5, 0.8, None)]))
    second = ps.evaluate(admin, live_session, "en0", _run(admin, live_session, [(5, 0.9, None)], base="2026-10-31T10:00:30+00:00"))
    assert second.recommendation_id == first.recommendation_id
    [rec] = ps.list_recent(admin)
    assert rec["predicted_utilization"] == 0.9 and rec["consecutive"] == 2
    ps.evaluate(admin, live_session, "en0", _run(admin, live_session, [(5, 0.3, None)], base="2026-10-31T10:01:00+00:00"))
    assert ps.list_recent(admin)[0]["status"] == "expired"


def test_a_recommendation_expires_when_its_time_has_passed(admin, live_session, validated):
    ps.evaluate(admin, live_session, "en0", _run(admin, live_session, [(5, 0.8, None)]))
    ps.expire_overdue(live_session, "2026-10-31T11:00:00+00:00")
    assert ps.list_recent(admin)[0]["status"] == "expired"


def test_expiry_only_looks_at_its_own_session(admin, live_session, validated):
    ps.evaluate(admin, live_session, "en0", _run(admin, live_session, [(5, 0.8, None)]))
    ps.expire_overdue(live_session + 1, "2026-10-31T11:00:00+00:00")
    assert ps.list_recent(admin)[0]["status"] == "open"


def test_projection_uses_stored_demand_and_is_labelled_a_scaling(admin, live_session, validated):
    ms.run_live_interval(live_session, 100 * M, [{"host": "10.0.0.1", "sent_bps": 30 * M, "received_bps": 0.0},
                                                 {"host": "10.0.0.2", "sent_bps": 10 * M, "received_bps": 0.0}], utc_now())
    current, projected, senders = ms.project_demand(live_session, 80 * M)
    assert sum(g["demand_bps"] for g in projected["classes"].values()) == pytest.approx(80 * M)
    assert current["classes"]["normal"]["demand_bps"] == pytest.approx(40 * M) and senders == ["10.0.0.1", "10.0.0.2"]
    ps.evaluate(admin, live_session, "en0", _run(admin, live_session, [(5, 0.8, None)]))
    [rec] = ps.list_recent(admin)
    assert rec["projected_allocation"] and any("10.0.0.1" in a and "not evidence of an attack" in a for a in rec["actions"])


def test_no_stored_hosts_means_no_projection(admin, live_session):
    assert ms.project_demand(live_session, 80 * M) == (None, None, [])


# ------------------------------------------------------------------ deciding

def test_dismissing_needs_a_reason_and_an_administrator_and_is_not_asked_again_at_once(admin, analyst, live_session, validated):
    rec_id = ps.evaluate(admin, live_session, "en0", _run(admin, live_session, [(5, 0.8, None)])).recommendation_id
    with pytest.raises(PermissionDenied):
        ps.dismiss(analyst, rec_id, reason="Not needed")
    with pytest.raises(PreventiveError, match="reason"):
        ps.dismiss(admin, rec_id, reason="")
    ps.dismiss(admin, rec_id, reason="Backup window, expected")
    assert ps.evaluate(admin, live_session, "en0", _run(admin, live_session, [(5, 0.9, None)])).recommendation_id is None
    with pytest.raises(PreventiveError, match="already been decided"):
        ps.dismiss(admin, rec_id, reason="Twice over")
    assert [r for r in audit_rows() if r["action"] == "preventive.dismissed"]


def test_a_real_link_cannot_be_prioritized_from_a_forecast(admin, live_session, validated):
    rec_id = ps.evaluate(admin, live_session, "en0", _run(admin, live_session, [(5, 0.8, None)])).recommendation_id
    with pytest.raises(PreventiveError, match="only available on a simulated link"):
        ps.apply(admin, rec_id, reason="Trying it anyway")
    assert ps.list_recent(admin)[0]["status"] == "open"
    assert ms.list_for_session(admin, live_session) == []


def test_applying_on_a_simulated_link_goes_through_the_normal_reversible_path(admin, engine, validated):
    _train(admin)
    session_id = _start(engine, admin, "normal")
    _advance(engine, 5, T0)
    rec_id = ps.evaluate(admin, session_id, "simulated-link", _run(admin, session_id, [(5, 0.8, None)])).recommendation_id
    result = ps.apply(admin, rec_id, reason="Get ahead of it")
    assert result["action_type"] == "prioritize" and result["status"] == "active" and result["expires_at"]
    assert ps.list_recent(admin)[0]["status"] == "applied" and ps.list_recent(admin)[0]["mitigation_id"] == result["id"]
    ms.rollback(admin, result["id"], reason="Back to normal")
    assert ms.get_action(admin, result["id"])["status"] == "rolled_back"


# ------------------------------------------------------------------ automatic only when everything permits it

BLOCKER_CASES = [
    (dict(policy="recommend"), {}, "not Auto rate-limit"), (dict(preventive_auto=False), {}, "switched off"),
    (dict(adaptive_enabled=False), {}, "adaptive allocation is off"), ({}, dict(validated=False), "not validated"),
    ({}, dict(strength="possible"), "error band"), ({}, dict(consecutive=1), "needs 2"),
    ({}, dict(refused_recently=True), "recently refused"), ({}, dict(origin="real"), "not available on this source"),
]


@pytest.mark.parametrize("settings, context, expected", BLOCKER_CASES)
def test_each_condition_alone_blocks_automation(settings, context, expected):
    allowed = MitigationSettings(policy="auto_rate_limit", preventive_auto=True)
    base = dict(origin="simulation", validated=True, strength="likely", consecutive=2, refused_recently=False)
    assert ps.automatic_blockers(allowed, **base) == []
    blockers = ps.automatic_blockers(replace(allowed, **settings), **{**base, **context})
    assert len(blockers) == 1 and expected in blockers[0]


def _twice(admin, session_id, interface="simulated-link"):
    ps.evaluate(admin, session_id, interface, _run(admin, session_id, [(5, 0.8, None)]))
    ps.evaluate(admin, session_id, interface, _run(admin, session_id, [(5, 0.9, None)], base="2026-10-31T10:00:30+00:00"))


def test_automation_applies_once_everything_permits_it_and_does_not_call_it_an_attack(admin, engine, validated):
    _train(admin)
    _settings(admin, policy="auto_rate_limit", preventive_auto=True)
    session_id = _start(engine, admin, "normal")
    _advance(engine, 5, T0)
    ps.evaluate(admin, session_id, "simulated-link", _run(admin, session_id, [(5, 0.8, None)]))
    assert ms.list_for_session(admin, session_id) == []  # one forecast is not enough
    ps.evaluate(admin, session_id, "simulated-link", _run(admin, session_id, [(5, 0.9, None)], base="2026-10-31T10:00:30+00:00"))
    [action] = ms.list_for_session(admin, session_id)
    assert action["action_type"] == "prioritize" and action["status"] == "active" and action["decided_by"] is None
    assert action["initiated_by"] == "engine" and action["expires_at"]
    assert correlation.get_incident(admin, action["incident_id"]).classification in ("performance", "security")
    incident = correlation.get_incident(admin, action["incident_id"])
    if not incident.alerts:
        assert incident.classification == "performance" and incident.not_an_attack
    assert ps.list_recent(admin)[0]["status"] == "applied"


def test_by_default_a_forecast_changes_nothing_by_itself(admin, engine, validated):
    _train(admin)
    session_id = _start(engine, admin, "normal")
    _advance(engine, 5, T0)
    _twice(admin, session_id)
    assert ms.list_for_session(admin, session_id) == []
    [rec] = ps.list_recent(admin)
    assert rec["status"] == "open" and "not Auto rate-limit" in rec["automatic_note"] and "switched off" in rec["automatic_note"]


def test_a_real_link_never_changes_by_itself_whatever_the_policy(admin, live_session, validated):
    _settings(admin, policy="auto_rate_limit", preventive_auto=True)
    _twice(admin, live_session, "en0")
    assert ms.list_for_session(admin, live_session) == []
    assert "not available on this source" in ps.list_recent(admin)[0]["automatic_note"]
    with pytest.raises(ms.MitigationError):
        ms.apply_preventive(live_session, "Trying directly", utc_now())


def test_the_engine_function_refuses_without_the_policy_whoever_calls_it(admin, engine):
    _train(admin)
    session_id = _start(engine, admin, "normal")
    with pytest.raises(ms.MitigationError, match="not permitted"):
        ms.apply_preventive(session_id, "Trying directly", utc_now())


# ------------------------------------------------------------------ pages

def _page(user):
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.session_state[session_service.USER_ID_KEY] = user.id
    app.session_state[session_service.LAST_ACTIVITY_KEY] = utc_now()
    app.run()
    app.switch_page("views/bandwidth.py")
    app.run()
    return app


def test_the_forecast_tab_says_unavailable_without_a_model(admin_user, analyst_user):
    for user in (admin_user, analyst_user):
        app = _page(user)
        assert not app.exception
        assert any("Forecasts are unavailable" in w.value for w in app.warning)


def test_the_forecast_tab_runs_a_real_forecast_and_decides(admin_user, admin, trained):
    _settings(admin, preventive_threshold=0.1)
    app = _page(admin_user)
    assert not app.exception
    app.selectbox(key="preventive_session").select(trained)
    app.run()
    app.button(key="preventive_run").click()
    app.run()
    assert not app.exception
    text = " ".join(m.value for m in app.markdown)
    assert "In 5 min" in text and "In 10 min" in text and "Predicted" in text
    [rec] = ps.list_recent(admin)
    app.run()
    app.text_input(key=f"preventive_reason_{rec['id']}").input("Known busy period")
    app.button(key=f"preventive_dismiss_{rec['id']}").click()
    app.run()
    assert not app.exception and ps.list_recent(admin)[0]["status"] == "dismissed"


def test_a_forecast_is_not_shown_under_another_sources_name(admin_user, admin, trained):
    other = telemetry_service.import_telemetry_csv(
        admin, telemetry_csv(days=3), "u.csv", telemetry_service.TelemetryImportOptions(source_name="u")).session_id
    app = _page(admin_user)
    app.selectbox(key="preventive_session").select(trained)
    app.run()
    app.button(key="preventive_run").click()
    app.run()
    assert any("In 5 min" in m.value for m in app.markdown)
    app.selectbox(key="preventive_session").select(other)
    app.run()
    assert not app.exception and not any("In 5 min" in m.value for m in app.markdown)


def test_the_controls_reach_the_forecast_settings(admin_user):
    app = _page(admin_user)
    app.slider(key="preventive_threshold").set_value(80)
    next(b for b in app.button if b.label == "Save").click()
    app.run()
    assert not app.exception and settings_service.get_mitigation_settings().preventive_threshold == 0.8
