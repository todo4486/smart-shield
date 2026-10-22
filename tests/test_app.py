"""Streamlit AppTest: routing and the login gate."""
from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from services import session_service
from services.timeutil import utc_now

APP = str(Path(__file__).resolve().parent.parent / "app.py")
TIMEOUT = 30


def _all_text(at: AppTest) -> str:
    parts = [m.value for m in at.markdown] + [i.value for i in at.info] + [e.value for e in at.error]
    parts += [w.value for w in at.warning] + [s.value for s in at.success]
    parts += [h.value for h in at.header] + [s.value for s in at.subheader] + [c.value for c in at.caption]
    return "\n".join(str(p) for p in parts)


def _signed_in(user) -> AppTest:
    at = AppTest.from_file(APP, default_timeout=TIMEOUT)
    at.session_state[session_service.USER_ID_KEY] = user.id
    at.session_state[session_service.LAST_ACTIVITY_KEY] = utc_now()
    return at.run()


def test_anonymous_user_sees_only_login_page():
    at = AppTest.from_file(APP, default_timeout=TIMEOUT).run()
    assert not at.exception
    labels = {t.label for t in at.text_input}
    assert {"Email", "Password"} <= labels
    text = _all_text(at)
    assert "first account you create becomes the **administrator**" in text
    assert "Overview" not in text and "Administration" not in text
    assert "Sign out" not in [b.label for b in at.button]


@pytest.mark.parametrize(
    "page", ["views/overview.py", "views/administration.py", "views/security_center.py", "views/settings.py"]
)
def test_anonymous_user_cannot_switch_to_protected_pages(page):
    at = AppTest.from_file(APP, default_timeout=TIMEOUT)
    at.switch_page(page)
    at.run()
    text = _all_text(at)
    # Only the login page is registered, so the router falls back to it.
    assert "Email" in {t.label for t in at.text_input}
    assert "Network health across Smart Shield" not in text
    assert "Manage accounts and roles" not in text
    assert "Planned for" not in text


def test_signed_in_admin_sees_overview_empty_state(admin_user):
    at = _signed_in(admin_user)
    assert not at.exception
    text = _all_text(at)
    assert "No network data yet" in text
    assert "Set up your team" in text
    assert "Sign out" in [b.label for b in at.button]


def test_analyst_overview_hides_admin_step_and_admin_page_is_guarded(analyst_user):
    at = _signed_in(analyst_user)
    assert not at.exception
    assert "Set up your team" not in _all_text(at)
    at.switch_page("views/administration.py")
    at.run()
    assert "Manage accounts and roles" not in _all_text(at)


def test_admin_can_open_administration(admin_user):
    at = AppTest.from_file(APP, default_timeout=TIMEOUT)
    at.session_state[session_service.USER_ID_KEY] = admin_user.id
    at.session_state[session_service.LAST_ACTIVITY_KEY] = utc_now()
    at.switch_page("views/administration.py")
    at.run()
    assert not at.exception
    assert "Manage accounts and roles" in _all_text(at)


def test_login_through_the_form(admin_user):
    at = AppTest.from_file(APP, default_timeout=TIMEOUT).run()
    at.text_input(key="login_email").input("ada@example.com")
    at.text_input(key="login_password").input("CorrectHorse42")
    at.button[0].click()  # first form submit button on the page is "Sign in"
    at.run()
    assert not at.exception
    assert "Network health across Smart Shield" in _all_text(at)


TELEMETRY = (
    b"timestamp,interface_name,incoming_bytes_per_second,outgoing_bytes_per_second,latency_ms\n"
    b"2026-10-01T00:00:00Z,eth0,1000,500,12\n"
    b"2026-10-01T00:05:00Z,eth0,2000,800,\n"
    b"2026-10-01T00:10:00Z,eth0,1800,600,13\n"
    b"2026-10-01T01:30:00Z,eth0,1500,700,14\n"  # gap -> exercises chart gap breaks
)


def _run_page(user, page: str) -> AppTest:
    at = AppTest.from_file(APP, default_timeout=TIMEOUT)
    at.session_state[session_service.USER_ID_KEY] = user.id
    at.session_state[session_service.LAST_ACTIVITY_KEY] = utc_now()
    at.switch_page(page)
    return at.run()


def test_ml_lab_and_live_monitoring_render_empty(analyst_user):
    at = _run_page(analyst_user, "views/ml_lab.py")
    assert not at.exception
    assert "Upload historical network performance measurements" in _all_text(at)
    at = _run_page(analyst_user, "views/live_monitoring.py")
    assert not at.exception
    assert "No monitoring sessions yet" in _all_text(at)


def test_live_monitoring_renders_imported_session(analyst_user, admin_user):
    from services import dataset_service, telemetry_service
    from services.dataset_service import FlowImportOptions
    from services.telemetry_service import TelemetryImportOptions
    from tests.test_datasets import cic_rows

    principal = analyst_user.to_principal()
    imported = telemetry_service.import_telemetry_csv(
        principal, TELEMETRY, "t.csv", TelemetryImportOptions(source_name="lab"))
    flows = dataset_service.register_intrusion_dataset(
        principal, cic_rows(), "cic.csv", "cic", FlowImportOptions(enabled=True))
    for user in (analyst_user, admin_user):
        at = _run_page(user, "views/live_monitoring.py")
        assert not at.exception, at.exception
        assert "Session history" in _all_text(at)
        assert at.selectbox[0].value == flows.flow_session_id  # newest session first
        at.selectbox[0].select(imported.session_id).run()
        assert not at.exception, at.exception
        # No capacity in the file -> utilization is unavailable, no invented percentage.
        assert "Utilization is **unavailable**" in _all_text(at)
    at = _run_page(admin_user, "views/overview.py")
    assert not at.exception
    assert "No network data yet" not in _all_text(at)
    at = _run_page(analyst_user, "views/ml_lab.py")
    assert not at.exception


def test_security_center_and_ml_lab_render_with_models_and_alerts(admin_user, analyst_user):
    from services import dataset_service, intrusion_inference_service, intrusion_training_service
    from services.intrusion_inference_service import DetectionOptions
    from services.intrusion_training_service import IntrusionTrainingOptions
    from tests.synthetic import cic_like_frame, to_cic_csv

    admin = admin_user.to_principal()
    at = _run_page(analyst_user, "views/security_center.py")
    assert not at.exception
    assert "No intrusion classifier is active yet" in _all_text(at)

    train_id = dataset_service.register_intrusion_dataset(admin, to_cic_csv(cic_like_frame(1500)), "a.csv", "a").dataset_id
    intrusion_training_service.train_intrusion_models(
        admin, IntrusionTrainingOptions(dataset_ids=(train_id,), n_estimators=10, activate=True))
    score_id = dataset_service.register_intrusion_dataset(
        admin, to_cic_csv(cic_like_frame(600, seed=5)), "b.csv", "b").dataset_id
    intrusion_inference_service.run_detection(admin, DetectionOptions(dataset_id=score_id))

    for user in (analyst_user, admin_user):
        at = _run_page(user, "views/security_center.py")
        assert not at.exception, at.exception
        text = _all_text(at)
        assert "Evidence" in text and "One alert per detected category" in text
        at = _run_page(user, "views/ml_lab.py")
        assert not at.exception, at.exception


def test_predictnet_and_settings_pages(admin_user, analyst_user):
    from services import congestion_training_service, telemetry_service
    from services.congestion_training_service import ForecastTrainingOptions
    from services.telemetry_service import TelemetryImportOptions
    from tests.synthetic import telemetry_csv

    at = _run_page(analyst_user, "views/predictnet.py")
    assert not at.exception and "No telemetry to forecast yet" in _all_text(at)

    admin = admin_user.to_principal()
    session_id = telemetry_service.import_telemetry_csv(
        admin, telemetry_csv(days=2), "t.csv", TelemetryImportOptions(source_name="lab")).session_id
    at = _run_page(analyst_user, "views/predictnet.py")
    assert not at.exception and "No forecaster is active" in _all_text(at)

    congestion_training_service.train_forecaster(admin, ForecastTrainingOptions(
        session_id=session_id, interface_name="eth0", horizons_minutes=(5,), activate=True))
    for user in (analyst_user, admin_user):
        at = _run_page(user, "views/predictnet.py")
        assert not at.exception, at.exception
        generate = next(b for b in at.button if b.label.startswith("Generate forecast"))
        generate.click().run()
        assert not at.exception, at.exception
        assert "last_forecast_run" in at.session_state
        assert "Congestion risk:" in _all_text(at)
        at = _run_page(user, "views/ml_lab.py")
        assert not at.exception, at.exception

    at = _run_page(analyst_user, "views/settings.py")
    assert not at.exception and "Only administrators can change settings." in _all_text(at)
    at = _run_page(admin_user, "views/settings.py")
    assert not at.exception and "Only administrators" not in _all_text(at)


def test_bandwidth_page(admin_user, analyst_user):
    from services import bandwidth_service

    at = _run_page(analyst_user, "views/bandwidth.py")
    assert not at.exception and "No bandwidth policies exist yet" in _all_text(at)
    admin = admin_user.to_principal()
    bandwidth_service.save_policy(admin, bandwidth_service.template_policy(1e9, interface="eth0"))
    bandwidth_service.recommend(admin, "TEMPLATE four-class policy", {"critical": 1e8, "standard": 9e8})
    for user in (analyst_user, admin_user):
        at = _run_page(user, "views/bandwidth.py")
        assert not at.exception, at.exception
        text = _all_text(at)
        assert "Recommendation mode." in text and "Enforcement is not available on this server" in text
