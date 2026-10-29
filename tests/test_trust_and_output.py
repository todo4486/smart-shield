"""Phase 5: PSI drift, model health cards, incident report and weekly summary."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from services import (
    alert_service, database_service, dataset_service, drift, incident_correlation_service, incident_report_service as reports,
    intrusion_inference_service, intrusion_training_service, model_health_service as health,
    replay_service, settings_service,
)
from services.authorization import PermissionDenied
from services.intrusion_inference_service import DetectionOptions
from services.intrusion_training_service import IntrusionTrainingOptions
from services.replay_service import ReplayEngine
from services.settings_service import DriftSettings, SettingsError
from services.timeutil import to_iso
from tests.conftest import audit_rows
from tests.synthetic import cic_like_frame, to_cic_csv


# ------------------------------------------------------------------ PSI (pure)

def test_reference_distribution_uses_deciles_and_missing_share():
    values = list(range(100)) + [None] * 25 + [float("inf")] * 5
    ref = drift.reference_distribution(values)
    assert len(ref["edges"]) == 9 and len(ref["proportions"]) == 10
    assert ref["missing"] == pytest.approx(30 / 130)
    assert sum(ref["proportions"]) + ref["missing"] == pytest.approx(1.0)


def test_psi_is_zero_for_identical_data_and_grows_with_shift():
    rng = np.random.default_rng(0)
    train = rng.normal(0, 1, 5000)
    ref = drift.reference_distribution(train)
    same = drift.feature_psi(rng.normal(0, 1, 5000), ref)
    shifted = drift.feature_psi(rng.normal(1.5, 1, 5000), ref)
    assert same < drift.STABLE and shifted > drift.MODERATE
    assert drift.level(same, 0.25) == "stable" and drift.level(shifted, 0.25) == "drift"
    assert drift.level(0.15, 0.25) == "moderate" and drift.level(None, 0.25) == "unavailable"
    assert drift.level(0.15, 0.12) == "drift"  # the configured threshold wins


def test_psi_formula_and_edge_cases():
    assert drift.psi([0.5, 0.5], [0.5, 0.5]) == 0
    expected = (0.9 - 0.5) * np.log(0.9 / 0.5) + (0.1 - 0.5) * np.log(0.1 / 0.5)
    assert drift.psi([0.5, 0.5], [0.9, 0.1]) == pytest.approx(expected)
    assert np.isfinite(drift.psi([1.0, 0.0], [0.0, 1.0]))  # zero shares are floored, never infinite
    constant = drift.reference_distribution([3.0] * 50)
    assert drift.feature_psi([3.0] * 50, constant) == pytest.approx(0, abs=1e-9)
    assert drift.feature_psi([1, 2], {"edges": [], "proportions": [], "missing": 1.0}) is None
    all_missing = drift.feature_psi([None] * 300, drift.reference_distribution(range(300)))
    assert all_missing > drift.MODERATE  # missing values are a drift signal, not zeros


def test_drift_settings_validate_and_are_admin_only(admin, analyst):
    assert settings_service.get_drift_settings() == DriftSettings()
    with pytest.raises(SettingsError):
        settings_service.update_drift_settings(admin, DriftSettings(psi_threshold=5))
    with pytest.raises(PermissionDenied):
        settings_service.update_drift_settings(analyst, DriftSettings(psi_threshold=0.2))
    settings_service.update_drift_settings(admin, DriftSettings(psi_threshold=0.2, top_features=5))
    assert settings_service.get_drift_settings() == DriftSettings(0.2, 5)
    assert audit_rows("settings.update", "success")


# ------------------------------------------------------------------ model health

def _register(principal, frame, name):
    return dataset_service.register_intrusion_dataset(principal, to_cic_csv(frame), f"{name}.csv", name).dataset_id


@pytest.fixture
def trained(admin):
    train_id = _register(admin, cic_like_frame(2500, seed=1), "train")
    report = intrusion_training_service.train_intrusion_models(
        admin, IntrusionTrainingOptions(dataset_ids=(train_id,), n_estimators=20, activate=True))
    return report, train_id


def test_training_stores_distributions_from_the_training_split_only(trained):
    report, _ = trained
    dists = report.metadata["feature_distributions"]
    assert set(dists) == set(report.metadata["feature_names"])
    rows = next(iter(dists.values()))["rows"]
    assert rows == report.metadata["split_sizes"]["train"]


def test_model_cards_show_registry_facts(analyst, trained):
    cards = {c.family: c for c in health.model_cards(analyst)}
    clf = cards["intrusion_classifier"]
    assert clf.active and clf.verified and clf.drift_ready and clf.split == "chronological"
    assert clf.trained_on == ["train"] and set(clf.metrics) >= {"precision", "recall", "f1", "false_positive_rate"}
    assert set(clf.confusion_matrix) == {"tn", "fp", "fn", "tp"}
    assert cards["anomaly_detector"].metrics["threshold"] is not None


def test_old_models_report_drift_unavailable(admin, trained):
    report, _ = trained
    with database_service.session(write=True) as conn:
        meta = json.loads(conn.execute("SELECT training_metadata_json FROM model_registry WHERE id = ?",
                                       (report.classifier_model_id,)).fetchone()[0])
        meta.pop("feature_distributions")
        conn.execute("UPDATE model_registry SET training_metadata_json = ? WHERE id = ?",
                     (json.dumps(meta), report.classifier_model_id))
    card = next(c for c in health.model_cards(admin) if c.id == report.classifier_model_id)
    assert not card.drift_ready and any("Retrain" in n for n in card.notes)
    with pytest.raises(health.HealthError, match="Retrain"):
        health.check_drift(admin, report.classifier_model_id, "dataset", 1)


def test_drift_against_similar_and_shifted_datasets(analyst, admin, trained):
    report, train_id = trained
    similar = health.check_drift(analyst, report.classifier_model_id, "dataset", train_id)
    assert similar.overall in ("stable", "moderate") and similar.rows == 2500
    assert len(similar.features) == settings_service.get_drift_settings().top_features
    assert similar.features[0].importance is not None  # most important first
    shifted_frame = cic_like_frame(800, seed=9)
    for column in ("flow_duration", "flow_bytes_s", "total_fwd_packets", "flow_iat_mean"):
        shifted_frame[column] = shifted_frame[column] * 50
    shifted_id = _register(admin, shifted_frame, "shifted")
    shifted = health.check_drift(analyst, report.classifier_model_id, "dataset", shifted_id)
    assert shifted.overall == "drift" and any(f.level == "drift" for f in shifted.features)


def test_drift_from_replayed_session_and_minimum_rows(analyst, admin, trained):
    report, _ = trained
    score_id = _register(admin, cic_like_frame(600, seed=2), "score")
    engine = ReplayEngine(tick_seconds=3600)
    replay_service.reset_engine_for_tests(engine)
    try:
        session_id = engine.start(analyst, score_id, "all", speed=30)
        while engine.step(3600):
            pass
    finally:
        replay_service.reset_engine_for_tests(None)
    assert any(s["kind"] == "session" and s["id"] == session_id for s in health.drift_sources(analyst))
    result = health.check_drift(analyst, report.anomaly_model_id, "session", session_id)
    assert result.rows == 600 and all(f.psi is not None for f in result.features)
    small = _register(admin, cic_like_frame(150, seed=3), "small")
    with pytest.raises(health.HealthError, match="at least"):
        health.check_drift(analyst, report.classifier_model_id, "dataset", small)


def test_checking_drift_changes_nothing(analyst, trained):
    report, train_id = trained
    with database_service.session() as conn:
        before = conn.execute("SELECT id, is_active, artifact_sha256, training_metadata_json FROM model_registry "
                              "ORDER BY id").fetchall()
    health.check_drift(analyst, report.classifier_model_id, "dataset", train_id)
    with database_service.session() as conn:
        after = conn.execute("SELECT id, is_active, artifact_sha256, training_metadata_json FROM model_registry "
                             "ORDER BY id").fetchall()
    assert [tuple(r) for r in before] == [tuple(r) for r in after]


# ------------------------------------------------------------------ reports (pure)

T0 = datetime(2026, 1, 5, 10, 0, tzinfo=timezone.utc)


def test_svg_timeline_escapes_and_draws_one_bar_per_alert():
    events = [{"alert_id": 1, "category": "<script>x</script>", "severity": "high", "start": T0,
               "end": T0 + timedelta(minutes=5)},
              {"alert_id": 2, "category": "PortScan", "severity": "low", "start": T0 + timedelta(minutes=2),
               "end": T0 + timedelta(minutes=2)}]
    svg = reports.svg_timeline(events, T0, T0 + timedelta(minutes=10))
    assert svg.count("<rect") == 2 and "<script>" not in svg and "&lt;script&gt;" in svg
    assert "No alerts" in reports.svg_timeline([], T0, T0)


def test_host_risk_from_alerts():
    alerts = [{"severity": "high", "evidence": {"top_sources": [{"value": "10.0.0.5", "flows": 3}]}},
              {"severity": "low", "evidence": {"top_sources": [{"value": "10.0.0.5", "flows": 1}],
                                               "top_destinations": [{"value": "10.0.0.9:22", "flows": 1}]}}]
    rows = reports.host_risk_from_alerts(alerts)
    assert rows[0] == {"host": "10.0.0.5", "score": 23, "alerts": 2, "worst": "high"}


def test_forecast_accuracy_matches_measurements_within_tolerance():
    predictions = [
        {"timestamp": to_iso(T0), "interface_name": "eth0", "forecast_horizon_seconds": 300,
         "predicted_utilization_ratio": 0.6, "predicted_throughput_bps": None},
        {"timestamp": to_iso(T0), "interface_name": "eth0", "forecast_horizon_seconds": 900,
         "predicted_utilization_ratio": 0.9, "predicted_throughput_bps": None},  # no measurement near +15 min
        {"timestamp": to_iso(T0), "interface_name": "eth1", "forecast_horizon_seconds": 300,
         "predicted_utilization_ratio": None, "predicted_throughput_bps": 2e6},
    ]
    measurements = [
        {"timestamp": to_iso(T0 + timedelta(minutes=5, seconds=30)), "interface_name": "eth0", "utilization_ratio": 0.5,
         "throughput_bps": 5e6},
        {"timestamp": to_iso(T0 + timedelta(minutes=5)), "interface_name": "eth1", "utilization_ratio": None,
         "throughput_bps": 1.5e6},
    ]
    rows = {(r["horizon_minutes"], r["quantity"]): r for r in reports.forecast_accuracy(predictions, measurements)}
    assert rows[(5, "utilization")] == {"horizon_minutes": 5, "quantity": "utilization", "forecasts": 1,
                                        "matched": 1, "mae": pytest.approx(0.1)}
    assert rows[(5, "throughput (bit/s)")]["mae"] == pytest.approx(5e5)  # scored apart from utilization
    assert rows[(15, "utilization")] == {"horizon_minutes": 15, "quantity": "utilization", "forecasts": 1,
                                         "matched": 0, "mae": None}
    assert all(r["matched"] == 0 for r in reports.forecast_accuracy(predictions, []))


# ------------------------------------------------------------------ reports (end to end)

@pytest.fixture
def incident(analyst, trained):
    score_id = _register(analyst, cic_like_frame(900, seed=2), "score")
    intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=score_id))
    run = incident_correlation_service.correlate(analyst)
    incident_id = run.incidents_created[0]
    incident_correlation_service.add_note(analyst, incident_id, "Checked with the <b>network</b> team")
    incident_correlation_service.acknowledge(analyst, incident_id)
    return incident_id


def test_incident_report_has_every_section_and_is_escaped(analyst, incident):
    report = reports.build_incident_report(analyst, incident)
    html = reports.incident_report_html(report)
    for heading in ("Summary", "Timeline", "Affected hosts", "MITRE ATT&amp;CK", "Why the alerts were raised",
                    "Actions taken (audit log)", "Analyst notes"):
        assert f"<h2>{heading}</h2>" in html, heading
    assert "<script" not in html and "&lt;b&gt;network&lt;/b&gt;" in html
    assert report.techniques and report.hosts and report.explanations
    assert {a["Action"] for a in report.actions} >= {"incident.add_note", "incident.change_status"}
    assert audit_rows("report.incident", "success")


def test_reports_need_view_reports():
    with pytest.raises(PermissionDenied):
        reports.build_incident_report(None, 1)
    with pytest.raises(PermissionDenied):
        reports.build_weekly_summary(None, datetime.now(timezone.utc))


def test_weekly_summary_leaves_out_replay_and_suppressed(analyst, admin, incident):
    from services import suppression_service
    suppression_service.create_rule(admin, alert_type="anomaly", category="quiet", reason="test suppression", days=1)
    with database_service.session(write=True) as conn:
        alert_service.create_alert(conn, alert_type="anomaly", severity="low", category="quiet", reason="r",
                                   evidence={}, dedup_key="q")
    summary = reports.build_weekly_summary(analyst, datetime.now(timezone.utc) + timedelta(minutes=1))
    assert summary.top_incidents and summary.top_incidents[0]["id"] == incident
    assert summary.suppressed_alerts == 1 and summary.replay_alerts_left_out == 0
    assert summary.risky_hosts and summary.risky_hosts[0]["score"] > 0
    html = reports.weekly_summary_html(summary)
    assert "Forecast accuracy" in html and "<script" not in html
    assert audit_rows("report.weekly", "success")
