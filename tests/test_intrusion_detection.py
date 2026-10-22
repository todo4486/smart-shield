from __future__ import annotations

import json

import numpy as np
import pandas as pd
import pytest

from services import (
    alert_service, database_service, dataset_service, intrusion_inference_service, intrusion_training_service,
    model_registry_service,
)
from services.alert_service import AlertError
from services.authorization import PermissionDenied
from services.intrusion_features import (
    FeatureError, build_label_map, candidate_features, clean_label, compatibility, numeric_feature_frame,
)
from services.intrusion_inference_service import DetectionError, DetectionOptions
from services.intrusion_training_service import IntrusionTrainingOptions, TrainingError
from tests.conftest import audit_rows
from tests.synthetic import cic_like_frame, to_cic_csv


def register(principal, frame, name="day"):
    return dataset_service.register_intrusion_dataset(principal, to_cic_csv(frame), f"{name}.csv", name).dataset_id


def train(principal, dataset_ids, **kwargs):
    options = IntrusionTrainingOptions(dataset_ids=tuple(dataset_ids), n_estimators=20, **kwargs)
    return intrusion_training_service.train_intrusion_models(principal, options)


# ------------------------------------------------------------- features

def test_label_map_is_explicit_and_cleans_encoding():
    labels = pd.Series(["BENIGN", "DDoS", "Web Attack � Brute Force", " PortScan "])
    label_map = build_label_map(labels)
    assert label_map.binary["BENIGN"] == 0 and label_map.binary["DDoS"] == 1
    assert label_map.attack_type["Web Attack � Brute Force"] == "Web Attack - Brute Force"
    assert clean_label(" PortScan ") == "PortScan"


def test_identifiers_and_leakage_columns_are_dropped():
    frame = cic_like_frame(200)
    features, dropped = candidate_features(frame, "full")
    for column in ("source_ip", "destination_ip", "timestamp"):
        assert dropped[column] == "identifier" and column not in features
    assert dropped["destination_port"].startswith("leakage")
    assert "label" not in features


def test_live_compatible_feature_set_requires_live_features():
    frame = cic_like_frame(200)
    features, dropped = candidate_features(frame, "live_compatible")
    assert "init_win_bytes_forward" not in features
    assert dropped["init_win_bytes_forward"] == "not computable from live packet headers"
    with pytest.raises(FeatureError, match="lacks live-compatible features"):
        candidate_features(frame.drop(columns=["flow_iat_mean"]), "live_compatible")


def test_infinite_values_become_nan_not_zero():
    frame = cic_like_frame(50)
    features = numeric_feature_frame(frame, ["flow_bytes_s"])
    assert features["flow_bytes_s"].isna().sum() == 3
    assert not np.isinf(features.to_numpy()).any()


def test_compatibility_rejects_missing_features_instead_of_zero_filling():
    report = compatibility(["a", "b"], ["a", "b", "c"])
    assert not report.compatible and report.missing == ["c"] and "never filled with zeros" in report.message
    assert compatibility(["a", "b", "c", "label"], ["a", "b"]).compatible


# ------------------------------------------------------------- training

def test_training_registers_both_models_with_metrics(analyst):
    dataset_id = register(analyst, cic_like_frame(2500))
    report = train(analyst, [dataset_id])
    assert report.metadata["split"] == "chronological"
    sizes = report.metadata["split_sizes"]
    assert sizes["train"] > sizes["validation"] > 0 and sizes["test"] > 0
    periods = report.metadata["split_periods"]
    assert periods["train"][1] <= periods["validation"][0] <= periods["test"][0]  # no time overlap
    for key in ("precision", "recall", "f1", "false_positive_rate", "confusion_matrix"):
        assert key in report.classifier_metrics["test"]
    assert "BENIGN" in report.classifier_metrics["per_type_test"]
    assert report.multiclass_metrics and "DDoS" in report.multiclass_metrics["per_class"]
    assert "constant_flag" in report.metadata["dropped_columns"]
    assert report.metadata["label_map"]["DDoS"] == {"binary": 1, "type": "DDoS"}
    models = model_registry_service.list_models(analyst)
    assert {m.family for m in models} == {"intrusion_classifier", "anomaly_detector"}
    assert not any(m.is_active for m in models)  # analysts cannot activate
    assert all(len(m.artifact_sha256) == 64 for m in models)
    assert report.anomaly_metrics["benign_training_rows"] < sizes["train"]  # benign only


def test_stratified_split_when_no_timestamps_is_flagged(analyst):
    dataset_id = register(analyst, cic_like_frame(2000, with_timestamp=False))
    report = train(analyst, [dataset_id])
    assert report.metadata["split"] == "stratified_random"
    assert any("optimistic" in w for w in report.warnings)
    with pytest.raises(TrainingError, match="Timestamp"):
        train(analyst, [dataset_id], split_strategy="time")


def test_single_class_data_is_refused_and_nothing_registered(analyst):
    frame = cic_like_frame(500)
    frame["label"] = "BENIGN"
    dataset_id = register(analyst, frame)
    with pytest.raises(TrainingError, match="both benign and attack"):
        train(analyst, [dataset_id])
    assert model_registry_service.list_models(analyst) == []
    assert len(audit_rows("model.train_intrusion", "failure")) == 1


def test_failed_save_never_replaces_active_model(admin, monkeypatch):
    dataset_id = register(admin, cic_like_frame(1500))
    first = train(admin, [dataset_id], activate=True)
    assert first.activated

    def broken(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(model_registry_service, "register", broken)
    with pytest.raises(TrainingError, match="nothing was registered"):
        train(admin, [dataset_id], activate=True)
    active = model_registry_service.active_model(admin, "intrusion_classifier")
    assert active.id == first.classifier_model_id
    assert len(model_registry_service.list_models(admin)) == 2  # only the first run's two models


def test_analyst_cannot_request_activation(analyst):
    dataset_id = register(analyst, cic_like_frame(500))
    with pytest.raises(PermissionDenied):
        train(analyst, [dataset_id], activate=True)


# ------------------------------------------------------------- registry

def test_activation_keeps_one_active_model_per_family(admin):
    dataset_id = register(admin, cic_like_frame(1500))
    first = train(admin, [dataset_id], activate=True)
    second = train(admin, [dataset_id])
    model_registry_service.activate(admin, second.classifier_model_id)
    with database_service.session() as conn:
        active = conn.execute("SELECT id FROM model_registry WHERE is_active = 1 AND model_family = "
                              "'intrusion_classifier'").fetchall()
    assert [r["id"] for r in active] == [second.classifier_model_id]
    assert model_registry_service.active_model(admin, "anomaly_detector").id == first.anomaly_model_id


def test_tampered_artifact_is_refused(admin):
    dataset_id = register(admin, cic_like_frame(1000))
    report = train(admin, [dataset_id])
    record = model_registry_service.get_model(admin, report.classifier_model_id)
    with open(record.artifact_path, "ab") as handle:
        handle.write(b"tampered")
    with pytest.raises(model_registry_service.ArtifactIntegrityError, match="SHA-256"):
        model_registry_service.activate(admin, report.classifier_model_id)
    assert len(audit_rows("model.activate", "failure")) == 1


def test_artifact_outside_artifact_dir_is_refused(admin, tmp_path):
    dataset_id = register(admin, cic_like_frame(1000))
    report = train(admin, [dataset_id])
    with database_service.session(write=True) as conn:
        conn.execute("UPDATE model_registry SET artifact_path = ? WHERE id = ?",
                     (str(tmp_path / "evil.joblib"), report.classifier_model_id))
    record = model_registry_service.get_model(admin, report.classifier_model_id)
    with pytest.raises(model_registry_service.ArtifactIntegrityError, match="outside"):
        model_registry_service.load_bundle(record)


def test_analyst_cannot_activate(admin, analyst):
    dataset_id = register(admin, cic_like_frame(1000))
    report = train(admin, [dataset_id])
    with pytest.raises(PermissionDenied):
        model_registry_service.activate(analyst, report.classifier_model_id)


# ------------------------------------------------------------- detection

@pytest.fixture
def trained(admin):
    train_id = register(admin, cic_like_frame(2500, seed=1), "train")
    report = train(admin, [train_id], activate=True)
    score_id = register(admin, cic_like_frame(1500, seed=2), "score")
    return report, score_id


def test_detection_groups_alerts_and_records_model_version(analyst, trained):
    report, score_id = trained
    result = intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=score_id))
    assert result.flagged_attack > 0 and result.flows_stored >= result.flagged_attack
    assert set(result.by_category) <= {"DDoS", "PortScan", "Attack (unclassified)", "Anomalous flows"}
    assert len(result.alerts_created) == len(result.by_category)  # one alert per category
    alerts = alert_service.list_alerts(analyst)
    assert all(a.model_version == report.version for a in alerts)
    ddos = next(a for a in alerts if a.category == "DDoS")
    assert ddos.severity in ("high", "critical") and ddos.alert_type == "security"
    assert "model_score_uncalibrated" in ddos.evidence and ddos.evidence["flows"] > 0
    with database_service.session() as conn:
        flow = conn.execute("SELECT * FROM network_flows WHERE intrusion_prediction = 'DDoS' LIMIT 1").fetchone()
        events = conn.execute("SELECT COUNT(*) FROM alert_events WHERE event_type = 'created'").fetchone()[0]
    assert flow["model_id"] == report.classifier_model_id and flow["model_version"] == report.version
    assert json.loads(flow["feature_summary_json"])["dataset_label"] == "DDoS"
    assert events == len(result.alerts_created)
    assert result.ground_truth["confusion_matrix"]["tp"] > 0


def test_rerun_does_not_duplicate_unresolved_alerts(analyst, trained):
    _, score_id = trained
    first = intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=score_id))
    second = intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=score_id))
    assert second.alerts_created == [] and second.alerts_deduplicated == len(first.alerts_created)
    alert_service.change_status(analyst, first.alerts_created[0], "resolved")
    third = intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=score_id))
    assert len(third.alerts_created) == 1  # only the resolved category is raised again


def test_incompatible_data_is_rejected(analyst, trained):
    frame = cic_like_frame(300, seed=3).drop(columns=["flow_iat_mean", "init_win_bytes_forward"])
    incompatible = register(analyst, frame, "partial")
    with pytest.raises(DetectionError, match="REJECTED"):
        intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=incompatible))
    assert alert_service.list_alerts(analyst) == []


def test_detection_without_active_model_explains_what_to_do(analyst):
    dataset_id = register(analyst, cic_like_frame(300))
    with pytest.raises(DetectionError, match="no active intrusion classifier"):
        intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=dataset_id))


def test_detection_without_timestamps_still_alerts(analyst, trained):
    no_ts = register(analyst, cic_like_frame(800, seed=4, with_timestamp=False), "nots")
    result = intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=no_ts))
    assert result.flows_stored == 0 and result.alerts_created
    assert any("no usable timestamps" in w for w in result.warnings)


def test_severity_rules():
    sev = intrusion_inference_service.severity_for
    assert sev("Heartbleed", 1, "security", False) == "critical"
    assert sev("DDoS", 10, "security", False) == "high"
    assert sev("DDoS", 5000, "security", True) == "critical"
    assert sev("PortScan", 10, "security", False) == "medium"
    assert sev("Anomalous flows", 10, "anomaly", False) == "low"


def test_potential_ddos_rule():
    n = 30
    group = pd.DataFrame({"source_ip": [f"10.0.0.{i}" for i in range(n)], "destination_ip": "192.168.1.50"})
    stamps = pd.Series(pd.date_range("2026-01-01", periods=n, freq="1s", tz="UTC"))
    found = intrusion_inference_service._potential_ddos(group, stamps)
    assert found["distinct_sources"] == n and found["destination"] == "192.168.1.50"
    assert intrusion_inference_service._potential_ddos(group.head(5), stamps.head(5)) is None


# ---------------------------------------------------------------- triage

def test_alert_triage_transitions_history_and_permissions(admin, analyst, trained):
    _, score_id = trained
    result = intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=score_id))
    alert_id = result.alerts_created[0]
    alert_service.change_status(analyst, alert_id, "acknowledged", "looking")
    with pytest.raises(AlertError, match="cannot move"):
        alert_service.change_status(analyst, alert_id, "acknowledged")
    alert_service.add_note(analyst, alert_id, "source is a lab host")
    alert_service.change_status(analyst, alert_id, "false_positive")
    alert, events = alert_service.get_alert(analyst, alert_id)
    assert alert.status == "false_positive" and alert.resolved_at
    assert "lab host" in alert.investigation_notes
    assert [e["event_type"] for e in events] == ["created", "status_change", "note", "status_change"]
    with pytest.raises(PermissionDenied):
        alert_service.change_status(None, alert_id, "open")
