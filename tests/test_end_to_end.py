"""End-to-end: the whole platform driven with the labelled sample files, through the same services the UI uses."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from scripts.make_sample_data import SAMPLES_DIR
from services import (
    alert_service, bandwidth_service, congestion_prediction_service, congestion_training_service, dashboard_service,
    dataset_service, health_summary_service, incident_correlation_service, intrusion_inference_service,
    intrusion_training_service, reporting_service, telemetry_service,
)
from services.telemetry_service import TelemetryImportOptions


@pytest.mark.slow
def test_full_platform_with_sample_data(admin, analyst):
    # 1. Telemetry import (analyst).
    telemetry = telemetry_service.import_telemetry_csv(
        analyst, (SAMPLES_DIR / "SAMPLE_telemetry_7days_synthetic.csv").read_bytes(),
        "SAMPLE_telemetry_7days_synthetic.csv", TelemetryImportOptions(source_name="SAMPLE (synthetic)"))
    assert telemetry.rows_rejected == 0

    # 2. Smart Shield: train (analyst), activate (admin), detect on the attack-during-peak file.
    train = dataset_service.register_intrusion_dataset(
        analyst, (SAMPLES_DIR / "SAMPLE_intrusion_train_day_synthetic.csv").read_bytes(), "train.csv",
        "SAMPLE train (synthetic)")
    trained = intrusion_training_service.train_intrusion_models(analyst, intrusion_training_service.IntrusionTrainingOptions(
        dataset_ids=(train.dataset_id,), n_estimators=40))
    assert trained.classifier_metrics["test"]["f1"] > 0.85
    for model_id in (trained.classifier_model_id, trained.anomaly_model_id):
        from services import model_registry_service
        model_registry_service.activate(admin, model_id)
    attack = dataset_service.register_intrusion_dataset(
        analyst, (SAMPLES_DIR / "SAMPLE_intrusion_attack_during_peak_synthetic.csv").read_bytes(), "attack.csv",
        "SAMPLE attack (synthetic)")
    detection = intrusion_inference_service.run_detection(
        analyst, intrusion_inference_service.DetectionOptions(dataset_id=attack.dataset_id))
    ddos = next(a for a in alert_service.list_alerts(analyst) if a.category == "DDoS")
    assert ddos.severity == "critical" and "potential_ddos" in ddos.evidence
    assert detection.ground_truth["recall"] > 0.8

    # 3. PredictNet: train, activate, forecast the congested peak.
    forecaster = congestion_training_service.train_forecaster(analyst, congestion_training_service.ForecastTrainingOptions(
        session_id=telemetry.session_id, interface_name="campus-uplink", horizons_minutes=(5, 15)))
    model_registry_service.activate(admin, forecaster.model_id)
    run = congestion_prediction_service.generate_forecast(analyst, telemetry.session_id, "campus-uplink")
    assert {f.risk.level for f in run.forecasts} & {"high", "critical"} and run.alerts_created

    # 4. Bandwidth: policy (admin) and recommendation scaled to the forecast (analyst).
    bandwidth_service.save_policy(admin, bandwidth_service.template_policy(1e9, interface="campus-uplink"))
    rec = bandwidth_service.recommend(analyst, "TEMPLATE four-class policy",
                                      {"critical": 2, "interactive": 3, "standard": 4, "background": 3},
                                      demand_mode="forecast")
    assert rec.result.total_allocated_bps <= 1e9 and all(rec.result.invariants.values())

    # 5. Correlation: the attack and the congestion overlap -> one combined incident.
    correlation = incident_correlation_service.correlate(analyst)
    incidents = [incident_correlation_service.get_incident(analyst, i) for i in correlation.incidents_created]
    combined = [i for i in incidents if i.classification == "combined"]
    assert len(combined) == 1 and "not evidence of an attack" in combined[0].rationale

    # 6. Dashboard, health summary and report all read the persisted results.
    overview = dashboard_service.get_overview(analyst)
    assert overview.has_any_data and overview.congestion_risk in ("high", "critical")
    assert any("Open incidents" in s.text for s in health_summary_service.summarize(analyst))
    report = reporting_service.build_report(analyst, datetime(2026, 9, 1, tzinfo=timezone.utc),
                                            datetime.now(timezone.utc) + timedelta(days=1))
    assert report.summary["incidents_by_classification"].get("combined") == 1
    assert report.sections["traffic_by_interface"] and report.sections["models"]
