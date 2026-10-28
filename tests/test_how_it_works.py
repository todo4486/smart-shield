"""Phase 3: the "How it works" trace uses stored data only."""
from __future__ import annotations

import json

import pytest

from services import (
    dataset_service, how_it_works_service as how, incident_correlation_service, intrusion_training_service,
    replay_service,
)
from services.authorization import PermissionDenied
from services.intrusion_training_service import IntrusionTrainingOptions
from services.replay_service import ReplayEngine
from tests.synthetic import cic_like_frame, to_cic_csv


def test_no_flows_explains_every_stage_without_data():
    stages = how.build_trace(None, None, None, None, None)
    assert [s.key for s in stages] == ["capture", "flow", "detect", "correlate", "incident", "act"]
    assert all(not s.reached and not s.facts and "without data" in s.note for s in stages)


def test_unflagged_flow_stops_at_detection_and_says_why():
    flow = {"session_id": 3, "src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 443,
            "protocol": "TCP", "timestamp": "2026-01-01T00:00:00+00:00", "packet_count": 12, "byte_count": 4200,
            "duration": 0.5, "intrusion_prediction": None, "anomaly_score": None, "model_id": None,
            "model_version": None, "feature_summary_json": json.dumps({"features": {"flow_duration": 500000.0}})}
    stages = {s.key: s for s in how.build_trace(flow, {"source_type": "live_capture", "interface_name": "en0"},
                                                None, None, None, live_running=True)}
    assert ("Data source", "LIVE") in stages["capture"].facts
    assert ("5-tuple", "10.0.0.1:5000 → 10.0.0.2:443 · TCP") in stages["flow"].facts
    assert ("Bytes", "4.2 KB") in stages["flow"].facts
    assert ("Smart Shield verdict", "not flagged (benign by the model)") in stages["detect"].facts
    assert "not scored" in stages["detect"].note
    assert not stages["correlate"].reached and "did not flag" in stages["correlate"].note
    assert ("PredictNet", "no forecast stored for this data") in stages["detect"].facts


def test_missing_counters_are_unavailable_not_zero():
    flow = {"session_id": 1, "timestamp": "t", "packet_count": None, "byte_count": None, "duration": None,
            "intrusion_prediction": None}
    facts = dict(how.build_trace(flow, None, None, None, None)[1].facts)
    assert facts["Packets"] == facts["Bytes"] == facts["Duration"] == "unavailable"


def test_replayed_flow_is_traced_to_its_incident(admin, analyst):
    def register(frame, name):
        return dataset_service.register_intrusion_dataset(admin, to_cic_csv(frame), f"{name}.csv", name).dataset_id
    train_id = register(cic_like_frame(2500, seed=1), "train")
    intrusion_training_service.train_intrusion_models(
        admin, IntrusionTrainingOptions(dataset_ids=(train_id,), n_estimators=20, activate=True))
    engine = ReplayEngine(tick_seconds=3600)
    replay_service.reset_engine_for_tests(engine)
    try:
        engine.start(analyst, register(cic_like_frame(600, seed=2), "score"), "all", speed=30)
        while engine.step(3600):
            pass
    finally:
        replay_service.reset_engine_for_tests(None)
    incident_correlation_service.correlate(analyst)
    trace = how.sample_trace(analyst, flagged_only=True)
    stages = {s.key: s for s in trace["stages"]}
    assert trace["flow_id"] is not None and all(s.reached for s in trace["stages"])
    assert dict(stages["capture"].facts)["Data source"] == "DATASET REPLAY"
    assert "Dataset label (ground truth)" in dict(stages["detect"].facts)
    assert dict(stages["incident"].facts)["Incident"].startswith("#")
    assert how.sample_trace(analyst, flagged_only=True, offset=1)["flow_id"] != trace["flow_id"]


def test_trace_requires_a_signed_in_user():
    with pytest.raises(PermissionDenied):
        how.sample_trace(None)
