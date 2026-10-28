"""Phase 3: "Why was this flagged?" explanations and the MITRE ATT&CK mapping."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from services import (
    alert_service, database_service, dataset_service, explainability_service as explain, intrusion_inference_service,
    intrusion_training_service, mitre, replay_service,
)
from services.authorization import PermissionDenied
from services.explainability_service import Deviation, ExplainError
from services.intrusion_inference_service import DetectionOptions
from services.intrusion_training_service import IntrusionTrainingOptions
from services.replay_service import ReplayEngine
from tests.synthetic import cic_like_frame, to_cic_csv


# ------------------------------------------------------------------ MITRE

@pytest.mark.parametrize("label, tactic, technique", [
    ("PortScan", "Discovery", "T1046"),
    ("FTP-Patator", "Credential Access", "T1110"),
    ("SSH-Patator", "Credential Access", "T1110"),
    ("Web Attack \x96 Brute Force", "Credential Access", "T1110"),
    ("DDoS", "Impact", "T1498"),
    ("DoS Hulk", "Impact", "T1499"),
    ("DoS slowloris", "Impact", "T1499"),
    ("Web Attack – Sql Injection", "Initial Access", "T1190"),
    ("Web Attack – XSS", "Initial Access", "T1189"),
    ("Bot", "Command and Control", "T1071"),
])
def test_mitre_mapping(label, tactic, technique):
    found = mitre.primary(label)
    assert (found.tactic, found.technique_id) == (tactic, technique)
    assert found.url.startswith("https://attack.mitre.org/techniques/T")


@pytest.mark.parametrize("label", ["BENIGN", "Anomalous flows", "Attack (unclassified)", "", None, "Something new"])
def test_mitre_never_guesses(label):
    assert mitre.techniques_for(label) == [] and mitre.primary(label) is None


def test_mitre_sub_techniques_and_incident_order():
    assert [t.technique_id for t in mitre.techniques_for("DDoS")] == ["T1498", "T1498.001"]
    assert mitre.techniques_for("DDoS")[1].url.endswith("/T1498/001/")
    ordered = mitre.primaries_for(["DDoS", "PortScan", "DDoS", "BENIGN", "FTP-Patator"])
    assert [t.technique_id for t in ordered] == ["T1110", "T1046", "T1498"]  # kill-chain order, no duplicates
    assert mitre.tactics_for(["DDoS", "PortScan"]) == ["Discovery", "Impact"]


# ------------------------------------------------------------------ pure helpers

def test_pretty_feature_names():
    assert explain.pretty("flow_iat_mean") == "Flow IAT mean"
    assert explain.pretty("flow_bytes_s") == "Flow bytes/s"
    assert explain.pretty("total_length_of_fwd_packets") == "Total length of Fwd packets"


def test_robust_deviations_rank_cap_and_ignore_missing():
    reference = pd.DataFrame({"a": [10, 11, 9, 10, 10], "b": [5, 5, 5, 5, 5], "c": [0, 0, 0, 0, 0],
                              "d": [1, 2, 3, 4, 5]})
    flagged = pd.DataFrame({"a": [400, 410, np.nan], "b": [5, 5, 5], "c": [3, 3, 3], "d": [3, 3, np.inf]})
    found = explain.robust_deviations(flagged, reference, ["a", "b", "c", "d", "missing"], {"a": 0.4})
    by_name = {d.feature: d for d in found}
    assert set(by_name) == {"a", "c"}  # b and d sit on the benign median; "missing" is skipped
    assert by_name["a"].ratio == pytest.approx(40.5) and by_name["a"].importance == 0.4
    assert by_name["c"].robust_z == explain.Z_CAP and by_name["c"].ratio is None  # MAD 0 and median 0
    assert found[0].feature in ("a", "c")


def test_vote_shares_and_anomaly_position():
    votes = explain.vote_shares(np.array([[0.1, 0.9, 0.0], [0.3, 0.7, 0.0]]), ["BENIGN", "PortScan", "DDoS"])
    assert votes == [{"label": "PortScan", "share": pytest.approx(0.8)}, {"label": "BENIGN", "share": pytest.approx(0.2)}]
    assert explain.vote_shares(np.empty((0, 3)), ["a", "b", "c"]) == []
    position = explain.anomaly_position(-0.6, -0.5, -0.7, -0.3)
    assert position["score"] == pytest.approx(0.75) and position["threshold"] == pytest.approx(0.5)
    assert explain.anomaly_position(1, 1, 2, 2) == {"score": 0.5, "threshold": 0.5}


def test_summary_sentence_quotes_real_numbers():
    deviation = Deviation("flow_duration", 4000.0, 100.0, 12.0, 40.0, 0.3)
    context = {"flows": 412, "top_source": "10.0.0.5", "distinct_destination_ports": 380, "span_seconds": 30.0}
    text = explain.summary_sentence("PortScan", "security", 0.93, {"label": "PortScan", "share": 0.88}, deviation,
                                    context)
    assert text.startswith("Flagged as PortScan (model score 0.93, uncalibrated; 88% of attack-type trees agree)")
    assert "412 flows, mostly from 10.0.0.5, reached 380 distinct destination ports within 30 s" in text
    assert "Flow duration is 40× the benign median" in text
    anomaly = explain.summary_sentence("Anomalous flows", "anomaly", None, None, None, {"flows": 1})
    assert anomaly.startswith("Flagged as unusual by the anomaly detector") and "probab" not in anomaly


def test_flow_context_counts_only_what_is_there():
    flows = pd.DataFrame({"timestamp": ["2017-07-03T08:00:00+00:00", "2017-07-03T08:00:30+00:00"],
                          "src_ip": ["10.0.0.5", "10.0.0.5"], "dst_port": [22, 80]})
    assert explain.flow_context(flows) == {"flows": 2, "top_source": "10.0.0.5", "distinct_sources": 1,
                                           "distinct_destination_ports": 2, "span_seconds": 30.0}
    assert explain.flow_context(pd.DataFrame({"src_ip": [None]})) == {"flows": 1}


# ------------------------------------------------------------------ end to end

@pytest.fixture
def scored(admin):
    def register(frame, name):
        return dataset_service.register_intrusion_dataset(admin, to_cic_csv(frame), f"{name}.csv", name).dataset_id
    train_id = register(cic_like_frame(2500, seed=1), "train")
    intrusion_training_service.train_intrusion_models(
        admin, IntrusionTrainingOptions(dataset_ids=(train_id,), n_estimators=20, activate=True))
    return register(cic_like_frame(900, seed=2), "score")


def test_explains_a_dataset_detection_alert(analyst, scored):
    intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=scored))
    alert = next(a for a in alert_service.list_alerts(analyst) if a.category == "DDoS")
    result = explain.explain_alert(analyst, alert.id)
    assert result.summary.startswith("Flagged as DDoS") and "uncalibrated" in result.summary
    assert result.flows_used == alert.evidence["flows"]  # every flagged flow, not just the example rows
    assert result.reference_rows > 0 and result.deviations and result.importances
    assert result.type_votes and result.type_votes[0]["label"] == "DDoS"
    assert result.anomaly is not None and 0 <= result.anomaly["position"]["score"] <= 1
    assert "BENIGN-labelled" in result.basis["reference"]


def test_explains_a_replayed_alert(analyst, scored):
    engine = ReplayEngine(tick_seconds=3600)
    replay_service.reset_engine_for_tests(engine)
    try:
        engine.start(analyst, scored, "all", speed=30)
        while engine.step(3600):
            pass
    finally:
        replay_service.reset_engine_for_tests(None)
    alert = alert_service.get_alert(analyst, engine.status.alerts[0])[0]
    result = explain.explain_alert(analyst, alert.id)
    assert result.flows_used == alert.evidence["flows"] and result.deviations
    assert result.context["flows"] == alert.evidence["flows"]


def test_congestion_alerts_and_missing_alerts_are_refused(analyst):
    with database_service.session(write=True) as conn:
        alert_id = alert_service.create_alert(conn, alert_type="congestion", severity="medium", category="Congestion",
                                              reason="r", evidence={}, dedup_key="k")
    with pytest.raises(ExplainError, match="PredictNet"):
        explain.explain_alert(analyst, alert_id)
    with pytest.raises(ExplainError, match="not found"):
        explain.explain_alert(analyst, 9999)


def test_explanations_need_a_signed_in_user():
    with pytest.raises(PermissionDenied):
        explain.explain_alert(None, 1)
