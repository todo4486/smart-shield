from __future__ import annotations

import json
import subprocess
import sys

import pytest

from services import (
    bandwidth_service, congestion_prediction_service, congestion_training_service, database_service,
    telemetry_service, traffic_shaping_service,
)
from services.authorization import PermissionDenied
from services.bandwidth_service import BandwidthError, Policy, PolicyClass
from services.traffic_shaping_service import ShapingError
from tests.conftest import audit_rows

M = 1_000_000


def four_class(name="lab", interface="eth0", capacity=100 * M):
    return Policy(name, interface, capacity, (
        PolicyClass("critical", 10 * M, 50 * M, 8, 46),
        PolicyClass("interactive", 10 * M, 60 * M, 4, 34),
        PolicyClass("standard", 5 * M, 90 * M, 2, 0),
        PolicyClass("background", 0, 70 * M, 1, 8),
    ))


@pytest.fixture
def policy(admin):
    return bandwidth_service.save_policy(admin, four_class())


# ---------------------------------------------------------------- policies

def test_policy_crud_is_admin_only_and_audited(admin, analyst):
    with pytest.raises(PermissionDenied):
        bandwidth_service.save_policy(analyst, four_class())
    bandwidth_service.save_policy(admin, four_class())
    bandwidth_service.save_policy(admin, four_class(capacity=200 * M))  # replace
    [saved] = bandwidth_service.list_policies(analyst)
    assert saved.capacity_bps == 200 * M and len(saved.classes) == 4 and saved.classes[0].dscp == 46
    assert len(audit_rows("bandwidth.save_policy", "success")) == 2
    bandwidth_service.delete_policy(admin, "lab")
    assert bandwidth_service.list_policies(admin) == []


def test_infeasible_policy_is_refused_before_saving(admin):
    bad = Policy("bad", None, 10 * M, (PolicyClass("a", 8 * M, 10 * M, 1), PolicyClass("b", 5 * M, 10 * M, 1)))
    with pytest.raises(BandwidthError, match="Infeasible"):
        bandwidth_service.save_policy(admin, bad)
    assert bandwidth_service.list_policies(admin) == []


def test_template_is_labelled_and_valid(admin):
    template = bandwidth_service.template_policy(1000 * M)
    assert template.name.startswith("TEMPLATE")
    bandwidth_service.save_policy(admin, template)


def test_policy_from_editor_rows():
    policy = bandwidth_service.policy_from_entries("p", None, 100 * M, [
        {"traffic_class": "voice", "minimum_mbps": 5, "maximum_mbps": 20, "priority_weight": 3, "dscp": 46.0},
        {"traffic_class": "", "minimum_mbps": 1},  # blank row from the editor is skipped
    ])
    assert len(policy.classes) == 1 and policy.classes[0].minimum_bps == 5 * M and policy.classes[0].dscp == 46


# ---------------------------------------------------------- recommendations

def test_manual_recommendation_is_stored_as_configured_estimate(analyst, policy):
    rec = bandwidth_service.recommend(analyst, "lab", {"critical": 30 * M, "interactive": 40 * M,
                                                       "standard": 50 * M, "background": 60 * M})
    assert rec.id and rec.demand_provenance == "configured"
    assert rec.result.total_allocated_bps <= 90 * M and rec.result.unmet_demand_bps > 0
    [stored] = bandwidth_service.list_recommendations(analyst)
    assert stored["status"] == "proposed" and stored["payload"]["enforcement"] == "none: recommendation only"
    assert stored["unmet_demand_bps"] == rec.result.unmet_demand_bps


def test_scaled_to_measured_throughput_is_labelled_derived(admin, analyst, policy):
    csv = b"timestamp,interface_name,throughput_bps\n2026-10-01T00:00:00Z,eth0,40000000\n2026-10-01T00:05:00Z,eth0,80000000\n"
    session_id = telemetry_service.import_telemetry_csv(
        admin, csv, "t.csv", telemetry_service.TelemetryImportOptions(source_name="s")).session_id
    rec = bandwidth_service.recommend(analyst, "lab", {"critical": 1, "interactive": 1, "standard": 2, "background": 0},
                                      demand_mode="measured", session_id=session_id, save=False)
    demand = {a.name: a.demand_bps for a in rec.result.allocations}
    assert demand["standard"] == pytest.approx(40 * M) and demand["critical"] == pytest.approx(20 * M)
    assert rec.demand_provenance == "derived from measurement" and rec.demand_context["provenance"] == "measured"


def test_forecast_mode_requires_a_stored_forecast(analyst, policy):
    with pytest.raises(BandwidthError, match="No stored PredictNet forecast"):
        bandwidth_service.recommend(analyst, "lab", {"critical": 1}, demand_mode="forecast")


def test_forecast_mode_uses_predicted_utilization_times_capacity(admin, policy):
    from tests.synthetic import telemetry_csv

    session_id = telemetry_service.import_telemetry_csv(
        admin, telemetry_csv(days=2), "t.csv", telemetry_service.TelemetryImportOptions(source_name="s")).session_id
    congestion_training_service.train_forecaster(admin, congestion_training_service.ForecastTrainingOptions(
        session_id=session_id, interface_name="eth0", horizons_minutes=(5,), activate=True))
    run = congestion_prediction_service.generate_forecast(admin, session_id, "eth0")
    rec = bandwidth_service.recommend(admin, "lab", {"critical": 1, "interactive": 1, "standard": 1, "background": 1},
                                      demand_mode="forecast")
    expected_total = run.forecasts[-1].predicted_utilization * 100 * M
    assert rec.result.total_demand_bps == pytest.approx(expected_total, rel=1e-6)
    assert rec.demand_provenance == "derived from forecast" and rec.congestion_context is not None


def test_review_transitions_admin_only(admin, analyst, policy):
    rec = bandwidth_service.recommend(analyst, "lab", {"critical": 10 * M})
    with pytest.raises(PermissionDenied):
        bandwidth_service.set_recommendation_status(analyst, rec.id, "accepted")
    bandwidth_service.set_recommendation_status(admin, rec.id, "accepted")
    with pytest.raises(BandwidthError, match="cannot become"):
        bandwidth_service.set_recommendation_status(admin, rec.id, "proposed")


# ------------------------------------------------------------------ shaping

class FakeTc:
    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on

    def __call__(self, argv):
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        self.calls.append(argv)
        failed = self.fail_on is not None and self.fail_on in argv
        return subprocess.CompletedProcess(argv, 1 if failed else 0, stdout="class htb 1:10", stderr="boom" if failed else "")


@pytest.fixture
def shaping(monkeypatch):
    monkeypatch.setenv("SMART_SHIELD_TC_ENABLED", "true")
    monkeypatch.setenv("SMART_SHIELD_TC_INTERFACES", "eth0")
    monkeypatch.setenv("SMART_SHIELD_TC_BINARY", sys.executable)  # any existing absolute path; never executed
    monkeypatch.setattr(traffic_shaping_service.platform, "system", lambda: "Linux")
    fake = FakeTc()
    traffic_shaping_service.set_runner_for_tests(fake)
    yield fake
    traffic_shaping_service.set_runner_for_tests(None)


def accepted_recommendation(admin):
    rec = bandwidth_service.recommend(admin, "lab", {"critical": 20 * M, "interactive": 30 * M,
                                                     "standard": 30 * M, "background": 30 * M})
    bandwidth_service.set_recommendation_status(admin, rec.id, "accepted")
    return rec


def test_shaping_disabled_by_default(admin, policy):
    state = traffic_shaping_service.availability()
    assert not state.available and any("disabled" in r for r in state.reasons)
    rec = accepted_recommendation(admin)
    with pytest.raises(ShapingError, match="disabled"):
        traffic_shaping_service.apply_recommendation(admin, rec.id, "eth0", confirm_interface="eth0")


def test_shaping_requires_linux(admin, monkeypatch):
    monkeypatch.setenv("SMART_SHIELD_TC_ENABLED", "true")
    monkeypatch.setenv("SMART_SHIELD_TC_INTERFACES", "eth0")
    assert any("Linux" in r for r in traffic_shaping_service.availability(system="Darwin").reasons)


def test_apply_builds_fixed_argv_and_records_action(admin, policy, shaping):
    rec = accepted_recommendation(admin)
    commands = traffic_shaping_service.preview_apply(admin, rec.id, "eth0")
    assert commands[0][1:] == ["qdisc", "del", "dev", "eth0", "root"]  # start from a clean root
    assert commands[1][1:] == ["qdisc", "add", "dev", "eth0", "root", "handle", "1:", "htb", "default", "99"]
    assert any("dsfield" in c for c in commands)  # DSCP filters for classes that have one
    traffic_shaping_service.apply_recommendation(admin, rec.id, "eth0", confirm_interface="eth0")
    assert shaping.calls == commands
    [action] = traffic_shaping_service.action_history(admin)
    assert action["status"] == "succeeded" and action["action_type"] == "apply"
    assert json.loads(action["policy_before_json"]) == {"state": "no shaping applied by Smart Shield"}
    assert bandwidth_service.list_recommendations(admin)[0]["status"] == "applied"
    assert len(audit_rows("shaping.apply", "success")) == 1


def test_apply_guards(admin, analyst, policy, shaping):
    rec = bandwidth_service.recommend(admin, "lab", {"critical": 10 * M})
    with pytest.raises(ShapingError, match="accepted"):
        traffic_shaping_service.apply_recommendation(admin, rec.id, "eth0", confirm_interface="eth0")
    bandwidth_service.set_recommendation_status(admin, rec.id, "accepted")
    with pytest.raises(ShapingError, match="Type the interface"):
        traffic_shaping_service.apply_recommendation(admin, rec.id, "eth0", confirm_interface="eth1")
    with pytest.raises(ShapingError, match="not allow-listed"):
        traffic_shaping_service.apply_recommendation(admin, rec.id, "wlan0", confirm_interface="wlan0")
    with pytest.raises(ShapingError, match="Invalid interface"):
        traffic_shaping_service.apply_recommendation(admin, rec.id, "eth0; rm -rf /", confirm_interface="eth0; rm -rf /")
    with pytest.raises(PermissionDenied):
        traffic_shaping_service.apply_recommendation(analyst, rec.id, "eth0", confirm_interface="eth0")
    assert shaping.calls == []


def test_failed_apply_is_recorded_and_reported(admin, policy, shaping):
    shaping.fail_on = "filter"
    rec = accepted_recommendation(admin)
    with pytest.raises(ShapingError, match="Applying failed"):
        traffic_shaping_service.apply_recommendation(admin, rec.id, "eth0", confirm_interface="eth0")
    [action] = traffic_shaping_service.action_history(admin)
    assert action["status"] == "failed" and "boom" in action["error_message"]
    assert bandwidth_service.list_recommendations(admin)[0]["status"] == "accepted"


def test_rollback_restores_previous_state(admin, policy, shaping):
    first = accepted_recommendation(admin)
    traffic_shaping_service.apply_recommendation(admin, first.id, "eth0", confirm_interface="eth0")
    second = accepted_recommendation(admin)
    traffic_shaping_service.apply_recommendation(admin, second.id, "eth0", confirm_interface="eth0")
    shaping.calls.clear()
    traffic_shaping_service.rollback(admin, "eth0", confirm_interface="eth0")
    # Rolling back the second apply re-applies the first one's classes.
    assert shaping.calls[0][1:4] == ["qdisc", "del", "dev"] and shaping.calls[1][1:4] == ["qdisc", "add", "dev"]
    shaping.calls.clear()
    traffic_shaping_service.rollback(admin, "eth0", confirm_interface="eth0")
    # Rolling back the first apply removes shaping entirely.
    assert shaping.calls == [[sys.executable, "qdisc", "del", "dev", "eth0", "root"]]
    with pytest.raises(ShapingError, match="no applied policy"):
        traffic_shaping_service.rollback(admin, "eth0", confirm_interface="eth0")


def test_emergency_disable_removes_root_qdisc(admin, policy, shaping):
    ids = traffic_shaping_service.emergency_disable(admin)
    assert len(ids) == 1 and shaping.calls == [[sys.executable, "qdisc", "del", "dev", "eth0", "root"]]


def test_no_shell_true_anywhere_in_the_codebase():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    offenders = [str(p) for p in root.rglob("*.py")
                 if ".venv" not in p.parts and "tests" not in p.parts and "shell=True" in p.read_text()]
    assert offenders == []
