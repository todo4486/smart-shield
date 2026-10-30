"""M2: simulation mode. Synthetic traffic in memory, real flow extractor and models, kept apart from real data."""
from __future__ import annotations

import ast
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from services import (
    data_source, database_service, dataset_service, header_service, incident_correlation_service, intrusion_inference_service,
    intrusion_training_service, live_network_service, monitoring_service, session_service, simulation_service as sim,
)
from services.authorization import PermissionDenied
from services.flow_extractor import FlowTable
from services.host_telemetry import HostMeter
from services.intrusion_inference_service import DetectionOptions
from services.intrusion_training_service import IntrusionTrainingOptions
from services.simulation_service import SimulationEngine, SimulationError, TrafficGenerator
from services.timeutil import utc_now
from tests.conftest import audit_rows

ROOT = Path(__file__).resolve().parent.parent
M = 1e6
T0 = (datetime.now(timezone.utc) - timedelta(minutes=30)).timestamp()


def _register_train_day(principal):
    data = (ROOT / "samples" / "SAMPLE_intrusion_train_day_synthetic.csv").read_bytes()
    return dataset_service.register_intrusion_dataset(principal, data, "train.csv", "train day").dataset_id


def _train(principal, feature_set="live_compatible", activate=True):
    return intrusion_training_service.train_intrusion_models(principal, IntrusionTrainingOptions(
        dataset_ids=(_register_train_day(principal),), feature_set=feature_set, n_estimators=30, activate=activate))


@pytest.fixture
def engine():
    engine = SimulationEngine(tick_seconds=3600)  # the thread never ticks; tests call step() themselves
    sim.reset_engine_for_tests(engine)
    yield engine
    if engine.status.running:
        engine.stop(None)
    sim.reset_engine_for_tests(None)


def _run(engine, principal, scenario, *, seconds=40, delay=5, start=T0):
    session_id = engine.start(principal, scenario, capacity_bps=100 * M, attack_delay_seconds=delay, duration_seconds=seconds)
    now = start
    while engine.step(now):
        now += 1
    return session_id


# ------------------------------------------------------------------ the link model (pure)

def test_full_link_cuts_every_source_equally():
    assert sim.delivered_share([10, 20], 100) == 1.0
    assert sim.delivered_share([100, 100], 100) == 0.5
    assert sim.delivered_share([], 100) == 1.0


def test_link_rates_follow_direction():
    sources = sim.baseline_sources(100 * M)
    assert all(s.inbound for s in sources)
    rates = sim.link_rates(sources, [x.offered_bps for x in sources])
    assert rates["incoming_bps"] == pytest.approx(40 * M) and rates["outgoing_bps"] == 0
    hog = sim.attack_sources("bandwidth_hog", 100 * M)
    assert sim.link_rates(hog, [x.offered_bps * 0.5 for x in hog])["outgoing_bps"] == pytest.approx(37.5 * M)


def test_scenarios_use_documentation_addresses_for_outside_hosts():
    for scenario in sim.SCENARIOS:
        for source in sim.baseline_sources(100 * M) + sim.attack_sources(scenario, 100 * M):
            assert source.client.startswith("10.20.")
            assert source.server.startswith(("198.51.100.", "203.0.113."))
    with pytest.raises(SimulationError):
        sim.attack_sources("nope", 100 * M)


def test_attack_starts_after_the_delay_and_only_then():
    generator = TrafficGenerator("ddos", 100 * M, attack_delay_seconds=2)
    first = generator.tick(T0)
    assert not any(not s.legitimate for s in first["sources"]) and first["share"] == 1.0
    generator.tick(T0 + 1)
    third = generator.tick(T0 + 2)
    assert any(not s.legitimate for s in third["sources"])
    assert third["offered_bps"] == pytest.approx(130 * M) and third["share"] == pytest.approx(100 / 130)
    assert third["throughput_bps"] == pytest.approx(100 * M)  # never above capacity


def test_generator_is_deterministic_for_a_seed():
    a, b = TrafficGenerator("port_scan", 10 * M, seed=3), TrafficGenerator("port_scan", 10 * M, seed=3)
    assert a.tick(T0)["packets"] == b.tick(T0)["packets"]
    assert TrafficGenerator("port_scan", 10 * M, attack_delay_seconds=0, seed=4).tick(T0)["packets"] != \
        TrafficGenerator("port_scan", 10 * M, attack_delay_seconds=0, seed=5).tick(T0)["packets"]


def test_flow_packets_go_through_the_real_flow_table():
    source = sim.baseline_sources(100 * M)[2]
    table = FlowTable()
    finished = []
    for packet in sim.flow_packets(source, T0, 40000, 443):
        finished.extend(table.add(packet))
    assert len(finished) == 1 and finished[0]["src_ip"] == source.client and finished[0]["end_reason"] == "tcp fin/rst"
    assert finished[0]["packet_count"] == 21  # 8 forward + 12 backward + FIN


def test_attack_flows_are_opened_by_the_outside_host():
    source = sim.attack_sources("ddos", 100 * M)[0]
    packets = sim.attacker_flow_packets(source, T0, 40000, 80)
    assert packets[0][1] == source.server and packets[0][2] == source.client and packets[0][4] == 80


def test_meter_totals_are_exact_and_respect_the_cut():
    meter = HostMeter()
    source = sim.baseline_sources(100 * M)[0]
    sim.meter_totals(meter, [source], [source.offered_bps * 0.5], 1.0)
    rows = {r["host"]: r for r in meter.sample(1.0)}
    assert rows[source.client]["received_bps"] == pytest.approx(source.offered_bps * 0.5, rel=1e-6)
    assert rows[source.server]["sent_bps"] == pytest.approx(source.offered_bps * 0.5, rel=1e-6)
    assert rows[source.client]["sent_bps"] == 0


def test_simulation_code_cannot_touch_a_network():
    tree = ast.parse((ROOT / "services" / "simulation_service.py").read_text())
    imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imported |= {(node.module or "").split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not imported & {"socket", "scapy", "subprocess", "requests", "urllib", "http", "asyncio", "ssl"}


# ------------------------------------------------------------------ the engine with the real models

def test_real_models_identify_scenarios_and_do_not_flag_normal_traffic(admin, analyst, engine):
    _train(admin)
    _run(engine, analyst, "normal", seconds=30)
    assert engine.status.flows_scored > 100 and engine.status.flagged == 0 and engine.status.alerts == []
    _run(engine, analyst, "ddos")
    assert engine.status.by_category.get("DDoS", 0) > 0 and engine.status.alerts
    _run(engine, analyst, "port_scan")
    assert engine.status.by_category.get("PortScan", 0) > 0
    _run(engine, analyst, "bandwidth_hog", start=T0 + 200)
    assert engine.status.flagged > 0  # the model decides what to call it; nothing is scripted
    assert engine.status.loss_ratio > 0


def test_everything_stored_is_labelled_as_simulated(admin, analyst, engine):
    _train(admin)
    session_id = _run(engine, analyst, "ddos")
    with database_service.session() as conn:
        session = conn.execute("SELECT * FROM monitoring_sessions WHERE id = ?", (session_id,)).fetchone()
        flows = conn.execute("SELECT provenance, feature_summary_json FROM network_flows WHERE session_id = ?",
                             (session_id,)).fetchall()
        metrics = conn.execute("SELECT * FROM network_metrics WHERE session_id = ?", (session_id,)).fetchall()
        hosts = conn.execute("SELECT DISTINCT provenance FROM host_metrics WHERE session_id = ?", (session_id,)).fetchall()
        alert = conn.execute("SELECT reason, evidence_json FROM alerts WHERE session_id = ? LIMIT 1", (session_id,)).fetchone()
    assert session["source_type"] == "simulation" and session["status"] == "STOPPED"
    assert "No packets were sent" in json.loads(session["configuration_json"])["note"]
    assert {f["provenance"] for f in flows} == {"derived"} and json.loads(flows[0]["feature_summary_json"])["simulated"]
    assert {m["provenance"] for m in metrics} == {"derived"} and "simulation" in metrics[0]["measurement_method"]
    assert {m["source_name"] for m in metrics} == {"simulation"} and all(m["latency_ms"] is None for m in metrics)
    assert [h[0] for h in hosts] == ["derived"]
    assert alert["reason"].startswith("Simulation:") and json.loads(alert["evidence_json"])["source"] == "simulation"
    assert data_source.classify("simulation").label == "SIMULATION"


def test_live_panel_and_header_show_simulation_as_simulation(admin, analyst, engine):
    _train(admin)
    session_id = engine.start(analyst, "ddos", capacity_bps=100 * M, attack_delay_seconds=0, duration_seconds=60)
    for i in range(12):
        engine.step(T0 + i)
    view = live_network_service.snapshot(analyst, simulation_session_id=session_id)
    assert view.running and view.provenance == "simulated" and view.source.label == "SIMULATION"
    assert view.capacity_bps == 100 * M and view.utilization == pytest.approx(1.0) and view.available_bps == pytest.approx(0, abs=1)
    assert any("No packets exist" in n for n in view.notes)
    assert any(h.status == "suspicious" and h.host.startswith("203.0.113.") for h in view.hosts)
    header = header_service.get_header(analyst, simulation_running=True, simulation_flows_per_second=30.0)
    assert header.source.label == "SIMULATION" and header.flows_per_second == 30.0 and header.flows_basis == "simulation"
    engine.stop(None)
    stored = live_network_service.snapshot(analyst)
    assert not stored.running and stored.provenance == "simulated" and "not the network right now" in stored.notes[0]


def test_simulated_alerts_never_join_real_or_replayed_incidents(admin, analyst, engine):
    _train(admin)
    data = (ROOT / "samples" / "SAMPLE_intrusion_test_day_synthetic.csv").read_bytes()
    dataset_id = dataset_service.register_intrusion_dataset(admin, data, "test.csv", "test day").dataset_id
    intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=dataset_id))
    _run(engine, analyst, "ddos")
    incident_correlation_service.correlate(analyst)
    with database_service.session() as conn:
        rows = conn.execute(
            "SELECT i.is_simulation, s.source_type FROM incidents i JOIN incident_alerts ia ON ia.incident_id = i.id "
            "JOIN alerts a ON a.id = ia.alert_id JOIN monitoring_sessions s ON s.id = a.session_id").fetchall()
    assert {r["is_simulation"] for r in rows} == {0, 1}
    assert all((r["source_type"] == "simulation") == bool(r["is_simulation"]) for r in rows)
    incident_id = engine.status.incidents[0]
    assert incident_correlation_service.get_incident(analyst, incident_id).is_simulation


# ------------------------------------------------------------------ guards

def test_full_feature_model_is_rejected_never_zero_filled(admin, engine):
    _train(admin, feature_set="full")
    with pytest.raises(SimulationError, match="never zero-filled"):
        engine.start(admin, "ddos")
    assert not engine.status.running


def test_a_registered_live_compatible_model_is_enough(admin, engine):
    _train(admin, activate=False)
    classifier, detector = sim.live_compatible_model(admin)
    assert classifier is not None and detector is not None and not classifier.is_active
    engine.start(admin, "normal", duration_seconds=10)
    assert engine.status.running and not engine.status.model_active


def test_start_is_validated_and_audited(admin, analyst, engine):
    _train(admin)
    for kwargs, message in (({"capacity_bps": 1.0}, "capacity"), ({"duration_seconds": 1}, "seconds"),
                            ({"attack_delay_seconds": -1}, "delay")):
        with pytest.raises(SimulationError, match=message):
            engine.start(analyst, "ddos", **kwargs)
    with pytest.raises(SimulationError, match="Unknown"):
        engine.start(analyst, "nope")
    with pytest.raises(PermissionDenied):
        engine.start(None, "ddos")
    engine.start(analyst, "ddos", duration_seconds=30)
    with pytest.raises(SimulationError, match="already running"):
        engine.start(analyst, "ddos")
    engine.stop(analyst)
    assert audit_rows("simulation.start", "success") and audit_rows("simulation.stop", "success")
    assert audit_rows("simulation.start", "denied")


def test_clear_is_admin_only_and_keeps_real_data(admin, analyst, engine):
    _train(admin)
    data = (ROOT / "samples" / "SAMPLE_intrusion_test_day_synthetic.csv").read_bytes()
    dataset_id = dataset_service.register_intrusion_dataset(admin, data, "test.csv", "test day").dataset_id
    report = intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=dataset_id))
    _run(engine, analyst, "ddos")
    with pytest.raises(PermissionDenied):
        sim.clear_simulation_data(analyst)
    assert audit_rows("simulation.clear", "denied")
    counts = sim.clear_simulation_data(admin)
    assert counts["sessions"] == 1 and counts["flows"] > 0 and counts["host_samples"] > 0 and counts["alerts"] > 0
    assert not any(sim.data_counts(admin).values())
    with database_service.session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM network_flows").fetchone()[0] == report.flows_stored > 0
        assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == len(report.alerts_created) > 0
    assert audit_rows("simulation.clear", "success")


def test_engine_stops_if_its_session_is_closed_elsewhere(admin, engine):
    _train(admin)
    session_id = engine.start(admin, "normal", duration_seconds=30)
    assert monitoring_service.recover_interrupted_sessions("simulation") == 1
    assert engine.step(T0) is False and not engine.status.running
    with database_service.session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM network_metrics WHERE session_id = ?", (session_id,)).fetchone()[0] == 0


def test_migration_keeps_older_sessions(tmp_path):
    from config import MIGRATIONS_DIR
    import shutil
    early = tmp_path / "early"
    early.mkdir()
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        if path.name < "011":
            shutil.copy(path, early / path.name)
    db = tmp_path / "upgrade.db"
    database_service.run_migrations(db, early)
    conn = database_service.connect(db)
    conn.execute("INSERT INTO monitoring_sessions (source_type, started_at, status) VALUES "
                 "('replay', '2026-01-01T00:00:00+00:00', 'STOPPED')")
    conn.execute("INSERT INTO host_metrics (session_id, timestamp, host, sent_bps, received_bps, sent_pps, received_pps, "
                 "active_connections) VALUES (1, '2026-01-01T00:00:00+00:00', 'a', 1, 1, 1, 1, 1)")
    conn.close()
    assert database_service.run_migrations(db)[0] == "011"
    conn = database_service.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM host_metrics").fetchone()[0] == 1
    conn.execute("INSERT INTO monitoring_sessions (source_type, started_at, status) VALUES "
                 "('simulation', '2026-01-01T00:00:00+00:00', 'STOPPED')")
    conn.close()


def test_page_renders_for_both_roles(admin_user, analyst_user):
    for user in (admin_user, analyst_user):
        at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
        at.session_state[session_service.USER_ID_KEY] = user.id
        at.session_state[session_service.LAST_ACTIVITY_KEY] = utc_now()
        at.switch_page("views/simulation.py")
        at.run()
        assert not at.exception
        assert any("No live-compatible model yet" in w.value for w in at.warning)
