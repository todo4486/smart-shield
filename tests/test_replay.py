"""Phase 3: replay / demo mode (migration 008, engine, data separation, clear)."""
from __future__ import annotations

import json
import shutil

import numpy as np
import pytest

from config import MIGRATIONS_DIR
from services import (
    database_service, dataset_service, incident_correlation_service, intrusion_inference_service,
    intrusion_training_service, monitoring_service, replay_service,
)
from services.authorization import PermissionDenied
from services.intrusion_inference_service import DetectionOptions
from services.intrusion_training_service import IntrusionTrainingOptions
from services.replay_service import ReplayEngine, ReplayError
from tests.conftest import audit_rows
from tests.synthetic import cic_like_frame, to_cic_csv


def _register(principal, frame, name):
    return dataset_service.register_intrusion_dataset(principal, to_cic_csv(frame), f"{name}.csv", name).dataset_id


@pytest.fixture
def trained(admin):
    train_id = _register(admin, cic_like_frame(2500, seed=1), "train")
    intrusion_training_service.train_intrusion_models(
        admin, IntrusionTrainingOptions(dataset_ids=(train_id,), n_estimators=20, activate=True))
    return _register(admin, cic_like_frame(900, seed=2), "score")


@pytest.fixture
def engine():
    engine = ReplayEngine(tick_seconds=3600)  # the thread never ticks; tests call step() themselves
    replay_service.reset_engine_for_tests(engine)
    yield engine
    if engine.status.running:
        engine.stop(None)
    replay_service.reset_engine_for_tests(None)


def _count(sql, *args):
    with database_service.session() as conn:
        return conn.execute(sql, args).fetchone()[0]


# ------------------------------------------------------------------ migration

def test_migration_008_rebuild_keeps_sessions_and_child_rows(tmp_path):
    early = tmp_path / "early"
    early.mkdir()
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        if path.name < "008":
            shutil.copy(path, early / path.name)
    db = tmp_path / "upgrade.db"
    database_service.run_migrations(db, early)
    conn = database_service.connect(db)
    conn.execute("INSERT INTO monitoring_sessions (source_type, started_at, status) VALUES "
                 "('dataset', '2026-01-01T00:00:00+00:00', 'STOPPED')")
    conn.execute("INSERT INTO network_flows (session_id, timestamp, src_ip) VALUES (1, '2026-01-01T00:00:00+00:00', 'a')")
    conn.execute("INSERT INTO network_metrics (session_id, timestamp, source_name, measurement_method, provenance, "
                 "validity_status) VALUES (1, '2026-01-01T00:00:00+00:00', 's', 'm', 'measured', 'valid')")
    conn.close()
    assert database_service.run_migrations(db)[0] == "008"
    conn = database_service.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM network_flows").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM network_metrics").fetchone()[0] == 1
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    conn.execute("INSERT INTO monitoring_sessions (source_type, started_at, status) VALUES "
                 "('replay', '2026-01-01T00:00:00+00:00', 'STOPPED')")
    # Foreign keys still cascade from the rebuilt table.
    conn.execute("DELETE FROM monitoring_sessions WHERE id = 1")
    assert conn.execute("SELECT COUNT(*) FROM network_flows").fetchone()[0] == 0
    conn.close()


def test_failed_foreign_key_check_rolls_the_rebuild_back(tmp_path):
    migrations = tmp_path / "m"
    migrations.mkdir()
    (migrations / "001_base.sql").write_text(
        "CREATE TABLE parent (id INTEGER PRIMARY KEY);\n"
        "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent (id));\n")
    (migrations / "002_rebuild.sql").write_text(
        "-- requires: foreign_keys_off\nINSERT INTO child (parent_id) VALUES (99);\n")
    db = tmp_path / "x.db"
    with pytest.raises(database_service.MigrationError, match="Foreign key check failed"):
        database_service.run_migrations(db, migrations)
    conn = database_service.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM child").fetchone()[0] == 0
    assert [r[0] for r in conn.execute("SELECT version FROM schema_migrations")] == ["001"]
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    conn.close()


# ------------------------------------------------------------------ pure helpers

def test_scenarios_only_offer_what_the_dataset_contains():
    keys = [s.key for s in replay_service.scenarios_for({"BENIGN": 10, "DDoS": 5, "PortScan": 3})]
    assert keys[0] == "all" and "scan_ddos" in keys and "benign" in keys
    assert "brute_force" not in keys  # no Patator rows → no brute-force scenario
    brute = replay_service.scenarios_for({"BENIGN": 10, "FTP-Patator": 4})
    assert any(s.key == "brute_force" and s.labels == ("BENIGN", "FTP-Patator") for s in brute)
    assert not any(s.key == "benign" for s in replay_service.scenarios_for({"DDoS": 4}))
    assert replay_service.scenarios_for({"BENIGN": 0, "DDoS": 4})[0].description.count("BENIGN") == 0


def test_clock_and_windows():
    assert replay_service.advance(10.0, 2.0, 30) == 70.0
    assert replay_service.advance(10.0, -1.0, 5) == 10.0
    with pytest.raises(ReplayError):
        replay_service.advance(0, 1, 7)
    times = np.array([0.0, 1.0, 1.0, 5.0, 9.0])
    assert replay_service.rows_due(times, 0, 1.0) == 3
    assert replay_service.rows_due(times, 3, 1.0) == 3  # never moves backwards
    assert replay_service.rows_due(times, 0, 100.0, limit=2) == 2
    assert replay_service.window_start(299.9, 300) == 0 and replay_service.window_start(300, 300) == 300
    assert replay_service.complete_windows([0, 300, 600], 650, 300) == [0, 300]
    assert replay_service.complete_windows([0, 300, 600], 650, 300, finished=True) == [0, 300, 600]


def test_throughput_sample_never_invents_utilization():
    sample = replay_service.throughput_sample(7500, 10, 60, None)
    assert sample["throughput_bps"] == 1000.0 and sample["utilization_ratio"] is None
    assert replay_service.throughput_sample(7500, 10, 60, 2000)["utilization_ratio"] == 0.5
    assert replay_service.throughput_sample(7500, 10, 60, 10)["utilization_ratio"] == 1.0


# ------------------------------------------------------------------ engine

def test_replay_runs_through_the_detection_pipeline(analyst, trained, engine):
    session_id = engine.start(analyst, trained, "all", speed=30)
    assert engine.status.running and engine.status.rows_total == 900
    assert engine.step(60) is True  # first minute of dataset time
    assert 0 < engine.status.rows_done < 900
    while engine.step(3600):
        pass
    status = engine.status
    assert status.finished and not status.running and status.rows_done == 900
    with database_service.session() as conn:
        session = conn.execute("SELECT * FROM monitoring_sessions WHERE id = ?", (session_id,)).fetchone()
        flows = conn.execute("SELECT COUNT(*) FROM network_flows WHERE session_id = ?", (session_id,)).fetchone()[0]
        flagged = conn.execute("SELECT COUNT(*) FROM network_flows WHERE session_id = ? "
                               "AND intrusion_prediction IS NOT NULL", (session_id,)).fetchone()[0]
        metrics = conn.execute("SELECT * FROM network_metrics WHERE session_id = ?", (session_id,)).fetchall()
        incidents = conn.execute("SELECT is_replay FROM incidents").fetchall()
    assert session["source_type"] == "replay" and session["status"] == "STOPPED"
    assert flows == 900 and flagged == status.flagged > 0
    assert metrics and all(m["provenance"] == "derived" and m["utilization_ratio"] is None for m in metrics)
    assert status.alerts and incidents and all(r["is_replay"] == 1 for r in incidents)
    assert len(audit_rows("replay.start", "success")) == 1


def test_detection_and_replay_give_the_same_verdicts(analyst, trained, engine):
    report = intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=trained))
    engine.start(analyst, trained, "all", speed=30)
    while engine.step(3600):
        pass
    replayed = _count("SELECT COUNT(*) FROM network_flows f JOIN monitoring_sessions s ON s.id = f.session_id "
                      "WHERE s.source_type = 'replay' AND f.intrusion_prediction IS NOT NULL")
    assert replayed == report.flagged_attack + report.flagged_anomaly_only


def test_replay_alerts_never_join_real_incidents(analyst, trained, engine):
    intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=trained))
    engine.start(analyst, trained, "all", speed=30)
    while engine.step(3600):
        pass
    incident_correlation_service.correlate(analyst)
    with database_service.session() as conn:
        rows = conn.execute(
            "SELECT i.id, i.is_replay, s.source_type FROM incidents i JOIN incident_alerts ia ON ia.incident_id = i.id "
            "JOIN alerts a ON a.id = ia.alert_id JOIN monitoring_sessions s ON s.id = a.session_id").fetchall()
    assert {r["is_replay"] for r in rows} == {0, 1}  # same timestamps, but two separate incident sets
    assert all((r["source_type"] == "replay") == bool(r["is_replay"]) for r in rows)


def test_controls_are_validated_and_audited(analyst, trained, engine):
    with pytest.raises(ReplayError, match="not available"):
        engine.start(analyst, trained, "brute_force")
    with pytest.raises(ReplayError, match="Speed"):
        engine.start(analyst, trained, "all", speed=3)
    engine.start(analyst, trained, "scan_ddos", speed=5)
    with pytest.raises(ReplayError, match="already running"):
        engine.start(analyst, trained, "all")
    engine.pause(analyst)
    assert engine.status.paused
    engine.resume(analyst)
    engine.set_speed(analyst, 10)
    assert engine.status.speed == 10
    first = engine.status.session_id
    second = engine.restart(analyst)
    assert second != first and engine.status.scenario_key == "scan_ddos"
    for action in ("replay.pause", "replay.resume", "replay.speed", "replay.stop"):
        assert audit_rows(action, "success"), action


def test_scenario_filter_only_replays_its_labels(analyst, trained, engine):
    engine.start(analyst, trained, "benign", speed=30)
    while engine.step(3600):
        pass
    with database_service.session() as conn:
        rows = conn.execute("SELECT feature_summary_json FROM network_flows").fetchall()
    assert rows and {json.loads(r[0])["dataset_label"] for r in rows} == {"BENIGN"}


def test_replay_needs_an_active_classifier(admin, engine):
    dataset_id = _register(admin, cic_like_frame(200, seed=3), "plain")
    with pytest.raises(ReplayError, match="no active intrusion classifier"):
        engine.start(admin, dataset_id, "all")


def test_clear_is_admin_only_and_keeps_real_data(admin, analyst, trained, engine):
    intrusion_inference_service.run_detection(analyst, DetectionOptions(dataset_id=trained))
    engine.start(analyst, trained, "all", speed=30)
    while engine.step(3600):
        pass
    incident_correlation_service.correlate(analyst)
    real_flows = _count("SELECT COUNT(*) FROM network_flows f JOIN monitoring_sessions s ON s.id = f.session_id "
                        "WHERE s.source_type = 'dataset'")
    real_alerts = _count("SELECT COUNT(*) FROM alerts a JOIN monitoring_sessions s ON s.id = a.session_id "
                         "WHERE s.source_type = 'dataset'")
    real_incidents = _count("SELECT COUNT(*) FROM incidents WHERE is_replay = 0")
    with pytest.raises(PermissionDenied):
        replay_service.clear_replay_data(analyst)
    assert audit_rows("replay.clear", "denied")
    counts = replay_service.clear_replay_data(admin)
    assert counts["flows"] == 900 and counts["alerts"] > 0 and counts["incidents"] > 0
    assert replay_service.replay_counts(admin) == {k: 0 for k in counts}
    assert _count("SELECT COUNT(*) FROM network_flows") == real_flows > 0
    assert _count("SELECT COUNT(*) FROM alerts") == real_alerts > 0
    assert _count("SELECT COUNT(*) FROM incidents") == real_incidents > 0
    assert audit_rows("replay.clear", "success")


def test_restart_recovery_only_closes_its_own_source_type(admin):
    with database_service.session(write=True) as conn:
        live = monitoring_service.create_session(conn, user_id=admin.user_id,
                                                 source_type=monitoring_service.SourceType.LIVE_CAPTURE)
        replay = monitoring_service.create_session(conn, user_id=admin.user_id,
                                                   source_type=monitoring_service.SourceType.REPLAY)
    assert monitoring_service.recover_interrupted_sessions("replay") == 1
    with database_service.session() as conn:
        status = dict(conn.execute("SELECT id, status FROM monitoring_sessions").fetchall())
    assert status == {live: "STARTING", replay: "ERROR"}


def test_replay_stops_when_its_session_is_closed_elsewhere(analyst, trained, engine):
    session_id = engine.start(analyst, trained, "all", speed=30)
    monitoring_service.recover_interrupted_sessions("replay")  # e.g. a second engine after a code reload
    assert engine.step(60) is False and not engine.status.running
    assert _count("SELECT COUNT(*) FROM network_flows WHERE session_id = ?", session_id) == 0
