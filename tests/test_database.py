from __future__ import annotations

import sqlite3

import pytest

from config import SCHEMA_FILE
from scripts import manage
from services import auth_service, database_service
from services.timeutil import utc_now_iso

NOW = "2026-10-22T06:00:00.000000+00:00"
SHA = "a" * 64

EXPECTED_TABLES = {
    # SPEC §11
    "users", "monitoring_sessions", "network_flows", "network_metrics", "congestion_predictions", "alerts",
    "bandwidth_policies", "bandwidth_recommendations", "policy_actions", "model_registry", "audit_logs",
    # CLAUDE.md extras
    "login_attempts", "alert_events", "incidents", "incident_alerts", "app_settings", "schema_migrations",
}


def _tables():
    with database_service.session() as conn:
        return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")}


def _insert_session(conn, status="RUNNING"):
    return conn.execute(
        "INSERT INTO monitoring_sessions (source_type, started_at, status) VALUES ('dataset', ?, ?)", (NOW, status)
    ).lastrowid


def _insert_model(conn, family="intrusion_classifier", version="1", active=0):
    return conn.execute(
        "INSERT INTO model_registry (model_family, model_name, version, artifact_path, artifact_sha256, "
        "feature_schema_version, trained_at, is_active) VALUES (?, 'rf', ?, 'artifacts/x.joblib', ?, 'v1', ?, ?)",
        (family, version, SHA, NOW, active),
    ).lastrowid


def test_all_tables_exist():
    assert EXPECTED_TABLES <= _tables()


def test_connection_pragmas(temp_db):
    conn = database_service.connect()
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == database_service.BUSY_TIMEOUT_MS
        assert conn.isolation_level is None
    finally:
        conn.close()


def test_migrations_are_idempotent():
    assert database_service.run_migrations() == []
    assert database_service.run_migrations() == []
    with database_service.session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == len(
            database_service.discover_migrations()
        )


def test_migrations_preserve_existing_data():
    user = auth_service.register("Keep Me", "keep@example.com", "CorrectHorse42")
    database_service.run_migrations()
    assert auth_service.get_user(user.id) is not None


def test_failed_migration_rolls_back(tmp_path):
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "001_ok.sql").write_text("CREATE TABLE a (id INTEGER PRIMARY KEY);\n")
    (migrations / "002_bad.sql").write_text("CREATE TABLE b (id INTEGER PRIMARY KEY);\nTHIS IS NOT SQL;\n")
    db = tmp_path / "m.db"
    with pytest.raises(database_service.MigrationError):
        database_service.run_migrations(db, migrations)
    conn = database_service.connect(db)
    try:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        versions = [r[0] for r in conn.execute("SELECT version FROM schema_migrations")]
    finally:
        conn.close()
    assert "a" in names and "b" not in names
    assert versions == ["001"]


def test_schema_sql_has_not_drifted():
    assert SCHEMA_FILE.exists(), "Run: python -m scripts.manage dump-schema"
    assert SCHEMA_FILE.read_text(encoding="utf-8") == database_service.generate_schema_sql(), (
        "database/schema.sql is out of date. Run: python -m scripts.manage dump-schema"
    )


def test_dump_schema_check_command_passes():
    assert manage.main(["dump-schema", "--check"]) == 0


def test_session_rolls_back_on_error():
    with pytest.raises(RuntimeError):
        with database_service.session(write=True) as conn:
            conn.execute(
                "INSERT INTO app_settings (key, value_json, updated_at) VALUES ('demo.key', '1', ?)", (NOW,)
            )
            raise RuntimeError("boom")
    with database_service.session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM app_settings").fetchone()[0] == 0


@pytest.mark.parametrize(
    "sql, params",
    [
        ("INSERT INTO users (name, email, password_hash, role, created_at, updated_at) VALUES ('X', 'x@example.com', 'h', 'superuser', ?, ?)", (NOW, NOW)),
        ("INSERT INTO users (name, email, password_hash, role, created_at, updated_at) VALUES ('X', 'X@Example.com', 'h', 'analyst', ?, ?)", (NOW, NOW)),
        ("INSERT INTO users (name, email, password_hash, role, created_at, updated_at) VALUES ('  ', 'y@example.com', 'h', 'analyst', ?, ?)", (NOW, NOW)),
        ("INSERT INTO monitoring_sessions (source_type, started_at, status) VALUES ('dataset', ?, 'PAUSED')", (NOW,)),
        ("INSERT INTO monitoring_sessions (source_type, started_at, ended_at, status) VALUES ('dataset', ?, '2000-01-01', 'STOPPED')", (NOW,)),
        ("INSERT INTO network_metrics (timestamp, source_name, utilization_ratio, measurement_method, provenance, validity_status) VALUES (?, 's', 1.5, 'csv', 'measured', 'valid')", (NOW,)),
        ("INSERT INTO network_metrics (timestamp, source_name, packet_loss_ratio, measurement_method, provenance, validity_status) VALUES (?, 's', -0.1, 'csv', 'measured', 'valid')", (NOW,)),
        ("INSERT INTO network_metrics (timestamp, source_name, measurement_method, provenance, validity_status) VALUES (?, 's', 'csv', 'guessed', 'valid')", (NOW,)),
        ("INSERT INTO congestion_predictions (timestamp, source_name, forecast_horizon_seconds, congestion_risk, model_version) VALUES (?, 's', 300, 'apocalyptic', 'v1')", (NOW,)),
        ("INSERT INTO congestion_predictions (timestamp, source_name, forecast_horizon_seconds, congestion_risk, model_version, provenance) VALUES (?, 's', 300, 'high', 'v1', 'measured')", (NOW,)),
        ("INSERT INTO alerts (alert_type, severity, category, reason, created_at) VALUES ('security', 'urgent', 'c', 'r', ?)", (NOW,)),
        ("INSERT INTO bandwidth_policies (policy_name, configured_capacity_bps, traffic_class, minimum_bps, maximum_bps, priority_weight, created_at, updated_at) VALUES ('p', 100, 'c', 50, 40, 1, ?, ?)", (NOW, NOW)),
        ("INSERT INTO bandwidth_policies (policy_name, configured_capacity_bps, traffic_class, minimum_bps, maximum_bps, priority_weight, created_at, updated_at) VALUES ('p', 100, 'c', 0, 200, 1, ?, ?)", (NOW, NOW)),
        ("INSERT INTO model_registry (model_family, model_name, version, artifact_path, artifact_sha256, feature_schema_version, trained_at) VALUES ('magic', 'm', '1', 'p', '" + SHA + "', 'v1', ?)", (NOW,)),
        ("INSERT INTO model_registry (model_family, model_name, version, artifact_path, artifact_sha256, feature_schema_version, trained_at) VALUES ('anomaly_detector', 'm', '1', 'p', 'not-a-hash', 'v1', ?)", (NOW,)),
        ("INSERT INTO audit_logs (action, outcome, created_at) VALUES ('x', 'maybe', ?)", (NOW,)),
        ("INSERT INTO app_settings (key, value_json, updated_at) VALUES ('Bad Key!', '1', ?)", (NOW,)),
    ],
    ids=[
        "invalid_role", "email_not_normalized", "blank_name", "invalid_monitoring_status", "ended_before_started",
        "utilization_over_1", "negative_loss", "invalid_provenance", "invalid_risk", "prediction_marked_measured",
        "invalid_severity", "max_below_min", "max_above_capacity", "invalid_model_family", "bad_sha256",
        "invalid_audit_outcome", "invalid_setting_key",
    ],
)
def test_check_constraints_reject_invalid_rows(sql, params):
    with pytest.raises(sqlite3.IntegrityError):
        with database_service.session(write=True) as conn:
            conn.execute(sql, params)


@pytest.mark.parametrize("port", [-1, 65536])
def test_port_range_enforced(port):
    with pytest.raises(sqlite3.IntegrityError):
        with database_service.session(write=True) as conn:
            sid = _insert_session(conn)
            conn.execute(
                "INSERT INTO network_flows (session_id, timestamp, src_port) VALUES (?, ?, ?)", (sid, NOW, port)
            )


def test_foreign_keys_enforced():
    with pytest.raises(sqlite3.IntegrityError):
        with database_service.session(write=True) as conn:
            conn.execute("INSERT INTO network_flows (session_id, timestamp) VALUES (999, ?)", (NOW,))


def test_flows_cascade_with_session():
    with database_service.session(write=True) as conn:
        sid = _insert_session(conn)
        conn.execute("INSERT INTO network_flows (session_id, timestamp) VALUES (?, ?)", (sid, NOW))
        conn.execute("DELETE FROM monitoring_sessions WHERE id = ?", (sid,))
        assert conn.execute("SELECT COUNT(*) FROM network_flows").fetchone()[0] == 0


def test_null_measurements_are_allowed_not_zero_filled():
    with database_service.session(write=True) as conn:
        conn.execute(
            "INSERT INTO network_metrics (timestamp, source_name, measurement_method, provenance, validity_status) "
            "VALUES (?, 'csv', 'import', 'unavailable', 'unavailable')",
            (NOW,),
        )
        row = conn.execute("SELECT latency_ms, utilization_ratio FROM network_metrics").fetchone()
    assert row["latency_ms"] is None and row["utilization_ratio"] is None


def test_one_active_model_per_family():
    with database_service.session(write=True) as conn:
        _insert_model(conn, "intrusion_classifier", "1", active=1)
        _insert_model(conn, "anomaly_detector", "1", active=1)  # different family: fine
        _insert_model(conn, "intrusion_classifier", "2", active=0)  # inactive: fine
    with pytest.raises(sqlite3.IntegrityError):
        with database_service.session(write=True) as conn:
            _insert_model(conn, "intrusion_classifier", "3", active=1)


def test_duplicate_model_version_rejected():
    with pytest.raises(sqlite3.IntegrityError):
        with database_service.session(write=True) as conn:
            _insert_model(conn, "anomaly_detector", "1")
            _insert_model(conn, "anomaly_detector", "1")


def test_split_sql_keeps_trigger_bodies_intact():
    script = (
        "-- comment\nCREATE TABLE t (x INTEGER);\n"
        "CREATE TRIGGER tr BEFORE INSERT ON t BEGIN SELECT 1; SELECT 2; END;\n-- trailing\n"
    )
    statements = database_service.split_sql_statements(script)
    assert len(statements) == 2
    assert statements[1].endswith("END;")


def test_manage_init_db_and_create_admin(capsys):
    assert manage.main(["init-db"]) == 0
    assert "up to date" in capsys.readouterr().out
    args = manage.build_parser().parse_args(["create-admin", "--name", "Ops", "--email", "ops@example.com"])
    secrets = iter(["CorrectHorse42", "CorrectHorse42"])
    assert manage.cmd_create_admin(args, secret=lambda _: next(secrets)) == 0
    user = auth_service.login("ops@example.com", "CorrectHorse42")
    assert user.role.value == "admin"


def test_timestamps_are_iso_utc():
    value = utc_now_iso()
    assert value.endswith("+00:00") and "T" in value
