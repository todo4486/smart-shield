from __future__ import annotations

import pytest

from services import database_service, monitoring_service, telemetry_service
from services.authorization import PermissionDenied
from services.telemetry_schema import ALL_COLUMNS, map_telemetry_columns, normalize_column_name, template_csv
from services.telemetry_service import TelemetryImportError, TelemetryImportOptions
from services.telemetry_view_service import downsample, session_telemetry
from tests.conftest import audit_rows

OPTS = TelemetryImportOptions(source_name="lab-router")


def csv(*lines: str) -> bytes:
    return ("\n".join(lines) + "\n").encode()


GOOD = csv(
    "timestamp,interface_name,incoming_bytes_per_second,outgoing_bytes_per_second,latency_ms,configured_capacity_bps",
    "2026-10-01T00:00:00Z,eth0,1000,500,12.5,100000",
    "2026-10-01T00:05:00Z,eth0,2000,1000,,100000",
    "2026-10-01T00:10:00+00:00,eth0,3000,1500,15,100000",
    "2026-10-01T00:20:00Z,eth0,4000,2000,9,100000",
)


def metrics(session_id):
    with database_service.session() as conn:
        return conn.execute(
            "SELECT * FROM network_metrics WHERE session_id = ? ORDER BY timestamp", (session_id,)
        ).fetchall()


# ---------------------------------------------------------------- schema

def test_column_normalization_and_aliases():
    assert normalize_column_name("  Flow Bytes/s ") == "flow_bytes_s"
    mapping, unknown, dupes = map_telemetry_columns(["Timestamp", "Interface", "RTT ms", "Mystery"])
    assert mapping == {"Timestamp": "timestamp", "Interface": "interface_name", "RTT ms": "latency_ms"}
    assert unknown == ["Mystery"] and dupes == []


def test_template_is_header_only():
    assert template_csv().strip() == ",".join(ALL_COLUMNS)


# ---------------------------------------------------------------- import

def test_import_valid_file(analyst):
    report = telemetry_service.import_telemetry_csv(analyst, GOOD, "lab.csv", OPTS)
    assert report.rows_read == 4 and report.rows_imported == 4 and report.rows_rejected == 0
    rows = metrics(report.session_id)
    assert rows[0]["timestamp"] == "2026-10-01T00:00:00.000000+00:00"
    assert rows[0]["provenance"] == "measured" and rows[0]["measurement_method"] == "csv_import"
    assert rows[0]["interface_name"] == "eth0" and rows[0]["source_name"] == "lab-router"
    # Missing latency stays NULL and marks the row partial, never 0.
    assert rows[1]["latency_ms"] is None and rows[1]["validity_status"] == "partial"
    assert rows[0]["validity_status"] == "valid"
    sampling = report.sampling[0]
    assert sampling.median_interval_seconds == 300 and sampling.gaps == 0
    with database_service.session() as conn:
        session = conn.execute("SELECT * FROM monitoring_sessions WHERE id = ?", (report.session_id,)).fetchone()
    assert session["status"] == "STOPPED" and session["source_type"] == "historical_import"
    assert session["dataset_id"] == report.dataset_id and session["ended_at"]
    assert len(audit_rows("telemetry.import", "success")) == 1


def test_derived_throughput_and_utilization_are_labelled(analyst):
    report = telemetry_service.import_telemetry_csv(analyst, GOOD, "lab.csv", OPTS)
    row = metrics(report.session_id)[0]
    assert row["throughput_bps"] == (1000 + 500) * 8 and row["throughput_provenance"] == "derived"
    assert row["utilization_ratio"] == pytest.approx(12000 / 100000)
    assert row["utilization_provenance"] == "derived"
    assert row["capacity_provenance"] == "configured"
    assert report.derived_counts["throughput_bps"] == 4


def test_utilization_not_invented_without_capacity(analyst):
    data = csv("timestamp,incoming_bytes_per_second,outgoing_bytes_per_second",
               "2026-10-01T00:00:00Z,10,20", "2026-10-01T00:01:00Z,30,40")
    report = telemetry_service.import_telemetry_csv(analyst, data, "nocap.csv", OPTS)
    row = metrics(report.session_id)[0]
    assert row["utilization_ratio"] is None and row["utilization_provenance"] == "unavailable"
    assert row["configured_capacity_bps"] is None and row["capacity_provenance"] == "unavailable"
    assert any("Utilization is unavailable" in w for w in report.warnings)


def test_capacity_override_is_configured_and_over_capacity_is_not_clamped(analyst):
    data = csv("timestamp,throughput_bps", "2026-10-01T00:00:00Z,500", "2026-10-01T00:01:00Z,5000")
    options = TelemetryImportOptions(source_name="s", capacity_override_bps=1000)
    report = telemetry_service.import_telemetry_csv(analyst, data, "cap.csv", options)
    first, second = metrics(report.session_id)
    assert first["throughput_provenance"] == "measured"
    assert first["utilization_ratio"] == 0.5 and first["capacity_provenance"] == "configured"
    assert second["utilization_ratio"] is None and second["utilization_provenance"] == "unavailable"
    assert any("above the configured capacity" in w for w in report.warnings)


def test_measured_utilization_and_percent_units(analyst):
    data = csv("timestamp,utilization_ratio,packet_loss_ratio", "2026-10-01T00:00:00Z,75,2")
    options = TelemetryImportOptions(source_name="s", utilization_unit="percent", packet_loss_unit="percent")
    report = telemetry_service.import_telemetry_csv(analyst, data, "pct.csv", options)
    row = metrics(report.session_id)[0]
    assert row["utilization_ratio"] == pytest.approx(0.75) and row["utilization_provenance"] == "measured"
    assert row["packet_loss_ratio"] == pytest.approx(0.02)


def test_invalid_rows_rejected_with_reasons(analyst):
    data = csv(
        "timestamp,incoming_bytes_per_second,utilization_ratio",
        "2026-10-01T00:00:00Z,100,0.5",
        "not-a-date,100,0.5",
        "2026-10-01T00:02:00Z,abc,0.5",
        "2026-10-01T00:03:00Z,-5,0.5",
        "2026-10-01T00:04:00Z,100,1.7",
        "2026-10-01T00:05:00Z,inf,0.5",
        "2026-10-01T00:06:00Z,,",
        ",100,0.5",
    )
    report = telemetry_service.import_telemetry_csv(analyst, data, "bad.csv", OPTS)
    assert report.rows_imported == 1 and report.rows_rejected == 7
    reasons = report.rejection_reasons
    assert reasons["timestamp: not ISO-8601"] == 1
    assert reasons["timestamp: missing"] == 1
    assert reasons["incoming_bytes_per_second: not a number"] == 1
    assert reasons["incoming_bytes_per_second: negative"] == 1
    assert reasons["utilization_ratio: outside 0–1"] == 1
    assert reasons["incoming_bytes_per_second: infinite"] == 1
    assert reasons["no measurement values in row"] == 1
    assert report.rejection_examples["timestamp: not ISO-8601"] == [3]


def test_naive_timestamps_rejected_unless_declared_utc(analyst):
    data = csv("timestamp,latency_ms", "2026-10-01 00:00:00,5", "2026-10-01 00:01:00,6")
    with pytest.raises(TelemetryImportError, match="no timezone"):
        telemetry_service.import_telemetry_csv(analyst, data, "naive.csv", OPTS)
    options = TelemetryImportOptions(source_name="s", naive_timestamps_are_utc=True)
    report = telemetry_service.import_telemetry_csv(analyst, data, "naive.csv", options)
    assert metrics(report.session_id)[0]["timestamp"] == "2026-10-01T00:00:00.000000+00:00"


def test_timezone_offsets_converted_to_utc(analyst):
    data = csv("timestamp,latency_ms", "2026-10-01T05:30:00+05:30,5")
    report = telemetry_service.import_telemetry_csv(analyst, data, "tz.csv", OPTS)
    assert metrics(report.session_id)[0]["timestamp"] == "2026-10-01T00:00:00.000000+00:00"


def test_duplicate_timestamps_in_file_keep_first(analyst):
    data = csv("timestamp,interface_name,latency_ms",
               "2026-10-01T00:00:00Z,eth0,5", "2026-10-01T00:00:00Z,eth0,9", "2026-10-01T00:00:00Z,eth1,7")
    report = telemetry_service.import_telemetry_csv(analyst, data, "dup.csv", OPTS)
    assert report.rows_imported == 2 and report.duplicate_rows == 1
    assert sorted(report.interfaces) == ["eth0", "eth1"]


def test_same_file_cannot_be_imported_twice(analyst):
    telemetry_service.import_telemetry_csv(analyst, GOOD, "lab.csv", OPTS)
    with pytest.raises(TelemetryImportError, match="already imported"):
        telemetry_service.import_telemetry_csv(analyst, GOOD, "copy.csv", OPTS)


@pytest.mark.parametrize(
    "data, message",
    [
        (b"", "empty"),
        (csv("interface_name,latency_ms", "eth0,5"), "no 'timestamp' column"),
        (csv("timestamp,configured_capacity_bps", "2026-10-01T00:00:00Z,100"), "no measurement columns"),
        (csv("timestamp,latency_ms"), "no data rows"),
        (csv("timestamp,latency_ms", "bad,5"), "No valid rows"),
        (csv("timestamp,latency,rtt_ms", "2026-10-01T00:00:00Z,1,2"), "more than once"),
    ],
)
def test_unusable_files_store_nothing(analyst, data, message):
    with pytest.raises(TelemetryImportError, match=message):
        telemetry_service.import_telemetry_csv(analyst, data, "x.csv", OPTS)
    with database_service.session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM network_metrics").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM datasets").fetchone()[0] == 0
    assert len(audit_rows("telemetry.import", "failure")) == 1


def test_database_failure_marks_session_error_and_rolls_back(analyst, monkeypatch):
    from repositories import telemetry_repository

    def boom(conn, rows):
        raise RuntimeError("disk full")

    monkeypatch.setattr(telemetry_repository, "insert_many", boom)
    with pytest.raises(TelemetryImportError, match="nothing was stored"):
        telemetry_service.import_telemetry_csv(analyst, GOOD, "lab.csv", OPTS)
    with database_service.session() as conn:
        session = conn.execute("SELECT status, status_message FROM monitoring_sessions").fetchone()
        assert conn.execute("SELECT COUNT(*) FROM datasets").fetchone()[0] == 0
    assert session["status"] == "ERROR" and "disk full" in session["status_message"]


def test_import_requires_principal_with_permission():
    with pytest.raises(PermissionDenied):
        telemetry_service.import_telemetry_csv(None, GOOD, "lab.csv", OPTS)


# ----------------------------------------------------------------- views

def test_session_telemetry_coverage_and_stats(analyst):
    report = telemetry_service.import_telemetry_csv(analyst, GOOD, "lab.csv", OPTS)
    view = session_telemetry(analyst, report.session_id)
    assert view.interfaces == ["eth0"] and len(view.metrics) == 4
    assert view.coverage["latency_ms"] == 0.75 and view.coverage["packet_loss_ratio"] == 0
    assert view.stats["incoming_bytes_per_second"]["max"] == 4000
    assert view.stats["packet_loss_ratio"]["count"] == 0
    assert view.provenance_counts["throughput_provenance"] == {"derived": 4}


def test_downsample_keeps_gaps_as_nan():
    import pandas as pd

    times = pd.date_range("2026-10-01", periods=10, freq="1min", tz="UTC").append(
        pd.date_range("2026-10-01 01:00", periods=10, freq="1min", tz="UTC"))
    frame = pd.DataFrame({"timestamp": times, "interface_name": "eth0", "latency_ms": 1.0})
    sampled, label = downsample(frame, ["latency_ms"], max_points=10)
    assert label is not None
    assert sampled["latency_ms"].isna().any() and (sampled["latency_ms"].dropna() == 1.0).all()


# -------------------------------------------------------------- sessions

def test_session_state_transitions():
    with database_service.session(write=True) as conn:
        sid = monitoring_service.create_session(conn, user_id=None, source_type="live_capture")
        monitoring_service.transition(conn, sid, monitoring_service.SessionState.RUNNING)
        with pytest.raises(monitoring_service.InvalidTransition):
            monitoring_service.transition(conn, sid, monitoring_service.SessionState.STARTING)
        monitoring_service.transition(conn, sid, monitoring_service.SessionState.STOPPING)
        monitoring_service.transition(conn, sid, monitoring_service.SessionState.STOPPED)
        with pytest.raises(monitoring_service.InvalidTransition):
            monitoring_service.transition(conn, sid, monitoring_service.SessionState.RUNNING)
        row = conn.execute("SELECT status, ended_at FROM monitoring_sessions WHERE id = ?", (sid,)).fetchone()
    assert row["status"] == "STOPPED" and row["ended_at"] is not None


def test_list_and_delete_sessions(admin, analyst):
    report = telemetry_service.import_telemetry_csv(analyst, GOOD, "lab.csv", OPTS)
    sessions = monitoring_service.list_sessions(analyst)
    assert sessions[0].metric_count == 4 and sessions[0].configuration["filename"] == "lab.csv"
    with pytest.raises(PermissionDenied):
        monitoring_service.delete_session(analyst, report.session_id)
    monitoring_service.delete_session(admin, report.session_id)
    assert monitoring_service.list_sessions(admin) == []
    with database_service.session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM network_metrics").fetchone()[0] == 0
    assert len(audit_rows("monitoring.delete_session", "success")) == 1


def test_overview_reflects_imported_measurements(analyst):
    from services import dashboard_service

    telemetry_service.import_telemetry_csv(analyst, GOOD, "lab.csv", OPTS)
    data = dashboard_service.get_overview(analyst)
    assert data.has_any_data
    assert data.incoming_bps.value == 4000 and data.incoming_bps.provenance == "measured"
    assert data.monitoring.status == "STOPPED" and data.monitoring.source_type == "historical_import"
    # Throughput was computed from in + out bytes, so the dashboard must say derived, not measured.
    assert data.throughput_bps.value == (4000 + 2000) * 8 and data.throughput_bps.provenance == "derived"
    assert data.utilization.provenance == "derived"


def test_break_gaps_inserts_empty_point_in_long_gaps():
    import pandas as pd

    from services.telemetry_view_service import break_gaps

    times = pd.to_datetime(["2026-10-01T00:00Z", "2026-10-01T00:05Z", "2026-10-01T00:10Z", "2026-10-01T02:00Z",
                            "2026-10-01T02:05Z"], utc=True)
    frame = pd.DataFrame({"timestamp": times, "interface_name": "eth0", "latency_ms": [1.0, 2, 3, 4, 5]})
    broken = break_gaps(frame, ["latency_ms"])
    assert len(broken) == 6 and broken["timestamp"].is_monotonic_increasing
    assert str(broken["timestamp"].dt.tz) == "UTC"
    assert broken["latency_ms"].isna().sum() == 1
