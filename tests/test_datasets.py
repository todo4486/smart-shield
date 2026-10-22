from __future__ import annotations

import json

import pytest

from config import get_settings
from services import database_service, dataset_service
from services.authorization import PermissionDenied
from services.dataset_service import DatasetError, FlowImportOptions
from services.telemetry_view_service import flow_summary
from tests.conftest import audit_rows

# CIC-IDS2017-style header: leading spaces, a duplicated column, Flow ID / IPs / Timestamp.
HEADER = ("Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration,"
          " Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets, Total Length of Bwd Packets,"
          " Flow Bytes/s, Fwd Header Length, Fwd Header Length, Label")


def cic_rows(n_benign: int = 3, n_attack: int = 2, with_timestamp: bool = True) -> bytes:
    lines = [HEADER]
    for i in range(n_benign + n_attack):
        label = "BENIGN" if i < n_benign else "DDoS"
        ts = f"3/7/2017 8:{i:02d}" if with_timestamp else ""
        flow_bytes = "Infinity" if i == 0 else str(100.5 * (i + 1))
        lines.append(
            f"10.0.0.{i}-192.168.1.1-{40000 + i}-80-6,10.0.0.{i},{40000 + i},192.168.1.1,80,6,{ts},"
            f"{2_000_000 + i},{3 + i},{2},{300 + i},{200},{flow_bytes},{40},{40},{label}"
        )
    return ("\n".join(lines) + "\n").encode()


def test_register_profiles_dataset(analyst):
    report = dataset_service.register_intrusion_dataset(analyst, cic_rows(), "Tuesday.csv", "Tuesday sample")
    assert report.row_count == 5
    assert report.label_distribution == {"BENIGN": 3, "DDoS": 2}
    assert "flow_bytes_s" in report.columns
    # Duplicate header becomes a distinct normalized name, not silently merged.
    assert "fwd_header_length" in report.columns and "fwd_header_length_1" in report.columns
    assert report.infinite_values == {"flow_bytes_s": 1}
    assert set(report.identifier_columns) == {"flow_id", "source_ip", "source_port", "destination_ip", "timestamp"}
    assert report.has_timestamps and report.flow_session_id is None and report.flows_imported == 0
    stored = get_settings().dataset_dir / f"{report.sha256}.csv"
    assert stored.read_bytes() == cic_rows()
    assert len(audit_rows("dataset.register", "success")) == 1


def test_missing_label_column_rejected(analyst):
    data = b"Destination Port,Flow Duration\n80,100\n"
    with pytest.raises(DatasetError, match="No 'Label' column"):
        dataset_service.register_intrusion_dataset(analyst, data, "nolabel.csv", "x")
    assert dataset_service.list_datasets(analyst) == []
    assert not any(get_settings().dataset_dir.glob("*.csv")) if get_settings().dataset_dir.exists() else True


def test_duplicate_dataset_rejected(analyst):
    dataset_service.register_intrusion_dataset(analyst, cic_rows(), "a.csv", "a")
    with pytest.raises(DatasetError, match="already registered"):
        dataset_service.register_intrusion_dataset(analyst, cic_rows(), "b.csv", "b")


def test_single_label_warns(analyst):
    report = dataset_service.register_intrusion_dataset(analyst, cic_rows(4, 0), "benign.csv", "benign only")
    assert any("Only one label" in w for w in report.warnings)


def test_flow_import_uses_dayfirst_utc_offset_and_keeps_label_as_ground_truth(analyst):
    options = FlowImportOptions(enabled=True, dayfirst=True, utc_offset_hours=-3)
    report = dataset_service.register_intrusion_dataset(analyst, cic_rows(), "t.csv", "t", options)
    assert report.flows_imported == 5 and report.flow_session_id
    with database_service.session() as conn:
        flows = conn.execute("SELECT * FROM network_flows ORDER BY timestamp").fetchall()
        session = conn.execute("SELECT * FROM monitoring_sessions WHERE id = ?", (report.flow_session_id,)).fetchone()
    first = flows[0]
    # 3 July 2017 08:00 at UTC-3 is 11:00 UTC.
    assert first["timestamp"] == "2017-07-03T11:00:00.000000+00:00"
    assert first["protocol"] == "TCP" and first["dst_port"] == 80 and first["src_ip"] == "10.0.0.0"
    assert first["packet_count"] == 5 and first["byte_count"] == 500 and first["duration"] == pytest.approx(2.0)
    assert first["intrusion_prediction"] is None  # labels are not predictions
    assert json.loads(first["feature_summary_json"]) == {"dataset_label": "BENIGN"}
    assert session["source_type"] == "dataset" and session["status"] == "STOPPED"
    assert session["dataset_id"] == report.dataset_id

    summary = flow_summary(analyst, report.flow_session_id)
    assert summary.total == 5 and summary.dataset_labels == {"BENIGN": 3, "DDoS": 2}
    assert summary.top_ports[0]["dst_port"] == 80


def test_flow_import_respects_row_limit(analyst):
    options = FlowImportOptions(enabled=True, max_rows=2)
    report = dataset_service.register_intrusion_dataset(analyst, cic_rows(), "t.csv", "t", options)
    assert report.flows_imported == 2 and report.row_count == 5
    assert any("Only the first 2 rows" in w for w in report.warnings)


def test_flow_import_skipped_without_timestamps(analyst):
    data = b"Destination Port,Flow Duration,Label\n80,100,BENIGN\n443,5,DDoS\n"
    report = dataset_service.register_intrusion_dataset(analyst, data, "ml.csv", "ml", FlowImportOptions(enabled=True))
    assert report.flows_imported == 0 and report.flow_session_id is None
    assert any("no Timestamp column" in w for w in report.warnings)


def test_unparseable_flow_timestamps_are_skipped_and_counted(analyst):
    data = cic_rows().decode().replace("3/7/2017 8:01", "garbage").encode()
    report = dataset_service.register_intrusion_dataset(analyst, data, "t.csv", "t", FlowImportOptions(enabled=True))
    assert report.flows_imported == 4 and report.flows_skipped == {"unparseable timestamp": 1}


def test_delete_dataset_is_admin_only_and_removes_file(admin, analyst):
    report = dataset_service.register_intrusion_dataset(analyst, cic_rows(), "t.csv", "t")
    stored = get_settings().dataset_dir / f"{report.sha256}.csv"
    with pytest.raises(PermissionDenied):
        dataset_service.delete_dataset(analyst, report.dataset_id)
    dataset_service.delete_dataset(admin, report.dataset_id)
    assert not stored.exists()
    assert dataset_service.list_datasets(admin) == []


def test_delete_never_touches_files_outside_dataset_dir(admin, analyst, tmp_path):
    report = dataset_service.register_intrusion_dataset(analyst, cic_rows(), "t.csv", "t")
    outside = tmp_path / "keep.csv"
    outside.write_text("x")
    with database_service.session(write=True) as conn:
        conn.execute("UPDATE datasets SET stored_path = ? WHERE id = ?", (str(outside), report.dataset_id))
    dataset_service.delete_dataset(admin, report.dataset_id)
    assert outside.exists()


def test_list_datasets_includes_telemetry_and_intrusion(analyst):
    from services import telemetry_service
    from services.telemetry_service import TelemetryImportOptions

    dataset_service.register_intrusion_dataset(analyst, cic_rows(), "t.csv", "flows")
    telemetry_service.import_telemetry_csv(
        analyst, b"timestamp,latency_ms\n2026-10-01T00:00:00Z,5\n", "m.csv", TelemetryImportOptions(source_name="m")
    )
    kinds = sorted(d.kind for d in dataset_service.list_datasets(analyst))
    assert kinds == ["intrusion_flows", "telemetry"]
    assert [d.kind for d in dataset_service.list_datasets(analyst, "telemetry")] == ["telemetry"]
