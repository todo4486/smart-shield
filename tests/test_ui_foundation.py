"""UI upgrade phase 1: severity scale, data-source badges, header strip data, preferences."""
from __future__ import annotations

import pytest

from components import severity as severity_ui
from components.header import _strip_html
from components.ui import source_badge
from services import (
    alert_service, data_source, database_service, header_service, model_registry_service, preferences_service,
    severity, telemetry_service,
)
from services.telemetry_service import TelemetryImportOptions
from tests.conftest import audit_rows

THRESHOLDS = {"elevated": 0.7, "high": 0.85, "critical": 0.95}


# ------------------------------------------------------------------ severity

def test_severity_scale_order_and_aliases():
    assert severity.LEVELS == ("info", "low", "medium", "high", "critical")
    assert severity.normalize("CRITICAL") == "critical"
    assert severity.normalize("elevated") == "medium" and severity.normalize("normal") == "low"
    assert severity.normalize(None) == "info" and severity.normalize("unknown") == "info"
    assert severity.highest(["low", None, "high", "medium"]) == "high"
    assert severity.highest([]) is None and severity.highest([None]) is None
    assert severity.rank("critical") > severity.rank("high") > severity.rank("info")


@pytest.mark.parametrize("level", severity.LEVELS)
def test_severity_badge_never_relies_on_colour_alone(level):
    html = severity_ui.badge(level)
    assert severity_ui.ICONS[level] in html and severity_ui.LABELS[level] in html
    assert len(set(severity_ui.ICONS.values())) == len(severity.LEVELS)  # every level has its own shape
    assert severity_ui.plain(level).startswith(severity_ui.ICONS[level])


def test_severity_badge_escapes_custom_text():
    assert "<script>" not in severity_ui.badge("high", "<script>x</script>")


# --------------------------------------------------------------- data source

@pytest.mark.parametrize("source_type, running, mode, kind", [
    ("live_capture", True, "packets", data_source.LIVE),
    ("live_capture", True, "counters", data_source.COUNTERS),
    ("live_capture", False, "packets", data_source.DATASET),  # a finished capture is not presented as live
    ("historical_import", False, None, data_source.DATASET),
    ("dataset", True, "packets", data_source.DATASET),  # live flag only applies to live sessions
    ("replay", False, None, data_source.REPLAY),
    (None, False, None, data_source.NONE),
])
def test_data_source_classification(source_type, running, mode, kind):
    source = data_source.classify(source_type, live_running=running, live_mode=mode)
    assert source.kind == kind
    assert source.label in source_badge(source)


def test_replay_badge_says_dataset_replay():
    assert "DATASET REPLAY" in source_badge(data_source.classify("replay"))


# ------------------------------------------------------------- health score

def test_health_score_formula():
    assert header_service.health_score({}, None, THRESHOLDS) == 100
    assert header_service.health_score({"critical": 1}, None, THRESHOLDS) == 75
    assert header_service.health_score({"critical": 5}, None, THRESHOLDS) == 50  # capped at −50
    assert header_service.health_score({"high": 2, "medium": 1}, None, THRESHOLDS) == 77
    assert header_service.health_score({}, 0.96, THRESHOLDS) == 75
    assert header_service.health_score({}, 0.9, THRESHOLDS) == 85
    assert header_service.health_score({}, 0.75, THRESHOLDS) == 95
    assert header_service.health_score({}, None, THRESHOLDS, monitoring_error=True) == 90
    worst = header_service.health_score({"critical": 9, "high": 9, "medium": 9}, 1.0, THRESHOLDS, monitoring_error=True)
    assert worst == 0


def test_no_data_means_no_score_not_a_perfect_one():
    assert header_service.health_score({}, None, THRESHOLDS, has_any_data=False) is None
    assert header_service.health_level(None) == "unavailable"
    assert [header_service.health_level(s) for s in (95, 80, 79, 50, 49)] == ["ok", "ok", "warn", "warn", "critical"]


def test_only_new_high_or_critical_incidents_are_toasted():
    notices = [header_service.IncidentNotice(1, "a", "critical", "security"),
               header_service.IncidentNotice(2, "b", "medium", "performance"),
               header_service.IncidentNotice(3, "c", "high", "combined"),
               header_service.IncidentNotice(4, "d", None, "performance")]
    assert [n.id for n in header_service.new_high_incidents(notices, 1)] == [3]
    assert [n.id for n in header_service.new_high_incidents(notices, None)] == [1, 3]
    assert header_service.new_high_incidents(notices, 4) == []


# ------------------------------------------------------------- header data

def test_header_on_empty_database_is_honest(analyst):
    data = header_service.get_header(analyst)
    assert data.health is None and data.health_level == "unavailable"
    assert data.source.kind == data_source.NONE
    assert data.flows_per_second is None and data.top_link_utilization is None
    assert data.models_active == 0 and data.active_incidents == 0
    html = _strip_html(data)
    assert "Unavailable" in html and "NO DATA" in html


def test_header_reads_stored_data(analyst):
    csv = (b"timestamp,interface_name,throughput_bps,configured_capacity_bps\n"
           b"2026-10-01T00:00:00Z,uplink,900,1000\n2026-10-01T00:05:00Z,uplink,500,1000\n"
           b"2026-10-01T00:00:00Z,lab,10,1000\n")
    telemetry_service.import_telemetry_csv(analyst, csv, "t.csv", TelemetryImportOptions(source_name="t"))
    with database_service.session(write=True) as conn:
        alert_service.create_alert(conn, alert_type="security", severity="critical", category="DDoS", reason="r",
                                   evidence={}, dedup_key="k1")
    data = header_service.get_header(analyst)
    assert data.top_link == "uplink" and data.top_link_utilization == pytest.approx(0.5)  # newest, not the peak
    assert data.source.kind == data_source.DATASET
    assert data.health == 75 and data.open_alerts == {"critical": 1}


def test_header_needs_a_signed_in_principal():
    from services.authorization import PermissionDenied
    with pytest.raises(PermissionDenied):
        header_service.get_header(None)


def test_model_verification_detects_tampering(tmp_path, monkeypatch):
    from config import get_settings
    artifact = get_settings().artifact_dir / "m.joblib"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(b"model bytes")
    record = model_registry_service.ModelRecord(
        id=1, family="intrusion_classifier", name="m", version="v1", artifact_path=str(artifact),
        artifact_sha256=model_registry_service.sha256_file(artifact), feature_schema_version="1", metrics={},
        training_metadata={}, trained_at="t", created_by_email=None, is_active=True)
    assert model_registry_service.is_verified(record)
    artifact.write_bytes(b"tampered bytes")
    assert not model_registry_service.is_verified(record)
    artifact.unlink()
    assert not model_registry_service.is_verified(record)


# -------------------------------------------------------------- preferences

def test_reduce_motion_is_per_user_and_audited(admin, analyst):
    assert preferences_service.get_preferences(analyst).reduce_motion is False
    preferences_service.set_reduce_motion(analyst, True)
    assert preferences_service.get_preferences(analyst).reduce_motion is True
    assert preferences_service.get_preferences(admin).reduce_motion is False  # other users unaffected
    preferences_service.set_reduce_motion(analyst, False)
    assert preferences_service.get_preferences(analyst).reduce_motion is False
    rows = audit_rows("preferences.update")
    assert len(rows) == 2 and all(r["user_id"] == analyst.user_id for r in rows)
