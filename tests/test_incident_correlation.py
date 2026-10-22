from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from services import (
    alert_service, database_service, health_summary_service, incident_correlation_service as correlation,
    telemetry_service,
)
from services.authorization import PermissionDenied
from services.incident_correlation_service import IncidentError
from services.telemetry_service import TelemetryImportOptions
from tests.conftest import audit_rows

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def iso(dt):
    return dt.isoformat()


def security_alert(start, minutes=10, category="DDoS", alert_type="security", key=None):
    with database_service.session(write=True) as conn:
        return alert_service.create_alert(
            conn, alert_type=alert_type, severity="high" if alert_type == "security" else "medium",
            category=category, reason="test", dedup_key=key or f"sec:{category}:{start}",
            evidence={"time_window_utc": [iso(start), iso(start + timedelta(minutes=minutes))], "flows": 100},
            model_version="clf-1")


def congestion_alert(base, category="Predicted congestion", interface="eth0", key=None):
    with database_service.session(write=True) as conn:
        return alert_service.create_alert(
            conn, alert_type="congestion", severity="high", category=category, reason="test",
            dedup_key=key or f"cong:{category}:{base}",
            evidence={"base_time": iso(base), "interface": interface,
                      "forecasts": [{"horizon_minutes": 5}, {"horizon_minutes": 15}]},
            model_version="fc-1")


def telemetry(principal, rows):
    lines = ["timestamp,interface_name,throughput_bps,utilization_ratio"]
    lines += [f"{iso(t).replace('+00:00', 'Z')},eth0,{tp},{u}" for t, tp, u in rows]
    telemetry_service.import_telemetry_csv(principal, ("\n".join(lines) + "\n").encode(), "t.csv",
                                           TelemetryImportOptions(source_name="lab"))


# ------------------------------------------------------------- scenarios

def test_scenario_a_security_plus_congestion_is_combined(analyst):
    security_alert(T0)
    congestion_alert(T0 + timedelta(minutes=5))
    run = correlation.correlate(analyst)
    assert len(run.incidents_created) == 1 and run.alerts_linked == 2
    incident = correlation.get_incident(analyst, run.incidents_created[0])
    assert incident.classification == "combined" and len(incident.alerts) == 2
    assert "Congestion by itself is not evidence of an attack" in incident.rationale
    assert incident.steps and incident.model_outputs["alert_models"] == ["clf-1", "fc-1"]


def test_scenario_b_congestion_alone_is_never_an_attack(analyst):
    congestion_alert(T0)
    congestion_alert(T0 + timedelta(minutes=3), category="Sustained high utilization")
    run = correlation.correlate(analyst)
    incident = correlation.get_incident(analyst, run.incidents_created[0])
    assert incident.classification == "performance"
    assert "not an attack" in incident.rationale
    assert "attack" not in incident.title.lower()
    assert any("bandwidth recommendation" in s for s in incident.steps)


def test_scenario_c_anomaly_with_normal_traffic_is_security_investigation(analyst):
    telemetry(analyst, [(T0 + timedelta(minutes=m), 1e6, 0.1) for m in range(-30, 31, 5)])
    security_alert(T0, minutes=10, category="Anomalous flows", alert_type="anomaly")
    run = correlation.correlate(analyst)
    incident = correlation.get_incident(analyst, run.incidents_created[0])
    assert incident.classification == "security"
    assert incident.measured_changes["traffic_trend"] == "normal"
    assert "unusual, not proven malicious" in incident.rationale


def test_scenario_d_performance_incident_points_to_existing_recommendation(admin):
    from services import bandwidth_service

    bandwidth_service.save_policy(admin, bandwidth_service.template_policy(1e9, interface="eth0"))
    rec = bandwidth_service.recommend(admin, "TEMPLATE four-class policy", {"standard": 5e8})
    congestion_alert(T0)
    run = correlation.correlate(admin)
    incident = correlation.get_incident(admin, run.incidents_created[0])
    assert any(f"#{rec.id}" in step for step in incident.steps)


def test_measured_sharp_rise_is_reported_from_stored_telemetry(analyst):
    before = [(T0 - timedelta(minutes=m), 1e6, 0.1) for m in range(5, 30, 5)]
    during = [(T0 + timedelta(minutes=m), 4e6, 0.4) for m in range(0, 25, 5)]
    telemetry(analyst, before + during)
    congestion_alert(T0)
    incident = correlation.get_incident(analyst, correlation.correlate(analyst).incidents_created[0])
    eth0 = incident.measured_changes["interfaces"]["eth0"]
    assert incident.measured_changes["traffic_trend"] == "sharp rise"
    assert eth0["change"] == pytest.approx(3.0) and eth0["peak_utilization"] == 0.4


def test_without_telemetry_changes_are_unavailable_not_zero(analyst):
    security_alert(T0)
    incident = correlation.get_incident(analyst, correlation.correlate(analyst).incidents_created[0])
    assert incident.measured_changes["traffic_trend"] == "unknown"
    assert "unavailable" in incident.measured_changes["summary"]


# ------------------------------------------------------------- grouping

def test_distant_alerts_make_separate_incidents_and_window_controls_grouping(analyst):
    security_alert(T0)
    congestion_alert(T0 + timedelta(hours=3))
    run = correlation.correlate(analyst, window_minutes=15)
    assert len(run.incidents_created) == 2
    kinds = sorted(correlation.get_incident(analyst, i).classification for i in run.incidents_created)
    assert kinds == ["performance", "security"]


def test_rerun_is_idempotent_and_new_alerts_join_open_incident(analyst):
    security_alert(T0)
    first = correlation.correlate(analyst)
    assert correlation.correlate(analyst).incidents_created == []
    congestion_alert(T0 + timedelta(minutes=8))
    second = correlation.correlate(analyst)
    assert second.incidents_created == [] and second.incidents_updated == first.incidents_created
    incident = correlation.get_incident(analyst, first.incidents_created[0])
    assert incident.classification == "combined" and len(incident.alerts) == 2


def test_resolved_alerts_are_not_correlated(analyst):
    alert_id = security_alert(T0)
    alert_service.change_status(analyst, alert_id, "resolved")
    run = correlation.correlate(analyst)
    assert run.incidents_created == []


def test_alert_without_network_time_uses_creation_time_and_says_so(analyst):
    with database_service.session(write=True) as conn:
        alert_service.create_alert(conn, alert_type="security", severity="medium", category="PortScan",
                                   reason="x", dedup_key="no-time", evidence={"flows": 3})
    incident = correlation.get_incident(analyst, correlation.correlate(analyst).incidents_created[0])
    assert "creation time" in incident.rationale


# ------------------------------------------------------------- workflow

def test_incident_status_workflow_notes_and_permissions(admin, analyst):
    security_alert(T0)
    incident_id = correlation.correlate(analyst).incidents_created[0]
    correlation.change_status(analyst, incident_id, "investigating", "looking at sources")
    correlation.add_note(analyst, incident_id, "lab scanner")
    with pytest.raises(IncidentError, match="cannot move"):
        correlation.change_status(analyst, incident_id, "closed")
    correlation.change_status(analyst, incident_id, "resolved")
    incident = correlation.get_incident(analyst, incident_id)
    assert incident.status == "resolved" and "lab scanner" in incident.notes and "looking at sources" in incident.notes
    with pytest.raises(PermissionDenied):
        correlation.correlate(None)
    assert len(audit_rows("incident.change_status", "success")) == 2


def test_health_summary_reflects_persisted_state(analyst):
    statements = health_summary_service.summarize(analyst)
    assert [s.text for s in statements if s.source == "alerts"] == ["No unresolved alerts."]
    security_alert(T0)
    texts = " ".join(s.text for s in health_summary_service.summarize(analyst))
    assert "1 unresolved alert(s)" in texts and "not yet grouped" in texts
    correlation.correlate(analyst)
    texts = " ".join(s.text for s in health_summary_service.summarize(analyst))
    assert "Open incidents: 1 security" in texts and "not yet grouped" not in texts
