"""UI upgrade phase 2: network map, incident triage + timeline, PredictNet outlook, water-filling steps."""
from __future__ import annotations

from datetime import timedelta

import pytest

from components import network_map as map_ui
from components import waterfill
from services import (
    alert_service, auth_service, database_service, incident_correlation_service as correlation, monitoring_service,
    network_map_service as nm,
)
from services.authorization import PermissionDenied
from services.bandwidth_allocation import TrafficClass, allocate
from services.congestion_prediction_service import HorizonForecast, RiskAssessment, congestion_outlook
from services.incident_correlation_service import IncidentError
from services.monitoring_service import SourceType
from tests.conftest import STRONG_PASSWORD, audit_rows
from tests.test_incident_correlation import T0, congestion_alert, iso, security_alert

THRESHOLDS = {"elevated": 0.7, "high": 0.85, "critical": 0.95}


# ------------------------------------------------------------ network map: pure

def flow(src, dst, size, flagged=False, ts=T0, protocol="TCP"):
    return {"timestamp": iso(ts), "src_ip": src, "dst_ip": dst, "src_port": 1000, "dst_port": 80,
            "protocol": protocol, "byte_count": size, "packet_count": 1,
            "intrusion_prediction": "DDoS" if flagged else None, "anomaly_score": None, "flagged": flagged}


def test_aggregate_merges_hosts_beyond_top_n_into_others():
    flows = [flow("10.0.0.1", "10.0.0.2", 1000), flow("10.0.0.1", "10.0.0.3", 500),
             flow("10.0.0.4", "10.0.0.5", 10), flow("10.0.0.2", "10.0.0.1", 300, flagged=True)]
    nodes, edges, total = nm.aggregate(flows, top_n=2, window_seconds=60, capacity_bps=None, thresholds=THRESHOLDS)
    ids = [n.id for n in nodes]
    assert total == 5 and ids[:2] == ["10.0.0.1", "10.0.0.2"] and ids[-1] == nm.OTHERS
    others = nodes[-1]
    assert others.members == 3
    # 1↔2 in both directions is one undirected link with both flows and their bytes.
    link = next(e for e in edges if {e.source, e.target} == {"10.0.0.1", "10.0.0.2"})
    assert link.flows == 2 and link.bytes == 1300 and link.flagged_flows == 1
    assert link.throughput_bps == pytest.approx(1300 * 8 / 60)
    # Traffic only between merged hosts (4↔5) is not drawn as a link.
    assert all(not (e.source == e.target == nm.OTHERS) for e in edges)


def test_edge_risk_needs_a_configured_capacity():
    assert nm.edge_risk(500, None, THRESHOLDS) == (None, "unknown")
    assert nm.edge_risk(960, 1000, THRESHOLDS) == (0.96, "critical")
    assert nm.edge_risk(860, 1000, THRESHOLDS)[1] == "high"
    assert nm.edge_risk(700, 1000, THRESHOLDS)[1] == "elevated"
    assert nm.edge_risk(100, 1000, THRESHOLDS)[1] == "normal"


def test_host_severity_and_risk_score():
    alerts = [{"severity": "medium", "evidence": {"top_sources": [{"value": "10.0.0.9", "flows": 3}]}},
              {"severity": "critical", "evidence": {"top_destinations": [{"value": "10.0.0.9:443", "flows": 1}]}},
              {"severity": "low", "evidence": {"top_destinations": [{"value": "2001:db8::1", "flows": 1}]}}]
    worst = nm.host_alert_severity(alerts)
    assert worst == {"10.0.0.9": "critical", "2001:db8::1": "low"}  # port stripped, IPv6 kept whole
    assert nm.host_risk_score(["critical", "medium"], 0.5, True) == 40 + 8 + 15 + 15
    assert nm.host_risk_score(["critical"] * 5, 1.0, True) == 100
    assert nm.host_risk_score([], None, False) == 0


def test_spring_layout_is_deterministic_and_bounded():
    ids = [f"h{i}" for i in range(12)]
    edges = [(f"h{i}", f"h{(i + 1) % 12}", 0.5) for i in range(12)]
    first, second = nm.spring_layout(ids, edges), nm.spring_layout(ids, edges)
    assert first == second
    assert all(0.0 <= x <= 1.0 and 0.0 <= y <= 1.0 for x, y in first.values())
    assert nm.spring_layout(["only"], []) == {"only": (0.5, 0.5)}


# --------------------------------------------------------- network map: stored

def make_flow_session(principal, flows, capacity=None):
    with database_service.session(write=True) as conn:
        session_id = monitoring_service.create_session(
            conn, user_id=principal.user_id, source_type=SourceType.FLOW_IMPORT, interface_name="eth0",
            configuration={"capacity_bps": capacity} if capacity else {})
        conn.executemany(
            "INSERT INTO network_flows (session_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, "
            "packet_count, byte_count, duration, intrusion_prediction, provenance) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 1.0, ?, 'measured')",
            [(session_id, f["timestamp"], f["src_ip"], f["dst_ip"], 1000, 80, f["protocol"], f["byte_count"],
              f["intrusion_prediction"]) for f in flows])
    return session_id


def test_build_map_from_stored_flows_with_filters(analyst):
    flows = [flow("10.0.0.1", "10.0.0.2", 6000, ts=T0), flow("10.0.0.3", "10.0.0.2", 60, ts=T0, protocol="UDP"),
             flow("10.0.0.1", "10.0.0.2", 6000, ts=T0 - timedelta(hours=3))]  # outside a 60-min window
    session_id = make_flow_session(analyst, flows, capacity=1000)
    with database_service.session(write=True) as conn:
        alert_service.create_alert(conn, alert_type="security", severity="high", category="DDoS", reason="r",
                                   dedup_key="m1", evidence={"top_sources": [{"value": "10.0.0.1", "flows": 1}],
                                                             "time_window_utc": [iso(T0), iso(T0)]})
    correlation.correlate(analyst)
    network = nm.build_map(analyst, nm.MapFilters(session_id, 60))
    assert network.flows_in_window == 2 and network.capacity_bps == 1000
    assert network.source.kind == "dataset" and set(network.protocols) == {"TCP", "UDP"}
    host1 = next(n for n in network.nodes if n.id == "10.0.0.1")
    assert host1.severity == "high" and host1.in_incident
    assert next(e for e in network.edges if "10.0.0.1" in (e.source, e.target)).risk != "unknown"
    only_udp = nm.build_map(analyst, nm.MapFilters(session_id, 60, protocols=("UDP",)))
    assert {n.id for n in only_udp.nodes} == {"10.0.0.3", "10.0.0.2"}
    incident_only = nm.build_map(analyst, nm.MapFilters(session_id, 60, only_incident_hosts=True))
    assert [n.id for n in incident_only.nodes] == ["10.0.0.1"] and incident_only.edges == []
    severe = nm.build_map(analyst, nm.MapFilters(session_id, 60, min_severity="critical"))
    assert severe.nodes == []
    detail = nm.host_detail(analyst, session_id, "10.0.0.1", 60)
    assert detail["flow_count"] == 1 and detail["alerts"][0]["severity"] == "high"
    assert detail["incidents"] and detail["risk_score"] == 20 + 15


def test_map_rejects_bad_filters_and_anonymous(analyst):
    session_id = make_flow_session(analyst, [flow("10.0.0.1", "10.0.0.2", 10)])
    with pytest.raises(nm.MapError):
        nm.build_map(analyst, nm.MapFilters(session_id, 0))
    with pytest.raises(nm.MapError):
        nm.build_map(analyst, nm.MapFilters(session_id, 60, top_n=1))
    with pytest.raises(PermissionDenied):
        nm.build_map(None, nm.MapFilters(session_id, 60))


def test_map_motion_respects_reduce_motion(analyst):
    session_id = make_flow_session(analyst, [flow("10.0.0.1", "10.0.0.2", 6000), flow("10.0.0.2", "10.0.0.3", 100)])
    network = nm.build_map(analyst, nm.MapFilters(session_id, 60))
    moving = map_ui.figure(network, reduce_motion=False)
    still = map_ui.figure(network, reduce_motion=True)
    dashes = [t.line.dash for t in moving.data if getattr(t, "line", None) is not None and t.line.dash]
    assert any(d in map_ui.PARTICLE_DASHES for d in dashes)
    assert not any(getattr(t, "line", None) is not None and t.line.dash in map_ui.PARTICLE_DASHES for t in still.data)
    hosts = still.data[-1]
    assert list(hosts.customdata) == [n.id for n in network.nodes]  # click → host id


# ------------------------------------------------------------- incident triage

def make_incident(analyst):
    security_alert(T0)
    return correlation.correlate(analyst).incidents_created[0]


def test_acknowledge_assign_resolve_with_history_and_audit(admin, analyst):
    incident_id = make_incident(analyst)
    correlation.acknowledge(analyst, incident_id)
    assert correlation.get_incident(analyst, incident_id).status == "investigating"
    correlation.assign(analyst, incident_id, admin.user_id)
    incident = correlation.get_incident(analyst, incident_id)
    assert incident.assigned_to == admin.user_id and incident.assigned_email == admin.email
    correlation.add_note(analyst, incident_id, "Scanner on the lab VLAN")
    correlation.change_status(analyst, incident_id, "resolved", "Confirmed lab scanner")
    history = correlation.events(analyst, incident_id)
    assert [e["event_type"] for e in history] == ["status_change", "assignment", "note", "status_change"]
    assert history[1]["assigned_email"] == admin.email and history[2]["note"] == "Scanner on the lab VLAN"
    assert history[3]["to_status"] == "resolved" and history[3]["note"] == "Confirmed lab scanner"
    assert len(audit_rows("incident.assign", "success")) == 1
    assert len(audit_rows("incident.change_status", "success")) == 2
    assert len(audit_rows("incident.add_note", "success")) == 1


def test_assignment_rules(admin, analyst):
    incident_id = make_incident(analyst)
    with pytest.raises(IncidentError, match="active user"):
        correlation.assign(analyst, incident_id, 9999)
    other = auth_service.register("Inactive", "inactive@example.com", STRONG_PASSWORD)
    with database_service.session(write=True) as conn:
        conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (other.id,))
    with pytest.raises(IncidentError, match="active user"):
        correlation.assign(analyst, incident_id, other.id)
    correlation.assign(analyst, incident_id, None)  # unassigning an unassigned incident is a no-op
    assert correlation.events(analyst, incident_id) == []
    correlation.change_status(analyst, incident_id, "resolved")
    correlation.change_status(analyst, incident_id, "closed")
    with pytest.raises(IncidentError, match="closed"):
        correlation.assign(analyst, incident_id, admin.user_id)
    with pytest.raises(PermissionDenied):
        correlation.assign(None, incident_id, admin.user_id)
    assert {u["email"] for u in correlation.assignable_users(analyst)} == {admin.email, analyst.email}


def test_swimlanes_split_security_and_congestion_and_mark_membership(analyst):
    security_alert(T0)
    congestion_alert(T0 + timedelta(minutes=2))
    incident_id = correlation.correlate(analyst).incidents_created[0]
    lanes = correlation.swimlanes(analyst)
    assert len(lanes["lanes"]["security"]) == 1 and len(lanes["lanes"]["congestion"]) == 1
    assert all(a["incident_id"] == incident_id for lane in lanes["lanes"].values() for a in lane)
    assert [i["id"] for i in lanes["incidents"]] == [incident_id]
    assert correlation.swimlanes(analyst, T0 + timedelta(days=1), T0 + timedelta(days=2))["lanes"] == \
        {"security": [], "congestion": []}


def test_congestion_only_incident_is_flagged_not_an_attack(analyst):
    congestion_alert(T0)
    incident = correlation.get_incident(analyst, correlation.correlate(analyst).incidents_created[0])
    assert incident.classification == "performance" and incident.not_an_attack
    strength = correlation.evidence_strength(incident.alerts)
    assert strength["level"] == "medium"


def test_evidence_strength_and_affected_hosts(analyst):
    security_alert(T0)
    incident = correlation.get_incident(analyst, correlation.correlate(analyst).incidents_created[0])
    assert correlation.evidence_strength(incident.alerts)["level"] == "high"
    assert correlation.evidence_strength([])["level"] == "low"
    alert = alert_service.Alert(1, None, "anomaly", "low", "x", "r", "open",
                                {"top_sources": [{"value": "10.0.0.7", "flows": 5}],
                                 "top_destinations": [{"value": "10.0.0.8:22", "flows": 9}]},
                                None, None, iso(T0), None, None, None)
    assert correlation.affected_hosts([alert]) == ["10.0.0.8", "10.0.0.7"]
    assert correlation.evidence_strength([alert])["level"] == "low"  # no network time in its evidence


# ------------------------------------------------------- PredictNet outlook

def forecast(minutes, value, upper):
    return HorizonForecast(minutes * 60, iso(T0), value, value, None, max(0, 2 * value - upper), upper, "rf",
                           RiskAssessment("normal", None, value, upper, None), 0)


def test_congestion_outlook():
    assert congestion_outlook([forecast(5, 0.5, 0.6), forecast(15, 0.9, 0.95)], 0.85) == \
        {"status": "likely", "minutes": 15, "text": "Congestion likely in ~15 min"}
    assert congestion_outlook([forecast(5, 0.5, 0.6), forecast(15, 0.8, 0.9)], 0.85)["status"] == "possible"
    clear = congestion_outlook([forecast(5, 0.5, 0.6), forecast(30, 0.6, 0.7)], 0.85)
    assert clear["status"] == "clear" and "30 min" in clear["text"]
    throughput = [forecast(5, 900.0, 950.0)]
    assert congestion_outlook(throughput, 0.85, target="throughput_bps")["status"] == "unavailable"
    assert congestion_outlook(throughput, 0.85, target="throughput_bps", capacity_bps=1000)["status"] == "likely"


# --------------------------------------------------------- water-filling steps

def test_allocator_records_its_steps_without_changing_results():
    classes = [TrafficClass("voip", 1e6, 5e6, 3, 2e6), TrafficClass("web", 1e6, 50e6, 1, 40e6),
               TrafficClass("backup", 0, 30e6, 1, 30e6)]
    result = allocate(50e6, 0.1, classes)
    assert result.steps[0]["allocations"] == {"backup": 0.0, "voip": 1e6, "web": 1e6}
    final = result.steps[-1]["allocations"]
    assert final == {a.name: float(a.allocated_bps) for a in result.allocations}
    for name in final:  # water only rises
        levels = [s["allocations"][name] for s in result.steps[:-1]]
        assert levels == sorted(levels)
    frames = waterfill.frames(result)
    assert all(0.0 <= v <= 1.0 for values in frames.values() for v in values)
    assert frames["voip"][-1] == pytest.approx(2e6 / 5e6)  # small demand filled completely (tank = maximum)
