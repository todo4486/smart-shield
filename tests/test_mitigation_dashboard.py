"""M5: incident lifecycle, the dashboard's data, allocation controls and the before and after view."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from components import attack_response
from services import (
    alert_service, capture_worker, database_service, host_allocation, incident_correlation_service as correlation,
    mitigation_service as ms, session_service, settings_service, simulation_service as sim,
)
from services.authorization import PermissionDenied
from services.bandwidth_allocation import AllocationError
from services.host_allocation import AllocationPolicy, HostDemand
from services.incident_correlation_service import IncidentError
from services.live_network_service import HostRow
from services.mitigation_service import MitigationError
from services.settings_service import SettingsError
from services.timeutil import to_iso, utc_now
from tests.conftest import audit_rows
from tests.test_live_monitoring import ddos_flow, fake_worker, monitor, train_live_model, wait_for  # noqa: F401
from tests.test_mitigation import _advance, _at, _first_proposal, _rows, _start
from tests.test_simulation import M, T0, _train, engine  # noqa: F401,F811

ROOT = Path(__file__).resolve().parent.parent
REMOTE = "203.0.113.5"


@pytest.fixture
def live_session(admin):
    with database_service.session(write=True) as conn:
        return conn.execute(
            "INSERT INTO monitoring_sessions (user_id, source_type, status, interface_name, started_at, configuration_json) "
            "VALUES (?, 'live_capture', 'RUNNING', 'en0', ?, '{}')", (admin.user_id, to_iso(utc_now()))).lastrowid


def _limit(admin, session_id, target=REMOTE):
    return ms.request_action(admin, session_id, "rate_limit", target=target, limit_bps=5 * M, reason="Too much traffic")


def _settings(admin, **changes):
    settings_service.update_mitigation_settings(admin, replace(settings_service.get_mitigation_settings(), **changes))


def _row(active=0, dry=0, proposed=0, last=None, status="open", resolution=None):
    return {"mitigations_active": active, "mitigations_dry_run": dry, "mitigations_proposed": proposed,
            "mitigation_last_status": last, "status": status, "resolution": resolution}


# ------------------------------------------------------------------ lifecycle

@pytest.mark.parametrize("row, expected", [
    (_row(), "Detected"), (_row(status="investigating"), "Investigating"), (_row(proposed=1), "Mitigation pending"),
    (_row(active=1), "Mitigation active"), (_row(dry=1), "Mitigation active (dry run)"), (_row(status="resolved"), "Resolved"),
    (_row(status="resolved", resolution="false_positive"), "False positive"), (_row(last="failed"), "Failed mitigation"),
    (_row(status="closed"), "Closed"),
    # Something in force is never hidden, and a failure does not outrank a later try.
    (_row(active=1, status="resolved"), "Mitigation active"), (_row(active=1, last="failed"), "Mitigation active"),
    (_row(proposed=1, last="failed"), "Mitigation pending"), (_row(last="rolled_back"), "Detected"),
])
def test_lifecycle(row, expected):
    assert correlation.lifecycle(row) == expected


def test_every_mitigation_gets_an_incident_and_a_dry_run_is_not_called_active(admin, live_session):
    result = _limit(admin, live_session)
    assert result["incident_id"]
    incident = correlation.get_incident(admin, result["incident_id"])
    assert incident.lifecycle == "Mitigation active (dry run)"
    assert incident.classification == "undetermined"  # an administrator's action is not evidence of an attack
    ms.rollback(admin, result["id"], reason="Back to normal")
    assert correlation.get_incident(admin, result["incident_id"]).lifecycle == "Detected"


def test_a_failed_action_shows_as_failed_mitigation(admin, live_session):
    result = ms.request_action(admin, live_session, "prioritize", reason="Share by class")
    assert result["status"] == "failed"
    assert correlation.get_incident(admin, result["incident_id"]).lifecycle == "Failed mitigation"


def test_a_second_action_joins_the_same_unfinished_incident_but_not_a_resolved_one(admin, live_session):
    first = _limit(admin, live_session)
    second = _limit(admin, live_session, target="203.0.113.6")
    assert second["incident_id"] == first["incident_id"]
    ms.rollback(admin, first["id"], reason="Back to normal")
    ms.rollback(admin, second["id"], reason="Back to normal")
    correlation.change_status(admin, first["incident_id"], "resolved")
    third = _limit(admin, live_session, target="203.0.113.7")
    assert third["incident_id"] != first["incident_id"]


def test_resolving_is_refused_while_a_limit_is_in_force(admin, live_session):
    result = _limit(admin, live_session)
    with pytest.raises(IncidentError, match="still active"):
        correlation.change_status(admin, result["incident_id"], "resolved")
    ms.rollback(admin, result["id"], reason="Back to normal")
    correlation.change_status(admin, result["incident_id"], "resolved")
    assert correlation.get_incident(admin, result["incident_id"]).lifecycle == "Resolved"


def test_false_positive_takes_off_the_action_and_records_why(admin, live_session):
    result = _limit(admin, live_session)
    ms.close_as_false_positive(admin, result["incident_id"], reason="Nightly backup host")
    incident = correlation.get_incident(admin, result["incident_id"])
    assert incident.lifecycle == "False positive" and incident.status == "resolved"
    assert ms.get_action(admin, result["id"])["status"] == "rolled_back"
    assert "Nightly backup host" in correlation.events(admin, incident.id)[-1]["note"]
    assert [r for r in audit_rows() if r["action"] == "incident.false_positive"]
    correlation.change_status(admin, incident.id, "open")
    assert correlation.get_incident(admin, incident.id).lifecycle == "Detected"  # reopening clears it


def test_false_positive_stops_if_the_rule_cannot_be_removed(admin, live_session):
    class Stuck:
        name = "pf+dnctl"

        def apply(self, mitigation):
            return None

        def remove(self, mitigation):
            raise ms.EnforcementError("Operation not permitted")

    ms.set_enforcer_for_tests("real", Stuck())
    try:
        result = _limit(admin, live_session)
        with pytest.raises(MitigationError, match="still active"):
            ms.close_as_false_positive(admin, result["incident_id"], reason="Nightly backup host")
    finally:
        ms.set_enforcer_for_tests("real", None)
    assert correlation.get_incident(admin, result["incident_id"]).lifecycle == "Mitigation active"


def test_false_positive_needs_an_administrator_only_when_an_action_is_open(admin, analyst, live_session):
    result = _limit(admin, live_session)
    with pytest.raises(PermissionDenied):
        ms.close_as_false_positive(analyst, result["incident_id"], reason="Looks harmless")
    ms.rollback(admin, result["id"], reason="Back to normal")
    ms.close_as_false_positive(analyst, result["incident_id"], reason="Looks harmless")
    assert correlation.get_incident(admin, result["incident_id"]).lifecycle == "False positive"


def test_false_positive_marks_the_open_alerts_too(admin, engine):
    _train(admin)
    session_id = _start(engine, admin, "bandwidth_hog")
    _advance(engine, 45, T0)
    proposal = _first_proposal(admin, session_id)
    fresh = ms.get_action(admin, proposal["id"])
    assert fresh["incident_id"]
    assert correlation.get_incident(admin, fresh["incident_id"]).lifecycle == "Mitigation pending"
    ms.close_as_false_positive(admin, fresh["incident_id"], reason="Scheduled upload")
    alerts = correlation.get_incident(admin, fresh["incident_id"]).alerts
    assert alerts and {a.status for a in alerts} == {"false_positive"}


def test_live_alerts_become_an_incident_the_action_joins(admin, monitor):
    train_live_model(admin, "live_compatible")

    def script(config):
        yield {"type": "started", "pid": 1, "mode": config["mode"]}
        yield {"type": "flows", "flows": [{**ddos_flow(i), "src_ip": "172.16.0.9"} for i in range(30)]}
        yield {"type": "metrics", "at": capture_worker._iso(1_700_000_030.0), "dropped_messages": 0, "active_flows": 3,
               "sample": {"incoming_bytes_per_second": 1000.0, "outgoing_bytes_per_second": 500.0, "incoming_packets_per_second": 10.0,
                          "outgoing_packets_per_second": 5.0, "throughput_bps": 12000.0, "utilization_ratio": None,
                          "configured_capacity_bps": None, "latency_ms": None},
               "hosts": [{"host": "172.16.0.9", "sent_bps": 50e6, "received_bps": 0.0, "sent_pps": 1.0, "received_pps": 1.0,
                          "active_connections": 1}]}

    monitor._worker_target = fake_worker(script)
    session_id = monitor.start(admin, "eth0", mode="packets", capacity_bps=100 * M)
    assert wait_for(lambda: ms.list_for_session(admin, session_id) and ms.list_for_session(admin, session_id)[0]["incident_id"])
    [action] = ms.list_for_session(admin, session_id)
    incident = correlation.get_incident(admin, action["incident_id"])
    assert incident.alerts and incident.lifecycle == "Mitigation pending"
    monitor.stop(admin)


def test_correlating_one_session_leaves_other_alerts_alone(admin, live_session):
    with database_service.session(write=True) as conn:
        alert_service.create_alert(conn, alert_type="security", severity="high", category="DDoS", reason="From elsewhere",
                                   evidence={}, dedup_key="elsewhere")
    assert correlation.correlate(admin, origin="real", session_id=live_session).alerts_linked == 0
    assert correlation.correlate(admin, origin="real").alerts_linked == 1


# ------------------------------------------------------------------ controls

def test_class_maximums_and_priorities_change_the_allocation():
    demands = [HostDemand("c", "critical", 90 * M), HostDemand("n", "normal", 90 * M)]
    capped = host_allocation.allocate_hosts(100 * M, AllocationPolicy(critical_max_share=0.4), demands)
    assert capped.hosts["c"].allocated_bps <= 40 * M + 1
    even = host_allocation.allocate_hosts(100 * M, AllocationPolicy(critical_min_share=0, normal_min_share=0, critical_weight=1, normal_weight=1), demands)
    assert even.hosts["c"].allocated_bps == pytest.approx(even.hosts["n"].allocated_bps, abs=2)
    favoured = host_allocation.allocate_hosts(100 * M, AllocationPolicy(critical_min_share=0, normal_min_share=0, critical_weight=9, normal_weight=1), demands)
    assert favoured.hosts["c"].allocated_bps > 3 * favoured.hosts["n"].allocated_bps
    assert favoured.total_allocated_bps <= favoured.usable_bps
    with pytest.raises(AllocationError):
        AllocationPolicy(critical_min_share=0.5, critical_max_share=0.4).validate()


@pytest.mark.parametrize("changes, message", [
    (dict(critical_min_share=0.5, critical_max_share=0.4), "cannot be above"), (dict(normal_weight=0), "priority"),
    (dict(critical_weight=11), "priority"), (dict(normal_max_share=1.5), "maximum"),
])
def test_controls_are_validated(admin, changes, message):
    with pytest.raises(SettingsError, match=message):
        _settings(admin, **changes)


def test_controls_are_administrators_only(analyst):
    with pytest.raises(PermissionDenied):
        settings_service.update_mitigation_settings(analyst, settings_service.MitigationSettings())
    with pytest.raises(PermissionDenied):
        settings_service.restore_mitigation_defaults(analyst)


def test_restoring_defaults_keeps_the_host_lists_and_is_audited(admin):
    _settings(admin, policy="off", critical_weight=9.0, protected_hosts=("10.0.0.1",), critical_services=("Web",))
    restored = settings_service.restore_mitigation_defaults(admin)
    assert restored.policy == "recommend" and restored.critical_weight == 6.0 and restored.critical_services == ()
    assert restored.protected_hosts == ("10.0.0.1",)
    assert settings_service.get_mitigation_settings() == restored
    assert [r for r in audit_rows() if r["action"] == "settings.update"]


def test_turning_adaptive_allocation_off_stops_it_but_not_threat_assessment(admin, engine):
    _train(admin)
    _settings(admin, adaptive_enabled=False)
    session_id = _start(engine, admin, "bandwidth_hog")
    _advance(engine, 40, T0)
    assert ms.latest_allocation(admin, session_id) is None
    assert _first_proposal(admin, session_id)  # the mitigation policy decides this, not the allocation switch


def test_a_service_marked_critical_moves_its_senders_to_the_critical_class(admin, engine):
    _train(admin)
    session_id = _start(engine, admin, "normal")
    _advance(engine, 5, T0)
    classes = {h["host"]: h["traffic_class"] for h in ms.latest_allocation(admin, session_id)["hosts"]}
    assert classes["198.51.100.20"] == "normal"
    _settings(admin, critical_services=("Video / voice",))
    _advance(engine, 5, T0 + 5)
    classes = {h["host"]: h["traffic_class"] for h in ms.latest_allocation(admin, session_id)["hosts"]}
    assert classes["198.51.100.20"] == "critical"


def test_a_critical_service_on_live_capture_comes_from_observed_ports(admin, live_session):
    _settings(admin, critical_services=("Video / voice",))
    now = utc_now()
    with database_service.session(write=True) as conn:
        conn.execute("INSERT INTO network_flows (session_id, timestamp, src_ip, dst_ip, dst_port, provenance) "
                     "VALUES (?, ?, ?, '10.0.0.1', 3478, 'measured')", (live_session, to_iso(now), "10.0.0.5"))
    ms.run_live_interval(live_session, 100 * M, [{"host": "10.0.0.5", "sent_bps": 5 * M, "received_bps": 0.0},
                                                 {"host": "10.0.0.6", "sent_bps": 5 * M, "received_bps": 0.0}], now)
    classes = {h["host"]: h["traffic_class"] for h in ms.latest_allocation(admin, live_session)["hosts"]}
    assert classes == {"10.0.0.5": "critical", "10.0.0.6": "normal"}


# ------------------------------------------------------------------ the dashboard's data

def _host(host, status="normal"):
    return HostRow(host, "Internet", 8 * M, 2 * M, 1.0, 1.0, 1, status, 0, None, None)


def test_host_rows_status_allocation_and_action(admin, live_session, monkeypatch):
    class Real:
        name = "pf+dnctl"

        def apply(self, mitigation):
            return None

        def remove(self, mitigation):
            return None

    ms.set_enforcer_for_tests("real", Real())
    try:
        now = utc_now()
        rows = ms.host_rows(admin, live_session, [_host("10.0.0.1")])
        assert rows[0]["allocated_bps"] is None  # unavailable, never 0
        ms.run_live_interval(live_session, 100 * M, [{"host": h, "sent_bps": 8 * M, "received_bps": 2 * M}
                                                     for h in ("10.0.0.1", "10.0.0.2", REMOTE)], now)
        _limit(admin, live_session)
        by_host = {r["host"]: r for r in ms.host_rows(admin, live_session, [_host("10.0.0.1"), _host("10.0.0.2", "suspicious"), _host(REMOTE)])}
    finally:
        ms.set_enforcer_for_tests("real", None)
    assert by_host["10.0.0.1"]["status"] == "normal" and by_host["10.0.0.1"]["action"] == "Manage"
    assert by_host["10.0.0.1"]["allocated_bps"] == pytest.approx(8 * M, abs=2)
    assert by_host["10.0.0.2"]["action"] == "Investigate"
    assert by_host[REMOTE]["status"] == "restricted" and by_host[REMOTE]["active_id"] and by_host[REMOTE]["usage_bps"] == 10 * M


def test_a_dry_run_never_makes_a_host_restricted(admin, live_session):
    _limit(admin, live_session)
    [row] = ms.host_rows(admin, live_session, [_host(REMOTE)])
    assert row["status"] == "normal" and row["dry_run"]


def test_allocation_history_is_oldest_first_and_available_changes_with_a_limit(admin, engine):
    _train(admin)
    session_id = _start(engine, admin, "bandwidth_hog")
    now = _advance(engine, 40, T0)
    before = ms.allocation_history(admin, session_id)
    assert [h["timestamp"] for h in before] == sorted(h["timestamp"] for h in before)
    assert {"critical", "normal", "suspicious", "restricted"} == set(before[-1]["classes"])
    ms.approve(admin, _first_proposal(admin, session_id)["id"], reason="Limit the hog", now=_at(now))
    _advance(engine, 15, now)
    after = ms.allocation_history(admin, session_id)[-1]
    assert after["classes"]["restricted"]["allocated_bps"] > 0 and after["enforced"]
    assert after["available_bps"] > before[-1]["available_bps"]


def test_acceptance_11_prioritizing_keeps_the_critical_guarantee_on_a_full_link(admin, engine):
    """The critical application's delivered rate under a flood from inside, without and with prioritization."""
    _train(admin)
    _settings(admin, policy="off")
    session_id = _start(engine, admin, "bandwidth_hog")
    now = _advance(engine, 40, T0)

    def critical_rate():
        with database_service.session() as conn:
            rows = conn.execute("SELECT sent_bps FROM host_metrics WHERE session_id = ? AND host = '198.51.100.50' "
                                "ORDER BY timestamp DESC LIMIT 5", (session_id,)).fetchall()
        return sum(r["sent_bps"] for r in rows) / len(rows)

    with database_service.session() as conn:
        rows = conn.execute("SELECT packet_loss_ratio FROM network_metrics WHERE session_id = ? ORDER BY timestamp DESC LIMIT 1", (session_id,)).fetchone()
    assert rows["packet_loss_ratio"] > 0  # the link really is full
    squeezed = critical_rate()
    ms.request_action(admin, session_id, "prioritize", reason="Protect critical traffic", now=_at(now))
    _advance(engine, 10, now)
    protected = critical_rate()
    offered = next(s.offered_bps for s in sim.baseline_sources(100 * M) if s.name == "Critical application")
    assert squeezed < offered and protected == pytest.approx(offered, rel=0.02)


# ------------------------------------------------------------------ before and after

def test_the_scene_draws_rates_and_never_invents_a_missing_one():
    picture = attack_response.scene("Before", {"samples": 3, "target_bps": 40 * M, "other_bps": None, "throughput_bps": 40 * M}, "Source 1.2.3.4", 40 * M)
    assert "40.0 Mbit/s" in picture or "40.00 Mbit/s" in picture
    assert "Unavailable" in picture
    assert picture.count("ss-net-flow") == 2  # the suspicious line and the link: a missing rate gets no moving traffic


def test_the_scene_escapes_what_it_draws():
    picture = attack_response.scene("<b>", {}, "<script>x</script>", 0)
    assert "<script>" not in picture and "<b>" not in picture


def test_a_blocked_host_shows_no_moving_traffic():
    picture = attack_response.scene("After", {"samples": 3, "target_bps": 0.0, "other_bps": 0.0, "throughput_bps": 0.0}, "x", 10 * M)
    assert "ss-net-flow" not in picture


# ------------------------------------------------------------------ pages

def _page(user, page):
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.session_state[session_service.USER_ID_KEY] = user.id
    app.session_state[session_service.LAST_ACTIVITY_KEY] = utc_now()
    app.run()
    app.switch_page(page)
    app.run()
    return app


def test_pages_render_with_no_data_for_both_roles(admin_user, analyst_user):
    for user in (admin_user, analyst_user):
        for page in ("views/bandwidth.py", "views/incident_center.py"):
            app = _page(user, page)
            assert not app.exception


def test_the_full_flow_through_the_pages(admin_user, admin, engine):
    """Acceptance 7, 8, 9, 10 on real pages: decide in the incident, see before and after, reverse it from the incident."""
    _train(admin)
    _page(admin_user, "views/simulation.py")  # the first page of a process closes sessions left over from an earlier process
    session_id = _start(engine, admin, "bandwidth_hog")
    now = _advance(engine, 40, T0)
    proposal = ms.get_action(admin, _first_proposal(admin, session_id)["id"])

    app = _page(admin_user, "views/bandwidth.py")
    assert not app.exception
    labels = " ".join(m.value for m in app.markdown)
    assert "Allocated bandwidth" in labels and "Restricted hosts" in labels
    assert any(d.value is not None and "Current usage" in d.value.columns for d in app.dataframe)
    ms.approve(admin, proposal["id"], reason="Confirmed upload hog", now=_at(now))
    _advance(engine, 15, now)

    app = _page(admin_user, "views/bandwidth.py")
    assert not app.exception
    picture = " ".join(m.value for m in app.markdown if "ss-net-scene" in m.value)
    assert "Before" in picture and "After" in picture and "10.20.1.99" in picture
    assert any("Simulated" in m.value for m in app.markdown)

    app.query_params["incident"] = str(proposal["incident_id"])
    app.switch_page("views/incident_center.py")
    app.run()
    assert not app.exception
    text = " ".join(m.value for m in app.markdown)
    assert "Mitigation active" in text and "Limit traffic from 10.20.1.99" in text
    app.button(key=f"mitigation_rollback_incident{proposal['id']}").click()
    app.run()
    assert not app.exception
    assert next(r for r in _rows(session_id) if r["id"] == proposal["id"])["status"] == "rolled_back"
    assert correlation.get_incident(admin, proposal["incident_id"]).lifecycle != "Mitigation active"


def test_an_administrator_can_set_a_per_host_limit_from_the_table(admin_user, admin, engine):
    _train(admin)
    _page(admin_user, "views/simulation.py")
    session_id = _start(engine, admin, "normal")
    _advance(engine, 20, T0)
    app = _page(admin_user, "views/bandwidth.py")
    assert not app.exception
    app.selectbox(key="manage_host").select("10.20.1.12")
    app.run()
    app.text_input(key="manage_reason").input("Holding it to its share")
    next(b for b in app.button if b.label == "Apply").click()
    app.run()
    assert not app.exception
    assert [e.value for e in app.error] == []
    [action] = [r for r in _rows(session_id) if r["target"] == "10.20.1.12"]
    assert action["status"] == "active" and action["initiated_by"] == "admin" and action["limit_bps"] == 5 * M


def test_saving_controls_from_the_page_reaches_the_settings(admin_user):
    app = _page(admin_user, "views/bandwidth.py")
    app.slider(key="critical_weight").set_value(8)
    next(b for b in app.button if b.label == "Save").click()
    app.run()
    assert not app.exception
    assert settings_service.get_mitigation_settings().critical_weight == 8.0
    next(b for b in app.button if b.label == "Restore defaults").click()
    app.run()
    assert not app.exception
    assert settings_service.get_mitigation_settings().critical_weight == 6.0


def test_a_status_filter_uses_the_lifecycle_names(admin_user, admin):
    app = _page(admin_user, "views/incident_center.py")
    assert not app.exception
    status = next(m for m in app.multiselect if m.label == "Status")
    assert "Failed mitigation" in status.options and "False positive" not in status.value
