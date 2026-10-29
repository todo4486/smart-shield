"""Phase 4: what-if simulator, host insights, suppression rules, safer enforcement."""
from __future__ import annotations

import random
from datetime import timedelta

import pandas as pd
import pytest

from services import (
    alert_service, bandwidth_allocation, bandwidth_service, database_service, header_service, host_insights_service as hi,
    incident_correlation_service, suppression_service as sup, traffic_shaping_service, what_if_service,
)
from services.authorization import PermissionDenied
from services.suppression_service import Rule, SuppressionError
from services.timeutil import to_iso, utc_now
from services.what_if_service import SimClass, WhatIfError
from tests.conftest import audit_rows
from tests.test_bandwidth import M, accepted_recommendation, four_class, shaping  # noqa: F401 (fixture)


# ------------------------------------------------------------------ what-if

def test_simulator_matches_the_real_allocator_on_random_inputs(analyst):
    rng = random.Random(4)
    for _ in range(200):
        capacity = rng.uniform(10, 1000) * M
        classes = [SimClass(f"c{i}", 0.0, rng.uniform(0.01, 1) * capacity, rng.uniform(0.1, 10), rng.uniform(0, 500) * M)
                   for i in range(rng.randint(1, 6))]
        margin = rng.uniform(0, 0.4)
        ours = what_if_service.simulate(analyst, capacity, margin, classes)
        real = bandwidth_allocation.allocate(capacity, margin, [
            bandwidth_allocation.TrafficClass(c.name, c.minimum_bps, c.maximum_bps, c.priority_weight, c.demand_bps)
            for c in classes])
        assert ours.as_dict() == real.as_dict()
        assert all(ours.invariants.values())


def test_simulator_validates_and_stores_nothing(analyst):
    with pytest.raises(WhatIfError, match="unique"):
        what_if_service.simulate(analyst, 100 * M, 0.1, [SimClass("a", 0, M, 1, 0), SimClass("a", 0, M, 1, 0)])
    with pytest.raises(WhatIfError, match="(?i)minimum"):
        what_if_service.simulate(analyst, 10 * M, 0.0, [SimClass("a", 8 * M, 10 * M, 1, 0), SimClass("b", 8 * M, 10 * M, 1, 0)])
    with database_service.session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM bandwidth_recommendations").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE 'what_if%'").fetchone()[0] == 0


def test_starting_point_from_template_and_policy(admin):
    capacity, _, rows = what_if_service.starting_point(admin, capacity_bps=50 * M)
    assert capacity == 50 * M and len(rows) == 4 and all(r.demand_bps == 0 for r in rows)
    bandwidth_service.save_policy(admin, four_class())
    capacity, interface, rows = what_if_service.starting_point(admin, "lab")
    assert capacity == 100 * M and interface == "eth0" and [r.name for r in rows][0] == "critical"


def test_propose_is_admin_only_and_only_proposes(admin, analyst):
    classes = [SimClass("voip", 5 * M, 20 * M, 8, 10 * M), SimClass("bulk", 0, 90 * M, 1, 200 * M)]
    with pytest.raises(PermissionDenied):
        what_if_service.propose(analyst, name="sandbox", interface="eth0", capacity_bps=100 * M, safety_margin=0.1,
                                classes=classes)
    assert audit_rows("what_if.propose", "denied")
    rid = what_if_service.propose(admin, name="sandbox", interface="eth0", capacity_bps=100 * M, safety_margin=0.1,
                                  classes=classes)
    [rec] = bandwidth_service.list_recommendations(admin)
    assert rec["id"] == rid and rec["status"] == "proposed"  # still needs accepting and applying
    assert rec["payload"]["enforcement"] == "none: recommendation only"
    assert audit_rows("what_if.propose", "success")


# ------------------------------------------------------------------ host insights

def _flows():
    return pd.DataFrame([
        {"timestamp": "2026-01-05T10:00:00+00:00", "src_ip": "10.0.0.5", "dst_ip": "10.0.1.9", "dst_port": 22,
         "protocol": "TCP", "byte_count": 100, "intrusion_prediction": "SSH-Patator"},
        {"timestamp": "2026-01-05T10:30:00+00:00", "src_ip": "10.0.0.5", "dst_ip": "10.0.1.9", "dst_port": 22,
         "protocol": "TCP", "byte_count": 300, "intrusion_prediction": None},
        {"timestamp": "2026-01-06T23:00:00+00:00", "src_ip": "10.0.0.7", "dst_ip": "8.8.8.8", "dst_port": 53,
         "protocol": "UDP", "byte_count": 1000, "intrusion_prediction": None},
        {"timestamp": "2026-01-06T23:10:00+00:00", "src_ip": "bad", "dst_ip": None, "dst_port": None,
         "protocol": None, "byte_count": None, "intrusion_prediction": None},
    ])


def test_subnet():
    assert hi.subnet("10.0.4.17") == "10.0.4.0/24"
    assert hi.subnet("2001:db8::1") == "2001:db8::/64"
    assert hi.subnet("nope") == hi.subnet(None) == "unknown"


def test_leaderboard_uses_the_network_map_formula():
    alerts = [{"id": 1, "severity": "high", "in_incident": True,
               "evidence": {"top_sources": [{"value": "10.0.0.5", "flows": 1}]}}]
    rows = {r.host: r for r in hi.leaderboard(_flows(), alerts)}
    # 20 (one high alert) + 30 × 0.5 flagged share + 15 (in an open incident) = 50
    assert rows["10.0.0.5"].score == 50 and rows["10.0.0.5"].alerts == {"high": 1}
    assert rows["10.0.1.9"].score == 15  # 30 × 0.5 flagged share, no alert names it
    assert rows["8.8.8.8"].score == 0 and rows["8.8.8.8"].bytes == 1000
    assert list(rows)[0] == "10.0.0.5"
    assert sum(rows["10.0.0.5"].trend) == 1 and len(rows["10.0.0.5"].trend) == hi.TREND_BUCKETS
    assert hi.leaderboard(_flows().iloc[0:0], alerts) == []


def test_top_talkers_heatmap_and_sankey():
    flows = _flows()
    talkers = hi.top_talkers(flows)
    assert talkers["hosts"].iloc[0]["host"] in ("10.0.0.7", "8.8.8.8")
    assert talkers["ports"].iloc[0]["dst_port"] == 22 and talkers["protocols"].iloc[0]["protocol"] == "TCP"
    grid = hi.heatmap(flows)
    assert grid.shape == (7, 24) and grid.loc["Mon", 10] == 400 and grid.loc["Tue", 23] == 1000
    assert hi.heatmap(flows, "flagged").values.sum() == 1
    graph = hi.sankey(flows)
    assert "10.0.0.0/24" in graph["labels"] and "TCP/22" in graph["labels"] and "UDP/53" in graph["labels"]
    assert len(graph["source"]) == len(graph["target"]) == len(graph["value"])
    assert sum(v for s, v in zip(graph["source"], graph["value"])
               if graph["kinds"][s] == "subnet") == 1400  # rows with no bytes are not drawn
    assert hi.sankey(flows.iloc[0:0])["labels"] == []


def test_insights_need_view_alerts():
    with pytest.raises(PermissionDenied):
        hi.load_flows(None, 1)


# ------------------------------------------------------------------ suppression

def _rule(**kw):
    base = dict(id=1, alert_type=None, category=None, host=None, host_role="source", reason="backup server",
                status="active", expires_at=to_iso(utc_now() + timedelta(days=1)))
    base.update(kw)
    return Rule(**base)


def test_host_rules_only_match_alerts_entirely_from_that_host():
    only_host = {"flows": 5, "top_sources": [{"value": "10.0.0.5", "flows": 5}]}
    mixed = {"flows": 5, "top_sources": [{"value": "10.0.0.5", "flows": 4}, {"value": "10.0.0.6", "flows": 1}]}
    rule = _rule(alert_type="anomaly", host="10.0.0.5")
    assert sup.matches(rule, "anomaly", "Anomalous flows", only_host)
    assert not sup.matches(rule, "anomaly", "Anomalous flows", mixed)
    assert not sup.matches(rule, "security", "Anomalous flows", only_host)
    assert not sup.matches(rule, "anomaly", "x", {})  # no host evidence → never hidden on a guess
    dest = _rule(host="192.168.1.50", host_role="destination")
    assert sup.matches(dest, "security", "DDoS", {"flows": 3, "top_destinations": [{"value": "192.168.1.50:80",
                                                                                     "flows": 3}]})
    assert sup.matches(_rule(category="portscan"), "security", "PortScan", {})


def test_activity_and_effective_status():
    now = utc_now()
    assert sup.is_active(_rule(), now)
    assert not sup.is_active(_rule(status="requested"), now)
    expired = _rule(expires_at=to_iso(now - timedelta(seconds=1)))
    assert not sup.is_active(expired, now) and sup.effective_status(expired, now) == "expired"
    assert sup.effective_status(_rule(status="revoked", expires_at=to_iso(now - timedelta(days=1))), now) == "revoked"


def test_rule_validation(admin):
    with pytest.raises(SuppressionError, match="narrow"):
        sup.create_rule(admin, reason="too broad here", days=1)
    with pytest.raises(SuppressionError, match="IP"):
        sup.create_rule(admin, host="backup-server", reason="backup server", days=1)
    with pytest.raises(SuppressionError, match="reason"):
        sup.create_rule(admin, alert_type="anomaly", reason="x", days=1)
    with pytest.raises(SuppressionError, match="days"):
        sup.create_rule(admin, alert_type="anomaly", reason="backup server", days=sup.MAX_DAYS + 1)


def _alert(conn, key, source="10.0.0.5", alert_type="anomaly", severity="medium"):
    return alert_service.create_alert(conn, alert_type=alert_type, severity=severity, category="Anomalous flows",
                                      reason="r", evidence={"flows": 2, "top_sources": [{"value": source, "flows": 2}],
                                                            "time_window_utc": ["2026-01-01T00:00:00+00:00",
                                                                                "2026-01-01T00:01:00+00:00"]},
                                      dedup_key=key)


def test_suppressed_alerts_are_stored_but_left_out_of_queues(admin, analyst):
    rule_id = sup.create_rule(admin, alert_type="anomaly", host="10.0.0.5", reason="nightly backup server", days=7)
    with database_service.session(write=True) as conn:
        hidden = _alert(conn, "a")
        shown = _alert(conn, "b", source="10.0.0.9")
    assert [a.id for a in alert_service.list_alerts(analyst)] == [shown]
    [suppressed] = alert_service.list_alerts(analyst, suppressed="only")
    assert suppressed.id == hidden and suppressed.suppressed_by_rule == rule_id and suppressed.status == "open"
    _, events = alert_service.get_alert(analyst, hidden)
    assert any("Suppressed by rule" in (e["note"] or "") for e in events)
    header = header_service.get_header(analyst)
    assert header.open_alerts == {"medium": 1}
    run = incident_correlation_service.correlate(analyst)
    with database_service.session() as conn:
        linked = {r[0] for r in conn.execute("SELECT alert_id FROM incident_alerts")}
    assert run.alerts_linked == 1 and linked == {shown}
    assert [r.alerts_suppressed for r in sup.list_rules(analyst)] == [1]


def test_requests_need_admin_approval_and_everything_is_audited(admin, analyst):
    with pytest.raises(PermissionDenied):
        sup.create_rule(analyst, alert_type="anomaly", reason="backup server", days=1)
    rule_id = sup.request_rule(analyst, alert_type="anomaly", host="10.0.0.5", reason="backup server", days=3)
    with database_service.session(write=True) as conn:
        before = _alert(conn, "a")
    assert alert_service.list_alerts(analyst)[0].id == before  # a request suppresses nothing
    with pytest.raises(PermissionDenied):
        sup.review_request(analyst, rule_id, approve=True)
    sup.review_request(admin, rule_id, approve=True, note="ok for a week")
    with pytest.raises(SuppressionError, match="already active"):
        sup.review_request(admin, rule_id, approve=False)
    alert_service.change_status(analyst, before, "resolved")
    with database_service.session(write=True) as conn:
        after = _alert(conn, "a2")
    assert alert_service.list_alerts(analyst, suppressed="only")[0].id == after
    sup.revoke(admin, rule_id)
    with database_service.session(write=True) as conn:
        later = _alert(conn, "a3")
    assert later in [a.id for a in alert_service.list_alerts(analyst)]
    sup.unsuppress_alert(analyst, after, "needed after all")
    assert alert_service.list_alerts(analyst, suppressed="only") == []
    for action in ("suppression.request", "suppression.approve", "suppression.revoke", "suppression.unsuppress_alert"):
        assert audit_rows(action, "success"), action
    assert audit_rows("suppression.create", "denied") and audit_rows("suppression.review", "denied")


def test_expired_rules_stop_suppressing(admin, analyst):
    rule_id = sup.create_rule(admin, alert_type="anomaly", reason="maintenance window", days=1)
    with database_service.session(write=True) as conn:
        conn.execute("UPDATE suppression_rules SET created_at = ?, expires_at = ? WHERE id = ?",
                     (to_iso(utc_now() - timedelta(days=2)), to_iso(utc_now() - timedelta(minutes=1)), rule_id))
        alert_id = _alert(conn, "x")
    assert alert_service.list_alerts(analyst)[0].id == alert_id


# ------------------------------------------------------------------ enforcement UX

def test_preview_shows_before_after_and_exact_commands(admin, analyst, shaping):  # noqa: F811
    bandwidth_service.save_policy(admin, four_class())
    first = accepted_recommendation(admin)
    preview = traffic_shaping_service.plan_preview(admin, first.id, "eth0")
    assert preview["before"] is None and preview["after"]["recommendation_id"] == first.id
    assert preview["commands"] == traffic_shaping_service.preview_apply(admin, first.id, "eth0")
    assert shaping.calls == []  # previewing runs nothing
    with pytest.raises(PermissionDenied):
        traffic_shaping_service.plan_preview(analyst, first.id, "eth0")
    traffic_shaping_service.apply_recommendation(admin, first.id, "eth0", confirm_interface="eth0")
    second = accepted_recommendation(admin)
    assert traffic_shaping_service.plan_preview(admin, second.id, "eth0")["before"]["recommendation_id"] == first.id


def test_active_policies_follow_apply_rollback_and_emergency_disable(admin, analyst, shaping):  # noqa: F811
    bandwidth_service.save_policy(admin, four_class())
    assert traffic_shaping_service.active_policies(analyst) == []
    rec = accepted_recommendation(admin)
    traffic_shaping_service.apply_recommendation(admin, rec.id, "eth0", confirm_interface="eth0")
    [active] = traffic_shaping_service.active_policies(analyst)
    assert active["interface"] == "eth0" and active["recommendation_id"] == rec.id and active["applied_by"]
    traffic_shaping_service.rollback(admin, "eth0", confirm_interface="eth0")
    assert traffic_shaping_service.active_policies(analyst) == []
    traffic_shaping_service.apply_recommendation(admin, accepted_recommendation(admin).id, "eth0",
                                                 confirm_interface="eth0")
    traffic_shaping_service.emergency_disable(admin)
    assert traffic_shaping_service.active_policies(analyst) == []
