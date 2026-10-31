"""M3: host-aware allocation, threat scoring, and the mitigation engine driven through real simulations and models."""
from __future__ import annotations

import ast
import random
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from services import (
    database_service, host_allocation, mitigation_scoring as scoring, mitigation_service as ms, monitoring_service,
    session_service,
    settings_service, simulation_service as sim,
)
from services.authorization import PermissionDenied
from services.bandwidth_allocation import AllocationError
from services.host_allocation import AllocationPolicy, HostDemand
from services.mitigation_scoring import FlaggedFlow, Thresholds
from services.mitigation_service import LinkPolicy, MitigationError, SenderDemand
from services.settings_service import MitigationSettings, SettingsError
from services.timeutil import utc_now
from tests.conftest import audit_rows
from tests.test_simulation import M, T0, _train, engine  # noqa: F401,F811  (engine is a fixture)

ROOT = Path(__file__).resolve().parent.parent
POLICY = AllocationPolicy()
UTC = timezone.utc


def _at(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, tz=UTC)


# ------------------------------------------------------------------ the allocator (pure)

def test_a_critical_class_keeps_its_guarantee_against_any_demand():
    result = host_allocation.allocate_hosts(100 * M, POLICY, [
        HostDemand("c", "critical", 30 * M), HostDemand("n", "normal", 90 * M)])
    assert result.hosts["c"].allocated_bps == pytest.approx(30 * M, abs=1)
    assert result.total_allocated_bps <= result.usable_bps


def test_an_unused_guarantee_is_lent_to_others():
    result = host_allocation.allocate_hosts(100 * M, POLICY, [HostDemand("c", "critical", 1 * M), HostDemand("n", "normal", 90 * M)])
    assert result.hosts["c"].allocated_bps == pytest.approx(1 * M, abs=1)
    assert result.hosts["n"].allocated_bps == pytest.approx(90 * M, abs=2)


def test_a_suspicious_host_is_capped_and_the_rest_keep_their_demand():
    result = host_allocation.allocate_hosts(100 * M, POLICY, [
        HostDemand("hog", "suspicious", 75 * M), HostDemand("n", "normal", 32 * M), HostDemand("c", "critical", 8 * M)])
    assert result.hosts["hog"].allocated_bps <= 10 * M
    assert result.hosts["n"].allocated_bps == pytest.approx(32 * M, abs=1)
    assert result.hosts["c"].allocated_bps == pytest.approx(8 * M, abs=1)


def test_a_restricted_host_gets_its_limit_at_most_and_a_blocked_host_nothing():
    result = host_allocation.allocate_hosts(100 * M, POLICY, [
        HostDemand("limited", "restricted", 75 * M, 5 * M), HostDemand("gone", "restricted", 20 * M, 0.0),
        HostDemand("n", "normal", 10 * M)])
    assert result.hosts["limited"].allocated_bps == pytest.approx(5 * M, abs=1)
    assert result.hosts["gone"].allocated_bps == 0


def test_hosts_in_a_class_share_it_equally_up_to_their_demand():
    result = host_allocation.allocate_hosts(100 * M, POLICY, [
        HostDemand("a", "normal", 5 * M), HostDemand("b", "normal", 300 * M), HostDemand("d", "normal", 300 * M)])
    assert result.hosts["a"].allocated_bps == pytest.approx(5 * M, abs=2)
    assert result.hosts["b"].allocated_bps == pytest.approx(result.hosts["d"].allocated_bps, abs=2)


def test_allocation_invariants_hold_for_random_inputs():
    rng = random.Random(11)
    for _ in range(300):
        capacity = rng.uniform(1, 1000) * M
        policy = AllocationPolicy(rng.uniform(0, .3), rng.uniform(0, .3), rng.uniform(0, .3), rng.uniform(0, .5))
        demands = []
        for i in range(rng.randint(0, 25)):
            name = rng.choice(host_allocation.CLASSES)
            limit = rng.uniform(0, capacity) if name == "restricted" and rng.random() < .8 else None
            demands.append(HostDemand(f"h{i}", name, rng.uniform(0, capacity), limit))
        result = host_allocation.allocate_hosts(capacity, policy, demands)
        again = host_allocation.allocate_hosts(capacity, policy, list(reversed(demands)))
        assert result == again
        assert result.total_allocated_bps <= result.usable_bps
        assert sum(g.allocated_bps for g in result.classes.values()) == result.total_allocated_bps
        for name, grant in result.classes.items():
            assert sum(h.allocated_bps for h in result.hosts.values() if h.traffic_class == name) <= grant.allocated_bps
        for host in result.hosts.values():
            assert 0 <= host.allocated_bps <= host.demand_bps + 1
            if host.limit_bps is not None:
                assert host.allocated_bps <= host.limit_bps + 1
        suspicious = result.classes["suspicious"].allocated_bps
        assert suspicious <= capacity * policy.suspicious_max_share + 1


def test_allocator_refuses_bad_input():
    with pytest.raises(AllocationError):
        host_allocation.allocate_hosts(0, POLICY, [])
    with pytest.raises(AllocationError):
        host_allocation.allocate_hosts(M, POLICY, [HostDemand("a", "normal", 1), HostDemand("a", "normal", 1)])
    with pytest.raises(AllocationError):
        host_allocation.allocate_hosts(M, POLICY, [HostDemand("a", "vip", 1)])
    with pytest.raises(AllocationError):
        host_allocation.allocate_hosts(M, AllocationPolicy(0.1, 0.6, 0.6, 0.1), [])


def test_classes_follow_mitigation_then_verdict_then_declaration():
    policy = LinkPolicy(source_limits={"a": 5 * M}, destination_limits={"v": 10 * M}, blocked=frozenset({"b"}))
    demands = [SenderDemand("a", "x", "normal", 50 * M), SenderDemand("b", "x", "normal", 1 * M),
               SenderDemand("f1", "v", "normal", 30 * M), SenderDemand("f2", "v", "normal", 10 * M),
               SenderDemand("s", "x", "critical", 1 * M), SenderDemand("c", "x", "critical", 1 * M),
               SenderDemand("n", "x", "normal", 1 * M)]
    by_host = {d.host: d for d in ms.classify_demands(demands, policy, {"s", "a"})}
    assert by_host["a"].traffic_class == "restricted" and by_host["a"].limit_bps == 5 * M
    assert by_host["b"].limit_bps == 0.0
    assert by_host["f1"].limit_bps == pytest.approx(7.5 * M) and by_host["f2"].limit_bps == pytest.approx(2.5 * M)
    assert by_host["s"].traffic_class == "suspicious"
    assert by_host["c"].traffic_class == "critical" and by_host["n"].traffic_class == "normal"


# ------------------------------------------------------------------ scoring (pure)

def _flows(src, count, *, dst="10.0.0.1", category="DoS", score=0.9, start=1000.0, gap=10.0):
    return [FlaggedFlow(src, dst, category, score, start + i * gap) for i in range(count)]


def test_a_repeated_confident_heavy_attacker_qualifies_for_auto():
    [a] = scoring.assess_targets(_flows("1.1.1.1", 6), {"1.1.1.1": 6}, {"1.1.1.1": 60 * M}, {}, 100 * M, set(), Thresholds())
    assert a.auto_eligible and a.confidence == pytest.approx(0.9) and a.confidence_basis == "classifier_votes"
    assert a.repetition == 6 and a.recommended_action == "rate_limit" and a.severity == "high"


@pytest.mark.parametrize("flows,totals,rate,critical,fragment", [
    (_flows("1.1.1.1", 6, score=0.5), 6, 60 * M, False, "confidence"),
    (_flows("1.1.1.1", 6, gap=0.1), 6, 60 * M, False, "window"),
    (_flows("1.1.1.1", 6, category="PortScan"), 6, 1 * M, False, "severity"),
    (_flows("1.1.1.1", 6), 6, 60 * M, True, "false-positive"),
])
def test_each_threshold_alone_blocks_auto(flows, totals, rate, critical, fragment):
    [a] = scoring.assess_targets(flows, {"1.1.1.1": totals}, {"1.1.1.1": rate}, {}, 100 * M,
                                 {"1.1.1.1"} if critical else set(), Thresholds())
    assert not a.auto_eligible
    assert any(fragment in blocker for blocker in a.auto_blockers)


def test_anomaly_only_uses_flag_share_and_is_labelled():
    flows = _flows("1.1.1.1", 4, category=scoring.ANOMALY_CATEGORY, score=0.1)
    [a] = scoring.assess_targets(flows, {"1.1.1.1": 10}, {"1.1.1.1": 60 * M}, {}, 100 * M, set(), Thresholds())
    assert a.confidence_basis == "flag_share" and a.confidence == 0.4
    assert a.false_positive_risk > 0.5 and not a.auto_eligible


def test_too_few_flows_produce_nothing():
    assert scoring.assess_targets(_flows("1.1.1.1", 2), {}, {}, {}, 100 * M, set(), Thresholds()) == []


def test_many_sources_become_one_destination_target_needing_upstream_help():
    flows = [f for i in range(25) for f in _flows(f"5.5.5.{i}", 2, dst="10.0.0.9")]
    results = scoring.assess_targets(flows, {f"5.5.5.{i}": 2 for i in range(25)}, {}, {"10.0.0.9": 90 * M}, 100 * M, set(), Thresholds())
    assert [a.target_kind for a in results] == ["destination"]
    assert results[0].target == "10.0.0.9" and results[0].distinct_sources == 25 and results[0].upstream_required


def test_a_quiet_scanner_is_recommended_a_block_which_is_never_auto():
    [a] = scoring.assess_targets(_flows("1.1.1.1", 6, category="PortScan"), {"1.1.1.1": 6}, {"1.1.1.1": 0.1 * M}, {},
                                 100 * M, set(), Thresholds(min_severity="low", max_false_positive_risk=1))
    assert a.recommended_action == "block" and not a.auto_eligible


def test_recovery_verdicts_say_what_the_samples_support():
    before = {"samples": 5, "loss_ratio": 0.2}
    assert scoring.verify_recovery("rate_limit", before, {"samples": 0}, M)[0] == "unavailable"
    assert scoring.verify_recovery("rate_limit", before, {"samples": 5, "target_bps": 5 * M, "loss_ratio": 0.0}, M)[0] == "not_recovered"
    assert scoring.verify_recovery("rate_limit", before, {"samples": 5, "target_bps": M, "loss_ratio": 0.0}, M)[0] == "recovered"
    status, note = scoring.verify_recovery("rate_limit", before, {"samples": 5, "target_bps": M, "loss_ratio": 0.2}, M)
    assert status == "partial" and "upstream" in note
    assert scoring.verify_recovery("rate_limit", before, {"samples": 5, "target_bps": M, "loss_ratio": None}, M)[0] == "partial"
    assert scoring.verify_recovery("block", before, {"samples": 5, "target_bps": 0.0, "loss_ratio": 0.0}, None)[0] == "recovered"
    assert scoring.verify_recovery("prioritize", before, {"samples": 5, "loss_ratio": 0.0}, None)[0] == "recovered"


# ------------------------------------------------------------------ the link model (pure)

def _hog():
    return sim.TrafficSource("Hog", "attack", "10.0.0.9", "9.9.9.9", 443, 6, 75 * M, False, sim.HOG, 1, legitimate=False)


def _download(rate=40 * M):
    return sim.TrafficSource("Web", "normal", "10.0.0.2", "8.8.4.4", 443, 6, rate, True, sim.WEB, 1)


def _flood(rate=90 * M):
    return sim.TrafficSource("Flood", "attack", "10.0.0.5", "7.7.7.7", 80, 6, rate, True, sim.FLOOD, 1, legitimate=False)


def test_limiting_an_outbound_host_frees_the_link():
    sources = [_hog(), _download()]
    assert sim.link_model(sources, 100 * M)["share"] < 1
    model = sim.link_model(sources, 100 * M, LinkPolicy(source_limits={"10.0.0.9": 5 * M}))
    assert model["share"] == 1.0
    assert model["delivered"] == pytest.approx([5 * M, 40 * M])


def test_limiting_an_inbound_flood_contains_it_but_cannot_free_the_link():
    sources = [_flood(), _download()]
    open_link = sim.link_model(sources, 100 * M)
    limited = sim.link_model(sources, 100 * M, LinkPolicy(source_limits={"7.7.7.7": 5 * M}))
    assert limited["share"] == open_link["share"] < 1
    assert limited["delivered"][0] == pytest.approx(5 * M)
    assert limited["delivered"][1] == open_link["delivered"][1] < 40 * M


def test_blocking_and_isolating_stop_delivery_and_a_destination_limit_is_shared():
    sources = [_flood(60 * M), _download(), _hog()]
    assert sim.link_model(sources, 300 * M, LinkPolicy(blocked=frozenset({"7.7.7.7"})))["delivered"][0] == 0
    isolated = sim.link_model(sources, 300 * M, LinkPolicy(isolated=frozenset({"10.0.0.9"})))["delivered"]
    assert isolated[2] == 0 and isolated[1] == pytest.approx(40 * M)
    assert sim.link_model(sources, 300 * M, LinkPolicy(destination_limits={"10.0.0.5": 6 * M}))["delivered"][0] == pytest.approx(6 * M)


def test_prioritizing_caps_only_what_this_side_can_hold_back():
    sources = [_hog(), _download()]
    caps = {"10.0.0.9": 10 * M, "8.8.4.4": 1 * M}
    delivered = sim.link_model(sources, 100 * M, LinkPolicy(sender_caps=caps))["delivered"]
    assert delivered == pytest.approx([10 * M, 40 * M])


def test_a_limited_source_sends_fewer_flows_to_the_models():
    generator = sim.TrafficGenerator("port_scan", 100 * M, attack_delay_seconds=0)
    blocked = LinkPolicy(blocked=frozenset({"198.51.100.66"}))
    packets = generator.tick(T0, 1.0, blocked)["packets"]
    assert not any("198.51.100.66" in (p[1], p[2]) for p in packets)
    assert any("198.51.100.66" in (p[1], p[2]) for p in generator.tick(T0 + 1)["packets"])


# ------------------------------------------------------------------ the engine, end to end through real models

def _policy(principal, level, **changes):
    settings_service.update_mitigation_settings(principal, replace(MitigationSettings(policy=level), **changes))


def _start(engine, principal, scenario, *, duration=200, delay=5):
    return engine.start(principal, scenario, capacity_bps=100 * M, attack_delay_seconds=delay, duration_seconds=duration)


def _advance(engine, seconds, start):
    now = start
    for _ in range(int(seconds)):
        if not engine.step(now):
            break
        now += 1
    return now


def _rows(session_id):
    with database_service.session() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM mitigation_actions WHERE session_id = ? ORDER BY id",
                                              (session_id,)).fetchall()]


def _first_proposal(admin, session_id):
    return next(m for m in ms.list_for_session(admin, session_id) if m["status"] == "proposed")


def _host_rate(session_id, host, column="sent_bps"):
    with database_service.session() as conn:
        row = conn.execute(f"SELECT {column} AS rate FROM host_metrics WHERE session_id = ? AND host = ? "
                           "ORDER BY timestamp DESC LIMIT 1", (session_id, host)).fetchone()
    return None if row is None else float(row["rate"])


def test_default_policy_recommends_and_changes_nothing_until_approved(admin, engine):
    _train(admin)
    session_id = _start(engine, admin, "bandwidth_hog")
    _advance(engine, 40, T0)
    proposal = _first_proposal(admin, session_id)
    assert proposal["initiated_by"] == "engine" and proposal["target"] == "10.20.1.99"
    assert proposal["action_type"] == "rate_limit" and proposal["limit_bps"] == pytest.approx(5 * M)
    assert proposal["category"] and proposal["confidence"] is not None and proposal["severity"] == "high"
    assert not [m for m in _rows(session_id) if m["status"] == "active"]
    assert _host_rate(session_id, "10.20.1.99") > 40 * M
    assert sim.status_copy().loss_ratio > 0


def test_approving_limits_the_host_gives_others_their_demand_and_can_be_rolled_back(admin, engine):
    _train(admin)
    session_id = _start(engine, admin, "bandwidth_hog")
    now = _advance(engine, 40, T0)
    before_share = sim.status_copy().loss_ratio
    assert before_share > 0
    web_before = _host_rate(session_id, "198.51.100.30")
    proposal = _first_proposal(admin, session_id)

    active = ms.approve(admin, proposal["id"], reason="Confirmed upload hog", now=_at(now))
    assert active["status"] == "active" and active["applied_at"] and active["expires_at"] > active["applied_at"]
    assert active["execution_ms"] is not None and active["adapter"] == "simulated-link"
    assert active["recovery_status"] == "pending"

    now = _advance(engine, 15, now)
    assert _host_rate(session_id, "10.20.1.99") == pytest.approx(5 * M, rel=0.01)
    assert sim.status_copy().loss_ratio == 0
    assert _host_rate(session_id, "198.51.100.30") > web_before  # legitimate traffic gets its demand back

    allocation = ms.latest_allocation(admin, session_id)
    assert allocation["enforced"] and allocation["provenance"] == "derived"
    hog = next(h for h in allocation["hosts"] if h["host"] == "10.20.1.99")
    assert hog["traffic_class"] == "restricted" and hog["allocated_bps"] <= 5 * M
    critical = next(h for h in allocation["hosts"] if h["host"] == "198.51.100.50")
    assert critical["allocated_bps"] == pytest.approx(critical["demand_bps"], abs=2)

    verified = next(m for m in ms.list_for_session(admin, session_id) if m["id"] == proposal["id"])
    assert verified["recovery_status"] == "recovered", verified["recovery_note"]
    assert verified["before"]["loss_ratio"] > 0 and verified["after"]["loss_ratio"] == 0
    assert verified["before"]["target_bps"] > 40 * M and verified["after"]["target_bps"] == pytest.approx(5 * M, rel=0.01)
    assert verified["after"]["other_bps"] > verified["before"]["other_bps"]
    assert verified["previous_allocation"] and verified["new_allocation"]
    assert verified["new_allocation"]["classes"]["restricted"]["allocated_bps"] <= 5 * M

    ms.rollback(admin, proposal["id"], reason="Demo: restore the policy", now=_at(now))
    now = _advance(engine, 3, now)
    assert _host_rate(session_id, "10.20.1.99") > 40 * M  # the original behaviour is back
    assert sim.status_copy().loss_ratio > 0
    assert not ms.latest_allocation(admin, session_id)["enforced"]
    actions = [r["action"] for r in audit_rows()]
    assert {"mitigation.propose", "mitigation.apply", "mitigation.verify", "mitigation.rollback"} <= set(actions)
    # The engine does not ask again straight after an administrator took it back.
    now = _advance(engine, 20, now)
    assert not [m for m in _rows(session_id) if m["status"] in ("proposed", "active")]


def test_auto_policy_applies_only_a_rate_limit_and_it_expires(admin, engine):
    _train(admin)
    _policy(admin, "auto_rate_limit")
    session_id = _start(engine, admin, "bandwidth_hog")
    _advance(engine, 45, T0)
    rows = _rows(session_id)
    assert rows, "the engine should have acted"
    auto = rows[0]
    assert auto["status"] == "active" and auto["initiated_by"] == "engine" and auto["decided_by"] is None
    assert auto["action_type"] == "rate_limit"
    ms.expire_due(datetime.fromisoformat(auto["expires_at"]) + timedelta(seconds=1))
    assert _rows(session_id)[0]["status"] == "expired"


def test_off_policy_never_proposes(admin, engine):
    _train(admin)
    _policy(admin, "off")
    session_id = _start(engine, admin, "bandwidth_hog")
    _advance(engine, 40, T0)
    assert _rows(session_id) == []
    assert ms.latest_allocation(admin, session_id) is not None  # the allocation is still calculated


def test_normal_traffic_gets_no_mitigation_even_under_auto(admin, engine):
    _train(admin)
    _policy(admin, "auto_rate_limit")
    session_id = _start(engine, admin, "normal", delay=0)
    _advance(engine, 40, T0)
    assert _rows(session_id) == []


def test_congestion_alone_never_starts_a_mitigation(admin, engine, monkeypatch):
    """A flooded link whose flows the models do not flag is congestion, not an attack."""
    _train(admin)
    _policy(admin, "auto_rate_limit")
    session_id = _start(engine, admin, "bandwidth_hog")
    monkeypatch.setattr(engine, "_score", lambda flows: [
        {"score": 0.0, "category": None, "anomaly_score": None} for _ in flows])
    _advance(engine, 40, T0)
    assert sim.status_copy().loss_ratio > 0
    assert _rows(session_id) == []


def test_a_flood_is_contained_but_the_check_says_upstream_help_is_needed(admin, engine):
    _train(admin)
    session_id = _start(engine, admin, "ddos")
    now = _advance(engine, 40, T0)
    proposal = next(m for m in ms.list_for_session(admin, session_id) if m["target_kind"] == "destination")
    assert proposal["target"] == "10.20.0.10" and proposal["upstream_required"]
    ms.approve(admin, proposal["id"], reason="Flood towards the server", now=_at(now))
    now = _advance(engine, 15, now)
    checked = next(m for m in ms.list_for_session(admin, session_id) if m["id"] == proposal["id"])
    assert checked["recovery_status"] == "partial", checked["recovery_note"]
    assert "upstream" in checked["recovery_note"]
    assert checked["after"]["target_bps"] <= 5.5 * M and checked["after"]["loss_ratio"] > 0.2


def test_a_scan_is_recommended_a_block_needing_a_typed_target_and_an_admin(admin, analyst, engine):
    _train(admin)
    _policy(admin, "auto_rate_limit")
    session_id = _start(engine, admin, "port_scan")
    now = _advance(engine, 40, T0)
    proposal = _first_proposal(admin, session_id)
    assert proposal["action_type"] == "block" and proposal["target"] == "198.51.100.66"
    assert proposal["status"] == "proposed"  # even under Auto rate-limit
    with pytest.raises(PermissionDenied):
        ms.approve(analyst, proposal["id"], reason="Please block it", confirm_target="198.51.100.66")
    with pytest.raises(MitigationError, match="Type the address"):
        ms.approve(admin, proposal["id"], reason="Confirmed scanner")
    with pytest.raises(MitigationError, match="reason"):
        ms.approve(admin, proposal["id"], reason="x", confirm_target="198.51.100.66")
    ms.approve(admin, proposal["id"], reason="Confirmed scanner", confirm_target="198.51.100.66", duration_minutes=30, now=_at(now))
    now = _advance(engine, 3, now)
    active = _rows(session_id)[0]
    assert active["status"] == "active" and active["decided_by"] == admin.user_id
    assert datetime.fromisoformat(active["expires_at"]) - datetime.fromisoformat(active["applied_at"]) == timedelta(minutes=30)
    with database_service.session() as conn:
        after_block = conn.execute("SELECT COUNT(*) FROM host_metrics WHERE session_id = ? AND host = ? AND timestamp > ?",
                                   (session_id, "198.51.100.66", active["applied_at"])).fetchone()[0]
    assert after_block == 0


def test_the_engine_itself_cannot_apply_a_block(admin, engine):
    _train(admin)
    session_id = _start(engine, admin, "port_scan")
    _advance(engine, 40, T0)
    with pytest.raises(MitigationError, match="Only a rate limit"):
        ms._apply_automatically(_first_proposal(admin, session_id)["id"], _at(T0 + 40))


def test_rejecting_keeps_a_record_and_is_not_asked_again_straight_away(admin, engine):
    _train(admin)
    session_id = _start(engine, admin, "bandwidth_hog")
    now = _advance(engine, 40, T0)
    proposal = _first_proposal(admin, session_id)
    ms.reject(admin, proposal["id"], reason="Scheduled backup", now=_at(now))
    now = _advance(engine, 30, now)
    rows = {r["id"]: r for r in _rows(session_id)}
    assert rows[proposal["id"]]["status"] == "rejected" and rows[proposal["id"]]["decision_note"] == "Scheduled backup"
    assert not [r for r in rows.values() if r["target"] == proposal["target"] and r["status"] == "proposed"]


def test_prioritizing_protects_others_without_a_host_limit(admin, engine):
    _train(admin)
    _policy(admin, "off")
    session_id = _start(engine, admin, "bandwidth_hog")
    now = _advance(engine, 30, T0)
    assert sim.status_copy().loss_ratio > 0
    ms.request_action(admin, session_id, "prioritize", reason="Protect critical traffic", now=_at(now))
    now = _advance(engine, 5, now)
    # Whichever class the hog is in, the allocator keeps it out of the way of the others.
    assert sim.status_copy().loss_ratio == 0
    assert _host_rate(session_id, "198.51.100.50") == pytest.approx(8 * M, rel=0.01)  # critical
    assert _host_rate(session_id, "10.20.1.99") < 75 * M


def test_manual_actions_are_validated_and_admin_only(admin, analyst, engine):
    _train(admin)
    _policy(admin, "off")
    session_id = _start(engine, admin, "normal", delay=0)
    _advance(engine, 2, T0)
    with pytest.raises(PermissionDenied):
        ms.request_action(analyst, session_id, "rate_limit", target="10.20.1.12", limit_bps=M, reason="Too much traffic")
    with pytest.raises(MitigationError, match="IP address"):
        ms.request_action(admin, session_id, "rate_limit", target="10.20.1.12; rm -rf /", limit_bps=M, reason="Too much traffic")
    with pytest.raises(MitigationError, match="at least"):
        ms.request_action(admin, session_id, "rate_limit", target="10.20.1.12", limit_bps=1, reason="Too much traffic")
    with pytest.raises(MitigationError, match="duration"):
        ms.request_action(admin, session_id, "rate_limit", target="10.20.1.12", limit_bps=M, reason="Too much traffic", duration_minutes=0)
    with pytest.raises(MitigationError, match="Type the address"):
        ms.request_action(admin, session_id, "isolate", target="10.20.1.12", reason="Compromised host")
    ms.request_action(admin, session_id, "isolate", target="10.20.1.12", reason="Compromised host", confirm_target="10.20.1.12")
    with pytest.raises(MitigationError, match="open action"):
        ms.request_action(admin, session_id, "rate_limit", target="10.20.1.12", limit_bps=M, reason="Too much traffic")


def test_a_failed_enforcer_is_recorded_as_failed(admin, engine):
    class Broken:
        name = "broken"

        def apply(self, mitigation):
            raise ms.EnforcementError("backend refused")

        def remove(self, mitigation):
            raise AssertionError("nothing to remove")

    _train(admin)
    session_id = _start(engine, admin, "bandwidth_hog")
    now = _advance(engine, 40, T0)
    proposal = _first_proposal(admin, session_id)
    ms.set_enforcer_for_tests("simulation", Broken())
    try:
        failed = ms.approve(admin, proposal["id"], reason="Try to limit", now=_at(now))
    finally:
        ms.set_enforcer_for_tests("simulation", None)
    assert failed["status"] == "failed" and failed["failure_reason"] == "backend refused"
    assert failed["recovery_status"] == "not_applied"
    now = _advance(engine, 3, now)
    assert _host_rate(session_id, "10.20.1.99") > 40 * M  # nothing changed
    assert [r for r in audit_rows() if r["action"] == "mitigation.apply" and r["outcome"] == "failure"]


def test_ending_a_simulation_ends_its_actions_and_clearing_removes_them(admin, engine):
    _train(admin)
    session_id = _start(engine, admin, "bandwidth_hog")
    now = _advance(engine, 40, T0)
    proposal = _first_proposal(admin, session_id)
    ms.approve(admin, proposal["id"], reason="Limit the hog", now=_at(now))
    engine.stop(admin)
    assert {r["status"] for r in _rows(session_id)} == {"ended"}
    with pytest.raises(MitigationError):
        ms.rollback(admin, proposal["id"], reason="Too late now")
    assert sim.data_counts(admin)["mitigations"] >= 1
    sim.clear_simulation_data(admin)
    assert sim.data_counts(admin)["mitigations"] == 0


def test_a_restart_closes_actions_of_sessions_that_stopped_with_it(admin, engine):
    _train(admin)
    session_id = _start(engine, admin, "bandwidth_hog")
    now = _advance(engine, 40, T0)
    ms.approve(admin, _first_proposal(admin, session_id)["id"], reason="Limit the hog", now=_at(now))
    assert ms.close_orphans() == 0  # the session is still running
    monitoring_service.recover_interrupted_sessions("simulation")
    assert ms.close_orphans() >= 1
    assert {r["status"] for r in _rows(session_id)} == {"ended"}


def test_incident_gets_linked_and_noted(admin, engine):
    _train(admin)
    session_id = _start(engine, admin, "bandwidth_hog")
    now = _advance(engine, 45, T0)
    proposal = _first_proposal(admin, session_id)
    ms.approve(admin, proposal["id"], reason="Limit the hog", now=_at(now))
    now = _advance(engine, 15, now)
    row = next(r for r in _rows(session_id) if r["id"] == proposal["id"])
    assert row["incident_id"]
    with database_service.session() as conn:
        notes = [r["note"] for r in conn.execute("SELECT note FROM incident_events WHERE incident_id = ? AND event_type = 'note'",
                                                 (row["incident_id"],)).fetchall()]
    assert any(f"Mitigation #{row['id']}" in n and "applied" in n for n in notes)
    assert any("recovery check" in n for n in notes)


# ------------------------------------------------------------------ settings and the database

def test_settings_are_validated_and_admin_only(admin, analyst):
    assert settings_service.get_mitigation_settings().policy == "recommend"
    with pytest.raises(PermissionDenied):
        settings_service.update_mitigation_settings(analyst, MitigationSettings(policy="auto_rate_limit"))
    for bad in (MitigationSettings(policy="always"), MitigationSettings(min_confidence=2), MitigationSettings(min_severity="x"),
                MitigationSettings(rate_limit_share=0.9), MitigationSettings(critical_min_share=0.8, normal_min_share=0.8),
                MitigationSettings(rate_limit_minutes=0)):
        with pytest.raises(SettingsError):
            settings_service.update_mitigation_settings(admin, bad)
    settings_service.update_mitigation_settings(admin, MitigationSettings(policy="off"))
    assert settings_service.get_mitigation_settings().policy == "off"


def test_the_database_refuses_impossible_rows(admin):
    base = {"origin": "simulation", "action_type": "rate_limit", "target_kind": "source", "target": "10.0.0.1",
            "status": "proposed", "initiated_by": "engine", "limit_bps": 1000.0, "duration_seconds": 600,
            "reason": "Some reason", "created_at": "2026-10-01T00:00:00.000000+00:00"}
    from repositories import mitigation_repository as repo

    for change in ({"limit_bps": None}, {"action_type": "block"}, {"action_type": "prioritize"}, {"status": "active"},
                   {"duration_seconds": 1}, {"status": "whatever"}):
        with pytest.raises(sqlite3.IntegrityError):
            with database_service.session(write=True) as conn:
                repo.insert(conn, {**base, **change})
    with database_service.session(write=True) as conn:
        repo.insert(conn, base)
    with pytest.raises(sqlite3.IntegrityError):  # one open action per target
        with database_service.session(write=True) as conn:
            repo.insert(conn, base)


def test_no_shell_or_network_code_in_the_engine():
    for name in ("mitigation_service", "mitigation_scoring", "host_allocation"):
        tree = ast.parse((ROOT / "services" / f"{name}.py").read_text())
        imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        assert not imported & {"socket", "subprocess", "scapy", "os"}


def _simulation_page(user):
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.session_state[session_service.USER_ID_KEY] = user.id
    app.session_state[session_service.LAST_ACTIVITY_KEY] = utc_now()
    app.run()
    app.switch_page("views/simulation.py")
    app.run()
    return app


def test_the_simulation_page_shows_a_decision_and_acting_on_it_works(admin_user, admin, engine):
    _train(admin)
    _simulation_page(admin_user)  # the first page of a process closes sessions left over from an earlier process
    session_id = _start(engine, admin, "bandwidth_hog")
    _advance(engine, 40, T0)
    proposal = _first_proposal(admin, session_id)
    app = _simulation_page(admin_user)
    assert not app.exception
    text = " ".join(m.value for m in app.markdown)
    assert f"#{proposal['id']}" in text and "Limit traffic from 10.20.1.99" in text
    app.text_input(key=f"mitigation_reason_{proposal['id']}").input("Confirmed upload hog")
    app.button(key=f"mitigation_approve_{proposal['id']}").click()
    app.run()
    assert not app.exception
    assert [e.value for e in app.error] == []
    assert next(r for r in _rows(session_id) if r["id"] == proposal["id"])["status"] == "active"
    app.run()
    app.button(key=f"mitigation_rollback_{proposal['id']}").click()
    app.run()
    assert not app.exception
    assert next(r for r in _rows(session_id) if r["id"] == proposal["id"])["status"] == "rolled_back"


def test_an_analyst_sees_decisions_but_gets_no_controls(admin, analyst_user, engine):
    _train(admin)
    _simulation_page(analyst_user)
    session_id = _start(engine, admin, "bandwidth_hog")
    _advance(engine, 40, T0)
    proposal = _first_proposal(admin, session_id)
    app = _simulation_page(analyst_user)
    assert not app.exception
    assert not [b for b in app.button if b.key == f"mitigation_approve_{proposal['id']}"]
    assert any("Only an administrator can decide" in c.value for c in app.caption)
