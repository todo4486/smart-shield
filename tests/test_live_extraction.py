from __future__ import annotations

import pytest

from services.flow_extractor import ACTIVE_TIMEOUT_S, IDLE_TIMEOUT_S, TCP_FIN, FlowTable, extract
from services.interface_counters import Snapshot, rates, validate_latency_target
from services.intrusion_features import LIVE_FLOW_FEATURES

A, B = "10.0.0.1", "10.0.0.2"


def pkt(ts, src=A, dst=B, sport=50000, dport=443, proto=6, length=100, flags=0):
    return (ts, src, dst, sport, dport, proto, length, flags)


def test_bidirectional_packets_form_one_flow_with_cic_features():
    flows = extract([
        pkt(0.0, length=100),
        pkt(0.5, src=B, dst=A, sport=443, dport=50000, length=1000),
        pkt(1.0, length=300),
        pkt(2.0, src=B, dst=A, sport=443, dport=50000, length=600),
    ])
    assert len(flows) == 1
    f = flows[0]
    assert (f["src_ip"], f["dst_ip"], f["dst_port"], f["protocol"]) == (A, B, 443, "TCP")
    feats = f["features"]
    assert tuple(feats) == LIVE_FLOW_FEATURES
    assert feats["flow_duration"] == 2_000_000  # microseconds
    assert feats["total_fwd_packets"] == 2 and feats["total_backward_packets"] == 2
    assert feats["total_length_of_fwd_packets"] == 400 and feats["total_length_of_bwd_packets"] == 1600
    assert feats["fwd_packet_length_max"] == 300 and feats["bwd_packet_length_min"] == 600
    assert feats["flow_bytes_s"] == pytest.approx(2000 / 2.0)
    assert feats["flow_packets_s"] == pytest.approx(2.0)
    assert feats["flow_iat_mean"] == pytest.approx((0.5e6 + 0.5e6 + 1.0e6) / 3)
    assert feats["flow_iat_max"] == pytest.approx(1.0e6) and feats["flow_iat_min"] == pytest.approx(0.5e6)
    assert feats["min_packet_length"] == 100 and feats["max_packet_length"] == 1000
    assert feats["packet_length_mean"] == pytest.approx(500)


def test_single_packet_flow_has_no_rate_instead_of_zero_or_infinity():
    [flow] = extract([pkt(5.0, proto=17, sport=53, dport=53)])
    feats = flow["features"]
    assert feats["flow_duration"] == 0 and feats["flow_bytes_s"] is None and feats["fwd_packets_s"] is None
    assert flow["protocol"] == "UDP"


def test_idle_timeout_splits_flows():
    flows = extract([pkt(0), pkt(1), pkt(1 + IDLE_TIMEOUT_S + 0.1)])
    assert len(flows) == 2 and flows[0]["end_reason"] == "idle timeout"


def test_active_timeout_cuts_long_flows():
    packets = [pkt(t) for t in range(0, int(ACTIVE_TIMEOUT_S) + 30, 10)]
    flows = extract(packets)
    assert len(flows) == 2 and flows[0]["end_reason"] == "active timeout"
    assert flows[0]["duration_s"] <= ACTIVE_TIMEOUT_S


def test_tcp_fin_ends_flow_and_new_connection_starts_fresh():
    table = FlowTable()
    assert table.add(pkt(0)) == []
    finished = table.add(pkt(1, flags=TCP_FIN))
    assert len(finished) == 1 and finished[0]["end_reason"] == "tcp fin/rst" and finished[0]["packet_count"] == 2
    assert table.active == {}


def test_memory_bound_evicts_oldest_flow():
    table = FlowTable(max_active=2)
    table.add(pkt(0, sport=1))
    table.add(pkt(1, sport=2))
    evicted = table.add(pkt(2, sport=3))
    assert len(evicted) == 1 and evicted[0]["src_port"] == 1 and table.evicted_for_memory == 1
    assert len(table.active) == 2


def test_counter_rates_are_measured_differences():
    a = Snapshot(100.0, 1_000, 500, 10, 5)
    b = Snapshot(102.0, 21_000, 4_500, 30, 9)
    r = rates(a, b)
    assert r["incoming_bytes_per_second"] == 10_000 and r["outgoing_bytes_per_second"] == 2_000
    assert r["throughput_bps"] == 96_000 and r["incoming_packets_per_second"] == 10
    assert r["utilization_ratio"] is None  # no capacity -> no percentage
    assert rates(a, b, capacity_bps=192_000)["utilization_ratio"] == 0.5


def test_counter_reset_gives_no_rate_not_negative():
    r = rates(Snapshot(0, 5_000, 5_000, 5, 5), Snapshot(1, 100, 6_000, 6, 6))
    assert r["incoming_bytes_per_second"] is None and r["throughput_bps"] is None
    assert r["outgoing_bytes_per_second"] == 1_000


def test_over_capacity_utilization_is_not_reported():
    r = rates(Snapshot(0, 0, 0, 0, 0), Snapshot(1, 1_000, 0, 1, 0), capacity_bps=1_000)
    assert r["utilization_ratio"] is None


@pytest.mark.parametrize("target, ok", [("192.168.1.1:443", True), ("router.lab:22", True), ("bad host:1", False),
                                        ("host:0", False), ("host", False), ("h;rm:1", False)])
def test_latency_target_validation(target, ok):
    if ok:
        assert validate_latency_target(target)
    else:
        with pytest.raises(ValueError):
            validate_latency_target(target)
