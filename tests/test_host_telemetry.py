"""M1: per-host live bandwidth, from packet to stored sample to the NOC snapshot."""
from __future__ import annotations

import queue
import threading
import time

import pytest

from services import capture_worker, database_service, live_monitor_service, live_network_service as live, settings_service
from services.authorization import PermissionDenied
from services.flow_extractor import FlowTable
from services.host_telemetry import MAX_HOSTS, OTHER, HostMeter, connections_by_host, wire_length
from services.interface_counters import Snapshot
from services.live_monitor_service import LiveMonitor


def packet(src="10.0.0.1", dst="10.0.0.2", payload=100, ip_len=140, ts=1000.0, dport=443):
    return (ts, src, dst, 5000, dport, 6, payload, 0, ip_len)


def test_meter_counts_sent_and_received_per_host_and_resets():
    meter = HostMeter()
    meter.add(packet(ip_len=1000))
    meter.add(packet(ip_len=1000))
    meter.add(packet(src="10.0.0.2", dst="10.0.0.1", ip_len=500))
    rows = {r["host"]: r for r in meter.sample(2.0, {"10.0.0.1": 3})}
    assert rows["10.0.0.1"]["sent_bps"] == 8 * 2000 / 2 and rows["10.0.0.1"]["received_bps"] == 8 * 500 / 2
    assert rows["10.0.0.2"]["received_pps"] == 1.0 and rows["10.0.0.2"]["sent_pps"] == 0.5
    assert rows["10.0.0.1"]["active_connections"] == 3 and rows["10.0.0.2"]["active_connections"] == 0
    assert meter.sample(2.0) == []  # one sample describes exactly one interval
    with pytest.raises(ValueError):
        meter.sample(0)


def test_wire_length_prefers_the_ip_length():
    assert wire_length(packet(payload=100, ip_len=140)) == 140
    assert wire_length((1.0, "a", "b", 1, 2, 6, 100, 0)) == 100  # 8-field summaries still work


def test_meter_is_bounded_and_rolls_the_rest_up():
    meter = HostMeter(max_hosts=3)
    for i in range(6):
        meter.add(packet(src=f"10.0.0.{i}", dst="10.0.1.1", ip_len=100 + i))
    rows = meter.sample(1.0)
    assert len(rows) == 3 and rows[0]["host"] == "10.0.1.1" and rows[-1]["host"] == OTHER
    total_sent = sum(8 * (100 + i) for i in range(6))
    assert sum(r["sent_bps"] for r in rows) == total_sent  # nothing is lost in the roll-up
    assert MAX_HOSTS >= 100


def test_connections_from_open_flows():
    table = FlowTable()
    table.add(packet()[:8])
    table.add(packet(dst="10.0.0.3", dport=80)[:8])
    assert connections_by_host(table.active) == {"10.0.0.1": 2, "10.0.0.2": 1, "10.0.0.3": 1}


def test_real_packet_summary_reports_the_ip_length():
    from scapy.layers.inet import IP, TCP

    built = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=443, flags="A") / (b"x" * 100)  # in memory only
    parsed = IP(bytes(built))
    parsed.time = 1000.0
    summary = capture_worker.summarize_packet(parsed)
    assert summary[1:6] == ("10.0.0.1", "10.0.0.2", 5000, 443, 6)
    assert summary[6] == 100 and summary[8] == 140  # payload for flow features, whole IP packet for bandwidth


def test_flow_table_accepts_the_longer_packet_summary():
    table = FlowTable()
    table.add(packet())
    assert len(table.active) == 1


# ------------------------------------------------------------------ pure summaries

def _sample(host, at, sent=0.0, received=0.0, connections=1):
    return {"host": host, "timestamp": at, "sent_bps": sent, "received_bps": received, "sent_pps": 1.0,
            "received_pps": 0.0, "active_connections": connections}


def test_host_kind_and_traffic_class():
    assert live.host_kind("10.0.0.1", {"10.0.0.1"}) == "This machine"
    assert live.host_kind("192.168.1.9", set()) == "Local network"
    assert live.host_kind("8.8.8.8", set()) == "Internet"
    assert live.host_kind("nope", set()) == "Other"
    assert live.traffic_class([443, 443, 53, 9999, 9999, 9999]) == "Web"  # known ports win over unknown ones
    assert live.traffic_class([9999]) == "Other traffic" and live.traffic_class([None]) == "Other traffic"
    assert live.traffic_class([]) is None


def test_summarize_means_flags_and_orders():
    samples = [_sample("10.0.0.1", "t1", sent=100), _sample("10.0.0.1", "t2", sent=300, connections=7),
               _sample("10.0.0.9", "t2", sent=10)]
    flows = [{"src_ip": "10.0.0.9", "dst_port": 22, "intrusion_prediction": "SSH-Patator"},
             {"src_ip": "10.0.0.1", "dst_port": 443, "intrusion_prediction": None}]
    rows = live.summarize_hosts(samples, flows, {"10.0.0.1"})
    assert [r.host for r in rows] == ["10.0.0.9", "10.0.0.1"]  # suspicious first, even though it is quieter
    assert rows[0].status == "suspicious" and rows[0].top_category == "SSH-Patator" and rows[0].traffic == "Remote access"
    assert rows[1].status == "normal" and rows[1].sent_bps == 200 and rows[1].active_connections == 7
    assert rows[1].kind == "This machine" and rows[1].traffic == "Web"
    assert rows[0].sent_bps == 5  # a quiet interval counts as no traffic in the mean
    assert live.summarize_hosts(samples, flows, set(), intervals=4)[1].sent_bps == 100
    assert live.summarize_hosts([], flows, set()) == []


def test_link_figures_never_invent_capacity_values():
    row = {"incoming_bytes_per_second": 1000.0, "outgoing_bytes_per_second": 500.0, "throughput_bps": 12000.0,
           "utilization_ratio": None, "incoming_packets_per_second": 5.0, "outgoing_packets_per_second": 2.0}
    figures = live.link_figures(row, None)
    assert figures["incoming_bps"] == 8000 and figures["outgoing_bps"] == 4000
    assert figures["available_bps"] is None and figures["utilization"] is None
    assert live.link_figures(row, 20000.0)["available_bps"] == 8000
    assert live.link_figures(row, 1000.0)["available_bps"] == 0  # never negative
    assert all(v is None for v in live.link_figures(None, 100.0).values())


# ------------------------------------------------------------------ worker → database → snapshot

def test_worker_emits_host_rows_only_in_packet_mode(monkeypatch):
    clock = {"t": 0.0}

    def snapshot(interface):
        clock["t"] += 1.0
        return Snapshot(clock["t"], int(clock["t"] * 1000), int(clock["t"] * 500), 10, 10)

    monkeypatch.setattr(capture_worker, "read_snapshot", snapshot)

    class FakeSniffer:
        running, exception = True, None

        def __init__(self, interface, pending):
            self.pending = pending

        def start(self):
            self.pending.append(packet(ts=time.time(), ip_len=1500))

        def stop(self):
            pass

    for mode, expect_hosts in (("packets", True), ("counters", False)):
        out, stop = queue.Queue(), threading.Event()
        worker = threading.Thread(target=capture_worker.run, daemon=True, args=(
            {"interface": "eth0", "mode": mode, "interval_seconds": 0.3}, out, stop),
            kwargs={"sniffer_factory": FakeSniffer})
        worker.start()
        deadline = time.time() + 8
        metrics = None
        while time.time() < deadline and metrics is None:
            message = out.get(timeout=8)
            assert message["type"] != "error", message
            if message["type"] == "metrics":
                metrics = message
        stop.set()
        worker.join(timeout=5)
        assert metrics is not None
        if expect_hosts:
            assert {r["host"] for r in metrics["hosts"]} == {"10.0.0.1", "10.0.0.2"}
            assert metrics["hosts"][0]["active_connections"] == 1
        else:
            assert metrics["hosts"] is None  # unavailable, not an empty measurement


def _sample_message(hosts):
    return {"type": "metrics", "at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()), "hosts": hosts,
            "active_flows": 2, "dropped_messages": 0, "dropped_packets": 0,
            "sample": {"incoming_bytes_per_second": 1000.0, "outgoing_bytes_per_second": 500.0,
                       "incoming_packets_per_second": 5.0, "outgoing_packets_per_second": 2.0,
                       "throughput_bps": 12000.0, "utilization_ratio": 0.12, "configured_capacity_bps": 100000.0,
                       "latency_ms": None}}


@pytest.fixture
def capture(admin):
    settings_service.update_monitoring_settings(admin, settings_service.MonitoringSettings(("eth0",)))

    def worker(config, out, stop_event):
        out.put({"type": "started"})
        hosts = [{"host": "10.0.0.1", "sent_bps": 4000.0, "received_bps": 8000.0, "sent_pps": 1.0, "received_pps": 2.0,
                  "active_connections": 2}]
        out.put(_sample_message(hosts if config["mode"] == "packets" else None))
        stop_event.wait(10)
        out.put({"type": "stopped"})

    monitor = LiveMonitor(worker_target=worker, use_threads=True)
    live_monitor_service.reset_monitor_for_tests(monitor)
    yield monitor
    if monitor.status.running:
        monitor.stop(None)
    live_monitor_service.reset_monitor_for_tests(None)


def _wait(predicate, timeout=8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_host_samples_are_stored_and_reach_the_snapshot(admin, analyst, capture, monkeypatch):
    monkeypatch.setattr(live_monitor_service, "capture_capability",
                        lambda system=None: live_monitor_service.Capability(True, True, []))
    session_id = capture.start(admin, "eth0", mode="packets", capacity_bps=100000.0, live_detection=False)
    assert _wait(lambda: capture.status.samples >= 1)
    with database_service.session() as conn:
        row = conn.execute("SELECT * FROM host_metrics WHERE session_id = ?", (session_id,)).fetchone()
    assert row["host"] == "10.0.0.1" and row["received_bps"] == 8000 and row["provenance"] == "measured"
    view = live.snapshot(analyst, live_running=True, live_session_id=session_id, live_active_flows=2)
    assert view.running and view.source.label == "LIVE" and view.mode == "packets"
    assert view.incoming_bps == 8000 and view.outgoing_bps == 4000 and view.capacity_bps == 100000
    assert view.available_bps == 88000 and view.utilization == 0.12 and view.active_connections == 2
    assert [h.host for h in view.hosts] == ["10.0.0.1"] and view.hosts[0].status == "normal"
    assert view.history and view.notes == []


def test_snapshot_says_what_is_missing(admin, analyst, capture, monkeypatch):
    empty = live.snapshot(analyst)
    assert empty.session_id is None and "No live capture" in empty.notes[0] and empty.incoming_bps is None
    session_id = capture.start(admin, "eth0", mode="counters")
    assert _wait(lambda: capture.status.samples >= 1)
    capture.stop(admin)
    view = live.snapshot(analyst)  # stopped: last capture's data, labelled as such, not LIVE
    assert view.session_id == session_id and not view.running and view.source.label == "DATASET"
    assert view.hosts == [] and view.active_connections is None
    joined = " ".join(view.notes)
    assert "not the network right now" in joined and "interface-counter mode" in joined


def test_snapshot_needs_a_signed_in_user():
    with pytest.raises(PermissionDenied):
        live.snapshot(None)


def test_live_tab_renders_for_both_roles_without_data(admin_user, analyst_user):
    from streamlit.testing.v1 import AppTest

    from pathlib import Path

    from services import session_service
    from services.timeutil import utc_now
    app = str(Path(__file__).resolve().parent.parent / "app.py")
    for user in (admin_user, analyst_user):
        at = AppTest.from_file(app, default_timeout=60)
        at.session_state[session_service.USER_ID_KEY] = user.id
        at.session_state[session_service.LAST_ACTIVITY_KEY] = utc_now()
        at.switch_page("views/bandwidth.py")
        at.run()
        assert not at.exception
        assert any("No live capture or simulation has run yet" in c.value for c in at.caption)
