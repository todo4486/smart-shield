from __future__ import annotations

import queue
import time

import numpy as np
import pytest

from services import (
    alert_service, capture_worker, database_service, dataset_service, intrusion_training_service,
    live_monitor_service as live, monitoring_service, settings_service,
)
from services.authorization import PermissionDenied
from services.intrusion_features import LIVE_FLOW_FEATURES
from services.intrusion_training_service import IntrusionTrainingOptions
from services.live_monitor_service import Capability, LiveMonitor, MonitorError
from tests.synthetic import TYPES, cic_like_frame, to_cic_csv


def ddos_flow(i, start=1_700_000_000.0):
    p = TYPES["DDoS"]
    features = {name: 0.0 for name in LIVE_FLOW_FEATURES}
    features.update(flow_duration=p["duration"], total_fwd_packets=p["packets"], total_backward_packets=2,
                    total_length_of_fwd_packets=p["size"] * p["packets"], total_length_of_bwd_packets=p["size"] * 2,
                    flow_bytes_s=p["rate"], flow_packets_s=p["rate"], fwd_packets_s=p["rate"], bwd_packets_s=p["rate"],
                    flow_iat_mean=p["duration"] / 3, flow_iat_max=p["duration"] / 3, flow_iat_min=p["duration"] / 3)
    for name in LIVE_FLOW_FEATURES:
        if name.endswith(("_max", "_min", "_mean")) and "iat" not in name:
            features[name] = p["size"]
    return {"start": start + i, "end": start + i + 0.05, "src_ip": f"172.16.0.{i}", "dst_ip": "192.168.1.50",
            "src_port": 40000 + i, "dst_port": 80, "protocol": "TCP", "packet_count": 5, "byte_count": 300,
            "duration_s": 0.05, "end_reason": "tcp fin/rst", "features": features}


SAMPLE = {"incoming_bytes_per_second": 1000.0, "outgoing_bytes_per_second": 500.0, "incoming_packets_per_second": 10.0,
          "outgoing_packets_per_second": 5.0, "throughput_bps": 12000.0, "utilization_ratio": None,
          "configured_capacity_bps": None, "latency_ms": None}


def fake_worker(script):
    def run(config, out, stop_event):
        for message in script(config):
            out.put(message)
        stop_event.wait(10)
        out.put({"type": "stopped", "dropped_messages": 0})
    return run


def normal_script(config):
    yield {"type": "started", "pid": 1, "mode": config["mode"]}
    for _ in range(2):
        yield {"type": "metrics", "at": "2026-10-22T10:00:00.000000+00:00", "sample": dict(SAMPLE),
               "dropped_messages": 0, "active_flows": 3}
    if config["mode"] == "packets":
        yield {"type": "flows", "flows": [ddos_flow(i) for i in range(30)]}


@pytest.fixture
def monitor(admin, monkeypatch):
    settings_service.update_monitoring_settings(admin, settings_service.MonitoringSettings(("eth0",)))
    monkeypatch.setattr(live, "capture_capability", lambda system=None: Capability(True, True, []))
    m = LiveMonitor(worker_target=fake_worker(normal_script), use_threads=True)
    yield m
    if m.status.running:
        m.stop(None)


def wait_for(predicate, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def session_row(session_id):
    with database_service.session() as conn:
        return dict(conn.execute("SELECT * FROM monitoring_sessions WHERE id = ?", (session_id,)).fetchone())


def train_live_model(admin, feature_set):
    dataset_id = dataset_service.register_intrusion_dataset(
        admin, to_cic_csv(cic_like_frame(2000)), f"{feature_set}.csv", feature_set).dataset_id
    intrusion_training_service.train_intrusion_models(admin, IntrusionTrainingOptions(
        dataset_ids=(dataset_id,), feature_set=feature_set, n_estimators=20, activate=True))


# ---------------------------------------------------------------- lifecycle

def test_counters_lifecycle_persists_states_and_measured_metrics(admin, monitor):
    session_id = monitor.start(admin, "eth0", mode="counters")
    assert wait_for(lambda: monitor.status.state == "RUNNING" and monitor.status.samples == 2)
    assert session_row(session_id)["status"] == "RUNNING"
    with pytest.raises(MonitorError, match="already running"):
        monitor.start(admin, "eth0")
    monitor.stop(admin)
    row = session_row(session_id)
    assert row["status"] == "STOPPED" and row["ended_at"] and row["source_type"] == "live_capture"
    with database_service.session() as conn:
        metric = conn.execute("SELECT * FROM network_metrics WHERE session_id = ?", (session_id,)).fetchone()
    assert metric["provenance"] == "measured" and metric["measurement_method"] == "psutil_counters"
    assert metric["throughput_provenance"] == "derived"
    assert metric["utilization_ratio"] is None and metric["utilization_provenance"] == "unavailable"
    assert metric["latency_ms"] is None and metric["packet_loss_ratio"] is None  # never invented
    assert not monitor.status.running


def test_only_authorised_interfaces_and_admins(admin, analyst, monitor):
    with pytest.raises(PermissionDenied):
        monitor.start(analyst, "eth0")
    with pytest.raises(MonitorError, match="not authorised"):
        monitor.start(admin, "wlan0")
    with pytest.raises(MonitorError, match="Unknown monitoring mode"):
        monitor.start(admin, "eth0", mode="inject")


def test_packet_mode_refused_with_reason_when_capture_not_permitted(admin, monitor, monkeypatch):
    monkeypatch.setattr(live, "capture_capability",
                        lambda system=None: Capability(True, False, ["macOS only lets root read /dev/bpf*."]))
    with pytest.raises(MonitorError, match="only lets root"):
        monitor.start(admin, "eth0", mode="packets")


def test_worker_error_sets_error_state_and_allows_restart(admin, monitor):
    def failing(config):
        yield {"type": "error", "permission": True, "message": "Packet capture is not permitted on eth0"}

    monitor._worker_target = fake_worker(failing)
    session_id = monitor.start(admin, "eth0", mode="counters")
    assert wait_for(lambda: not monitor.status.running)
    row = session_row(session_id)
    assert row["status"] == "ERROR" and "not permitted" in row["status_message"]
    monitor._worker_target = fake_worker(normal_script)
    monitor.start(admin, "eth0")  # a failed capture never blocks the next one
    monitor.stop(admin)


def test_interrupted_sessions_are_closed_on_restart(admin):
    with database_service.session(write=True) as conn:
        sid = monitoring_service.create_session(conn, user_id=admin.user_id, source_type="live_capture")
        monitoring_service.transition(conn, sid, monitoring_service.SessionState.RUNNING)
    assert monitoring_service.recover_interrupted_sessions() == 1
    assert session_row(sid)["status"] == "ERROR"


def test_get_monitor_is_a_singleton():
    live.reset_monitor_for_tests(None)
    try:
        assert live.get_monitor() is live.get_monitor()
    finally:
        live.reset_monitor_for_tests(None)


def test_bounded_queue_drops_and_counts():
    out = queue.Queue(maxsize=2)
    sender = capture_worker._Sender(out)
    for i in range(5):
        sender.put({"n": i})
    assert out.qsize() == 2 and sender.dropped == 3


# ---------------------------------------------------------------- detection

def test_live_detection_with_compatible_model_raises_grouped_alert(admin, monitor):
    train_live_model(admin, "live_compatible")
    session_id = monitor.start(admin, "eth0", mode="packets")
    assert wait_for(lambda: monitor.status.flows_stored == 30)
    assert monitor.status.detection["enabled"] and monitor.status.flagged > 0
    monitor.stop(admin)
    with database_service.session() as conn:
        flow = conn.execute("SELECT * FROM network_flows WHERE session_id = ? AND intrusion_prediction IS NOT NULL",
                            (session_id,)).fetchone()
    assert flow["model_version"] and flow["provenance"] == "measured"
    alerts = alert_service.list_alerts(admin)
    assert len(alerts) >= 1 and all(a.evidence["source"] == "live capture" for a in alerts)
    assert alerts[0].evidence["interface"] == "eth0" and "time_window_utc" in alerts[0].evidence


def test_full_feature_model_is_rejected_for_live_use_not_zero_filled(admin, monitor):
    train_live_model(admin, "full")  # needs init_win_bytes_forward, which live capture cannot compute
    monitor.start(admin, "eth0", mode="packets")
    assert wait_for(lambda: monitor.status.flows_stored == 30)
    detection = monitor.status.detection
    assert not detection["enabled"] and "REJECTED" in detection["reason"]
    assert "init_win_bytes_forward" in detection["missing"]
    assert monitor.status.flows_scored == 0 and alert_service.list_alerts(admin) == []
    monitor.stop(admin)


def test_flow_storage_limit(admin, monitor):
    monitor.start(admin, "eth0", mode="packets", live_detection=False)
    monitor._max_flows = 10
    assert wait_for(lambda: monitor.status.flows_stored + monitor.status.flows_not_stored == 30)
    assert monitor.status.flows_stored == 10 and monitor.status.flows_not_stored == 20
    monitor.stop(admin)


def test_monitoring_settings_validation(admin, analyst):
    with pytest.raises(PermissionDenied):
        settings_service.update_monitoring_settings(analyst, settings_service.MonitoringSettings(("eth0",)))
    with pytest.raises(settings_service.SettingsError, match="host:port"):
        settings_service.update_monitoring_settings(admin, settings_service.MonitoringSettings(("eth0",), "nope"))
    assert settings_service.get_monitoring_settings().allowed_interfaces == ()  # nothing allowed by default


def test_monitoring_code_is_passive_only():
    """No Scapy transmit/probe functions anywhere in the application code."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    forbidden = re.compile(r"\b(sendp?|srp?1?|srloop|sendpfast|arping|traceroute)\s*\(")
    offenders = []
    for path in root.rglob("*.py"):
        if ".venv" in path.parts or "tests" in path.parts:
            continue
        for line in path.read_text().splitlines():
            if "scapy" in path.read_text() and forbidden.search(line):
                offenders.append(f"{path.name}: {line.strip()}")
    assert offenders == []


def test_spawned_worker_does_not_rerun_the_parent_main_script(tmp_path, monkeypatch):
    """Regression: under Streamlit, __main__ is app.py; a spawned worker must not re-execute it."""
    import multiprocessing
    import sys
    import types

    from tests import spawn_probe

    marker = tmp_path / "main_was_executed"
    fake_main_file = tmp_path / "fake_app.py"
    fake_main_file.write_text(f"open({str(marker)!r}, 'w').write('re-executed')\n")
    fake_main = types.ModuleType("__main__")
    fake_main.__file__ = str(fake_main_file)
    monkeypatch.setitem(sys.modules, "__main__", fake_main)

    ran = tmp_path / "worker_ran"
    process = multiprocessing.get_context("spawn").Process(target=spawn_probe.touch, args=(str(ran),))
    live.start_without_main_reimport(process)
    process.join(30)
    assert process.exitcode == 0 and ran.exists()
    assert not marker.exists(), "the spawned worker re-ran the parent's main script"
    assert sys.modules["__main__"] is fake_main  # restored


def test_macos_capture_needs_read_and_write_access(monkeypatch):
    """Scapy opens /dev/bpf* with O_RDWR: read-only access (e.g. chmod o+r) must not count as capture support."""
    import os

    def access(path, mode):
        return not (mode & os.W_OK)  # readable but not writable

    monkeypatch.setattr(live.os, "access", access)
    capability = live.capture_capability(system="Darwin")
    assert not capability.packets and capability.counters
    assert any("reading and writing" in r for r in capability.reasons)
