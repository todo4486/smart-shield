"""Live monitoring lifecycle: one capture worker at a time, managed by a process-wide singleton.

* start(): admin-only (CONTROL_MONITORING), interface must be allow-listed in
  Settings and exist on this machine. Creates a live_capture session (STARTING)
  and launches the worker in a separate process. It becomes RUNNING when the
  worker reports that it started.
* A consumer thread drains the worker's bounded queue and writes in batches:
  metrics every few seconds, flows in groups. Live detection runs on finished
  flows only with a compatible model (every feature it needs is one the flow
  extractor computes); otherwise the model is reported as rejected, never fed
  zero-filled features.
* stop(): STOPPING, then the worker is signalled, joined (terminated if it hangs)
  and the session is set to STOPPED. Worker errors set ERROR with the reason.
* Streamlit reruns call get_monitor(), which always returns the same instance,
  so reruns never start a second worker.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import platform
import queue as queue_module
import sys
import threading
import types
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import numpy as np
import pandas as pd

from repositories import monitoring_repository, telemetry_repository
from services import (
    alert_service, audit_service, capture_worker, database_service, model_registry_service, monitoring_service,
    settings_service,
)
from services.authorization import Permission, Principal, require_permission
from services.flow_extractor import ACTIVE_TIMEOUT_S, IDLE_TIMEOUT_S
from services.intrusion_features import LIVE_FLOW_FEATURES
from services.monitoring_service import SessionState, SourceType
from services.timeutil import utc_now_iso

QUEUE_MAX = 2_000
FLUSH_SECONDS = 2.0
JOIN_TIMEOUT_SECONDS = 5.0
LIVE_ALERT_COOLDOWN_MINUTES = 15
MODES = {"counters": "Interface counters (no special permission)",
         "packets": "Counters + passive packet capture and flow analysis (needs capture permission)"}


class MonitorError(Exception):
    pass


@dataclass
class Capability:
    counters: bool
    packets: bool
    reasons: List[str] = field(default_factory=list)


def capture_capability(system: Optional[str] = None) -> Capability:
    """What this server can do, and in plain words why not."""
    reasons: List[str] = []
    try:
        import psutil  # noqa: F401
        counters = True
    except ImportError:
        counters = False
        reasons.append("psutil is not installed, so interface counters are unavailable.")
    try:
        import scapy  # noqa: F401
        packets = True
    except ImportError:
        packets = False
        reasons.append("Scapy is not installed, so packet capture is unavailable.")
    system = system or platform.system()
    if packets and system == "Darwin":
        # Scapy opens /dev/bpf* with O_RDWR, so read access alone is not enough.
        if not os.access("/dev/bpf0", os.R_OK | os.W_OK):
            packets = False
            reasons.append("macOS only lets root open packet-capture devices (/dev/bpf*) for reading and writing, "
                           "which Scapy needs. Install Wireshark (its ChmodBPF helper grants access to the "
                           "access_bpf group), then log out and back in; or run the app with sudo in an authorised lab.")
    elif packets and system == "Linux":
        if os.geteuid() != 0 and not _linux_has_cap_net_raw():
            packets = False
            reasons.append("Linux needs root or the CAP_NET_RAW capability for packet capture "
                           "(e.g. sudo setcap cap_net_raw,cap_net_admin=eip on the Python binary).")
    elif packets and system == "Windows":
        reasons.append("Windows needs Npcap installed and the app run as administrator for packet capture.")
    return Capability(counters, packets, reasons)


def _linux_has_cap_net_raw() -> bool:
    try:
        with open("/proc/self/status") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << 13))
    except OSError:
        pass
    return False


@dataclass
class LiveStatus:
    running: bool
    session_id: Optional[int] = None
    state: str = "STOPPED"
    interface: Optional[str] = None
    mode: Optional[str] = None
    started_at: Optional[str] = None
    samples: int = 0
    flows_stored: int = 0
    flows_not_stored: int = 0
    flows_scored: int = 0
    flagged: int = 0
    dropped_messages: int = 0
    active_flows: Optional[int] = None
    detection: Dict[str, Any] = field(default_factory=dict)
    last_error: Optional[str] = None


class LiveMonitor:
    def __init__(self, worker_target: Callable = capture_worker.run, use_threads: bool = False):
        self._worker_target = worker_target
        self._use_threads = use_threads
        self._lock = threading.Lock()
        self._worker = None
        self._queue = None
        self._stop_event = None
        self._consumer: Optional[threading.Thread] = None
        self._consumer_stop = threading.Event()
        self.status = LiveStatus(running=False)
        self._detector: Optional[Dict[str, Any]] = None
        self._max_flows = 100_000
        self._capacity: Optional[float] = None

    # ------------------------------------------------------------ control
    def start(self, principal: Principal, interface: str, *, mode: str = "counters",
              interval_seconds: Optional[int] = None, capacity_bps: Optional[float] = None,
              live_detection: bool = True) -> int:
        require_permission(principal, Permission.CONTROL_MONITORING, action="monitoring.start",
                           details={"interface": interface, "mode": mode})
        settings = settings_service.get_monitoring_settings()
        if mode not in MODES:
            raise MonitorError("Unknown monitoring mode.")
        if interface not in settings.allowed_interfaces:
            raise MonitorError(f"Interface {interface} is not authorised for monitoring. An administrator can "
                               "authorise it in Settings → Monitoring.")
        capability = capture_capability()
        if not capability.counters or (mode == "packets" and not capability.packets):
            raise MonitorError(" ".join(capability.reasons) or "Monitoring is not supported here.")
        interval = int(interval_seconds or settings.default_interval_seconds)
        if not 1 <= interval <= 60:
            raise MonitorError("Sampling interval must be between 1 and 60 seconds.")
        if capacity_bps is not None and capacity_bps <= 0:
            raise MonitorError("Configured capacity must be positive.")
        with self._lock:
            if self.status.running:
                raise MonitorError("A capture is already running. Stop it before starting another.")
            detection = self._prepare_detection(principal) if (mode == "packets" and live_detection) else \
                {"enabled": False, "reason": "Live detection needs packet capture." if mode != "packets"
                 else "Live detection was not requested."}
            configuration = {"interface": interface, "mode": mode, "interval_seconds": interval,
                             "capacity_bps": capacity_bps, "capacity_provenance": "configured" if capacity_bps else "unavailable",
                             "latency_target": settings.latency_target or None,
                             "latency": "measured by TCP connect to the configured target" if settings.latency_target
                             else "unavailable (no latency target configured)",
                             "detection": {k: v for k, v in detection.items() if k not in ("classifier", "anomaly")},
                             "flow_idle_timeout_s": IDLE_TIMEOUT_S, "flow_active_timeout_s": ACTIVE_TIMEOUT_S}
            with database_service.session(write=True) as conn:
                session_id = monitoring_service.create_session(
                    conn, user_id=principal.user_id, source_type=SourceType.LIVE_CAPTURE, interface_name=interface,
                    configuration=configuration)
                audit_service.record(conn, user_id=principal.user_id, action="monitoring.start",
                                     details={"session_id": session_id, "interface": interface, "mode": mode})
            self._detector = detection
            self._max_flows = settings.max_flows_per_session
            self._capacity = capacity_bps
            self.status = LiveStatus(running=True, session_id=session_id, state="STARTING", interface=interface,
                                     mode=mode, started_at=utc_now_iso(),
                                     detection={k: v for k, v in detection.items() if k not in ("classifier", "anomaly")})
            worker_config = {"interface": interface, "mode": mode, "interval_seconds": interval,
                             "capacity_bps": capacity_bps, "latency_target": settings.latency_target or None}
            if self._use_threads:
                self._queue = queue_module.Queue(maxsize=QUEUE_MAX)
                self._stop_event = threading.Event()
                self._worker = threading.Thread(target=self._worker_target,
                                                args=(worker_config, self._queue, self._stop_event), daemon=True)
            else:
                context = multiprocessing.get_context("spawn")
                self._queue = context.Queue(maxsize=QUEUE_MAX)
                self._stop_event = context.Event()
                self._worker = context.Process(target=self._worker_target,
                                               args=(worker_config, self._queue, self._stop_event), daemon=True,
                                               name=f"smart-shield-capture-{session_id}")
            if self._use_threads:
                self._worker.start()
            else:
                start_without_main_reimport(self._worker)
            self._consumer_stop = threading.Event()
            self._consumer = threading.Thread(target=self._consume, name="smart-shield-capture-consumer", daemon=True)
            self._consumer.start()
            return session_id

    def stop(self, principal: Optional[Principal], reason: str = "Stopped by user") -> None:
        if principal is not None:
            require_permission(principal, Permission.CONTROL_MONITORING, action="monitoring.stop")
        with self._lock:
            if not self.status.running:
                raise MonitorError("No capture is running.")
            session_id = self.status.session_id
            self._set_state(SessionState.STOPPING, None)
            self._stop_event.set()
        self._join_worker()
        self._consumer_stop.set()
        if self._consumer is not None:
            self._consumer.join(timeout=JOIN_TIMEOUT_SECONDS + FLUSH_SECONDS + 2)
        with self._lock:
            if self.status.state not in ("ERROR", "STOPPED"):
                self._set_state(SessionState.STOPPED, f"{reason}. {self.status.samples} samples, "
                                                      f"{self.status.flows_stored} flows stored.")
            self.status.running = False
        if principal is not None:
            audit_service.record_standalone(user_id=principal.user_id, action="monitoring.stop", outcome="success",
                                            details={"session_id": session_id, "samples": self.status.samples,
                                                     "flows_stored": self.status.flows_stored})

    def _join_worker(self) -> None:
        worker = self._worker
        if worker is None:
            return
        worker.join(timeout=JOIN_TIMEOUT_SECONDS)
        if not self._use_threads and worker.is_alive():
            worker.terminate()
            worker.join(timeout=2)

    # ----------------------------------------------------------- detection
    def _prepare_detection(self, principal: Principal) -> Dict[str, Any]:
        record = model_registry_service.active_model(principal, "intrusion_classifier")
        if record is None:
            return {"enabled": False, "reason": "No active intrusion classifier."}
        needed = record.training_metadata.get("feature_names", [])
        missing = [f for f in needed if f not in LIVE_FLOW_FEATURES]
        if missing:
            return {"enabled": False, "model_version": record.version, "compatible": False, "missing": missing,
                    "reason": f"Active model {record.version} is REJECTED for live use: it needs {len(missing)} "
                              "feature(s) that live capture cannot compute (e.g. " + ", ".join(missing[:5]) +
                              "). Train a 'live-compatible' model in the ML Laboratory. Features are never zero-filled."}
        try:
            classifier = model_registry_service.load_bundle(record)
        except model_registry_service.ModelRegistryError as exc:
            return {"enabled": False, "reason": str(exc)}
        detection = {"enabled": True, "compatible": True, "model_id": record.id, "model_version": record.version,
                     "reason": f"Scoring finished flows with {record.name} {record.version}.", "classifier": classifier}
        anomaly = model_registry_service.active_model(principal, "anomaly_detector")
        if anomaly is not None and all(f in LIVE_FLOW_FEATURES for f in anomaly.training_metadata.get("feature_names", [])):
            try:
                detection["anomaly"] = model_registry_service.load_bundle(anomaly)
                detection["anomaly_model"] = {"id": anomaly.id, "version": anomaly.version}
            except model_registry_service.ModelRegistryError:
                pass
        return detection

    def _score(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detector = self._detector or {}
        if not detector.get("enabled") or not flows:
            return [{} for _ in flows]
        classifier = detector["classifier"]
        frame = pd.DataFrame([f["features"] for f in flows], columns=list(LIVE_FLOW_FEATURES)).astype(float)
        features = frame[classifier["feature_names"]].replace([np.inf, -np.inf], np.nan)
        scores = classifier["model"].predict_proba(features)[:, 1]
        flagged = scores >= classifier["score_threshold"]
        categories = np.array([""] * len(flows), dtype=object)
        if flagged.any():
            attack_model = classifier.get("attack_type_model")
            if attack_model is not None:
                predicted = attack_model.predict(features[flagged])
                categories[flagged] = np.where(predicted == "BENIGN", "Attack (unclassified)", predicted)
            else:
                categories[flagged] = "Attack (unclassified)"
        anomaly_scores = None
        if "anomaly" in detector:
            bundle = detector["anomaly"]
            anomaly_scores = bundle["model"].score_samples(frame[bundle["feature_names"]])
            only = (anomaly_scores < bundle["threshold"]) & ~flagged
            categories[only] = "Anomalous flows"
        out = []
        for i in range(len(flows)):
            out.append({"score": float(scores[i]), "category": categories[i] or None,
                        "anomaly_score": None if anomaly_scores is None else float(anomaly_scores[i])})
        return out

    # -------------------------------------------------------------- consume
    def _consume(self) -> None:
        metrics: List[Dict[str, Any]] = []
        flows: List[Dict[str, Any]] = []
        last_flush = time.monotonic()
        worker_done = False
        while True:
            try:
                message = self._queue.get(timeout=0.5)
            except queue_module.Empty:
                message = None
            except (EOFError, OSError):
                message = None
                worker_done = True
            if message is not None:
                kind = message.get("type")
                if kind == "started":
                    with self._lock:
                        self._set_state(SessionState.RUNNING, f"Capturing on {self.status.interface} "
                                                              f"({self.status.mode}).")
                elif kind == "metrics":
                    metrics.append(message)
                    self.status.dropped_messages = message.get("dropped_messages", 0)
                    self.status.active_flows = message.get("active_flows")
                elif kind == "flows":
                    flows.extend(message["flows"])
                elif kind == "error":
                    self.status.last_error = message["message"]
                    with self._lock:
                        self._set_state(SessionState.ERROR, message["message"][:500])
                    worker_done = True
                elif kind == "stopped":
                    self.status.dropped_messages = message.get("dropped_messages", 0)
                    worker_done = True
            due = time.monotonic() - last_flush >= FLUSH_SECONDS
            if (due or worker_done or self._consumer_stop.is_set()) and (metrics or flows):
                self._flush(metrics, flows)
                metrics, flows = [], []
                last_flush = time.monotonic()
            if worker_done or (self._consumer_stop.is_set() and self._queue_empty()):
                break
            if not self._worker_alive() and self._queue_empty() and self.status.state in ("STARTING", "RUNNING"):
                with self._lock:
                    self._set_state(SessionState.ERROR, "The capture worker exited unexpectedly.")
                break
        if metrics or flows:
            self._flush(metrics, flows)
        with self._lock:
            if self.status.state == "ERROR":
                self.status.running = False

    def _queue_empty(self) -> bool:
        try:
            return self._queue.empty()
        except (OSError, ValueError):
            return True

    def _worker_alive(self) -> bool:
        return self._worker is not None and self._worker.is_alive()

    def _flush(self, metrics: List[Dict[str, Any]], flows: List[Dict[str, Any]]) -> None:
        session_id = self.status.session_id
        rows = []
        for m in metrics:
            s = m["sample"]
            measured = [s["incoming_bytes_per_second"], s["outgoing_bytes_per_second"]]
            rows.append((
                session_id, m["at"], "live capture", self.status.interface,
                s["incoming_bytes_per_second"], s["outgoing_bytes_per_second"],
                s["incoming_packets_per_second"], s["outgoing_packets_per_second"],
                s["throughput_bps"], s.get("latency_ms"), None, s["utilization_ratio"], s["configured_capacity_bps"],
                "psutil_counters", "measured", "valid" if all(v is not None for v in measured) else "partial",
                "derived" if s["throughput_bps"] is not None else "unavailable",
                "derived" if s["utilization_ratio"] is not None else "unavailable",
                "configured" if s["configured_capacity_bps"] else "unavailable",
            ))
        room = max(0, self._max_flows - self.status.flows_stored)
        stored, skipped = flows[:room], flows[room:]
        verdicts = self._score(stored)
        flow_rows = []
        for flow, verdict in zip(stored, verdicts):
            features = {k: (None if v is None else round(float(v), 6)) for k, v in flow["features"].items()}
            flow_rows.append((
                session_id, capture_worker._iso(flow["start"]), flow["src_ip"], flow["dst_ip"], flow["src_port"],
                flow["dst_port"], flow["protocol"], flow["packet_count"], flow["byte_count"], flow["duration_s"],
                verdict.get("category"), verdict.get("anomaly_score"),
                self._detector.get("model_id") if verdict else None,
                self._detector.get("model_version") if verdict else None,
                json.dumps({"features": features, "end_reason": flow["end_reason"],
                            "model_score_uncalibrated": verdict.get("score")}),
                "measured",
            ))
        with database_service.session(write=True) as conn:
            if rows:
                telemetry_repository.insert_many(conn, rows)
            if flow_rows:
                conn.executemany(
                    "INSERT INTO network_flows (session_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, "
                    "packet_count, byte_count, duration, intrusion_prediction, anomaly_score, model_id, model_version, "
                    "feature_summary_json, provenance) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    flow_rows)
            self._raise_alerts(conn, stored, verdicts)
        self.status.samples += len(rows)
        self.status.flows_stored += len(stored)
        self.status.flows_not_stored += len(skipped)
        self.status.flows_scored += sum(1 for v in verdicts if v)
        self.status.flagged += sum(1 for v in verdicts if v.get("category"))

    def _raise_alerts(self, conn, flows: List[Dict[str, Any]], verdicts: List[Dict[str, Any]]) -> None:
        groups: Dict[str, List[int]] = {}
        for i, verdict in enumerate(verdicts):
            if verdict.get("category"):
                groups.setdefault(verdict["category"], []).append(i)
        for category, indexes in groups.items():
            members = [flows[i] for i in indexes]
            is_anomaly = category == "Anomalous flows"
            sources: Dict[str, int] = {}
            targets: Dict[str, int] = {}
            for f in members:
                sources[f["src_ip"]] = sources.get(f["src_ip"], 0) + 1
                targets[f"{f['dst_ip']}:{f['dst_port']}"] = targets.get(f"{f['dst_ip']}:{f['dst_port']}", 0) + 1
            evidence = {
                "flows": len(members), "interface": self.status.interface, "live_session_id": self.status.session_id,
                "time_window_utc": [capture_worker._iso(min(f["start"] for f in members)),
                                    capture_worker._iso(max(f["end"] for f in members))],
                "top_sources": [{"value": k, "flows": v} for k, v in sorted(sources.items(), key=lambda kv: -kv[1])[:5]],
                "top_destinations": [{"value": k, "flows": v} for k, v in sorted(targets.items(), key=lambda kv: -kv[1])[:5]],
                "model_score_uncalibrated": {
                    "min": min(verdicts[i]["score"] for i in indexes), "max": max(verdicts[i]["score"] for i in indexes),
                    "median": float(np.median([verdicts[i]["score"] for i in indexes]))},
                "source": "live capture",
            }
            model = self._detector.get("anomaly_model") if is_anomaly else \
                {"id": self._detector.get("model_id"), "version": self._detector.get("model_version")}
            alert_service.create_alert(
                conn, alert_type="anomaly" if is_anomaly else "security",
                severity="medium" if is_anomaly or len(members) < 50 else "high", category=category,
                reason=(f"Live capture on {self.status.interface}: the {'anomaly detector' if is_anomaly else 'intrusion classifier'} "
                        f"flagged {len(members)} flow(s) as '{category}'."),
                evidence=evidence, dedup_key=f"live:{self.status.interface}:{category}",
                session_id=self.status.session_id, model_id=(model or {}).get("id"),
                model_version=(model or {}).get("version"), cooldown_minutes=LIVE_ALERT_COOLDOWN_MINUTES,
            )

    # ---------------------------------------------------------------- state
    def _set_state(self, state: SessionState, message: Optional[str]) -> None:
        """Persist a state change. Caller holds the lock."""
        session_id = self.status.session_id
        if session_id is None:
            return
        try:
            with database_service.session(write=True) as conn:
                row = monitoring_repository.get(conn, session_id)
                if row is not None and SessionState(row["status"]) != state:
                    monitoring_service.transition(conn, session_id, state, message)
        except monitoring_service.InvalidTransition:
            return
        self.status.state = state.value


_SPAWN_LOCK = threading.Lock()


def start_without_main_reimport(process) -> None:
    """Start a spawn-context process without re-running the parent's __main__ in the child.

    With the "spawn" start method (default on macOS and Windows), the child re-imports the
    parent's main script. Under Streamlit that script is app.py, so the worker would re-run
    the whole app, including startup recovery that closes live sessions. Hiding __main__ for
    the instant of start() makes the child import only the worker's own module.
    """
    with _SPAWN_LOCK:
        original = sys.modules.get("__main__")
        sys.modules["__main__"] = types.ModuleType("__main__")
        try:
            process.start()
        finally:
            if original is not None:
                sys.modules["__main__"] = original


_MONITOR: Optional[LiveMonitor] = None
_MONITOR_LOCK = threading.Lock()


def get_monitor() -> LiveMonitor:
    """The process-wide monitor. Creating it closes sessions orphaned by a previous run."""
    global _MONITOR
    with _MONITOR_LOCK:
        if _MONITOR is None:
            monitoring_service.recover_interrupted_sessions()
            _MONITOR = LiveMonitor()
        return _MONITOR


def reset_monitor_for_tests(monitor: Optional[LiveMonitor] = None) -> None:
    global _MONITOR
    _MONITOR = monitor
