"""Simulation mode: synthetic network traffic created in memory, sent through the real detection pipeline.

No packet ever exists on a network. Nothing here opens a socket; the generator only builds Python tuples.

What is synthetic and what is real
* SYNTHETIC: the hosts (documentation address ranges 198.51.100.0/24 and 203.0.113.0/24, plus 10.20.0.0/16), the offered
  traffic, the scenario. Bandwidth figures are calculated by this model of a link, so they are stored as `derived`
  under a `simulation` session and shown with a SIMULATION label. They are never measurements.
* REAL: flows are built from the packet records by the real FlowTable, features are computed by the same code as live
  capture, and verdicts come from the registered, hash-verified Random Forest and Isolation Forest. No verdict is
  scripted: if a model does not flag a scenario's traffic, nothing is flagged.

How the link is modelled (deterministic for a given seed)
* Each traffic source offers a rate. If total offered traffic exceeds the configured capacity, every source is cut by
  the same share (tail drop on a full queue), so an attack really does squeeze legitimate traffic. The dropped share is
  reported as the packet-loss ratio of this model. Latency is not modelled, so it stays unavailable.
* Mitigations act where a controller on this side of the link can act. Outbound traffic is limited before it enters
  the link, which frees capacity. Inbound traffic has already crossed the link when it reaches the controller: a limit
  stops it reaching the internal host, but it still fills the link. So a flood from outside can be contained locally,
  yet legitimate traffic only recovers once it is filtered upstream, and the recovery check says so.
* Sending every packet of a 100 Mbit/s link through Python would be too slow, so each source contributes its exact byte
  and packet totals to the per-host meter, plus a few REPRESENTATIVE flows per second to the flow extractor and models.
  Stored flows are therefore a sample, which the session configuration and the UI say.
"""
from __future__ import annotations

import json
import random
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pandas as pd

from repositories import telemetry_repository
from repositories.incident_repository import SIMULATION_SOURCE_NAME
from services import (
    alert_service, audit_service, database_service, incident_correlation_service, intrusion_inference_service,
    mitigation_service, model_registry_service, monitoring_service,
)
from services.authorization import Permission, Principal, require_permission
from services.flow_extractor import FlowTable
from services.host_telemetry import HostMeter, connections_by_host
from services.intrusion_features import LIVE_FLOW_FEATURES
from services.mitigation_service import LinkPolicy, SenderDemand
from services.model_registry_service import ModelRecord
from services.monitoring_service import SessionState, SourceType

TICK_SECONDS = 1.0
ALERT_WINDOW_SECONDS = 10
DEFAULT_ATTACK_DELAY_SECONDS = 15
MAX_DURATION_SECONDS = 1800
SIMULATED_INTERFACE = "simulated-link"
FLOW_ACTIVE_TIMEOUT_SECONDS = 10.0  # shorter than live capture's 120 s, so long flows reach the models during a demo
METHOD = "simulation: rates calculated by the link model from synthetic traffic, not measured"
SAMPLE_NOTE = "Stored flows are a representative sample of the simulated traffic; bandwidth totals include all of it."


class SimulationError(Exception):
    pass


# ------------------------------------------------------------------ traffic model (pure)

@dataclass(frozen=True)
class FlowShape:
    """How one representative flow looks at packet level."""
    forward_packets: int
    backward_packets: int
    forward_size: int
    backward_size: int
    gap_seconds: float


WEB = FlowShape(8, 12, 300, 1200, 0.05)
VIDEO = FlowShape(10, 30, 200, 1100, 0.02)
FILE = FlowShape(12, 16, 200, 1000, 0.05)
APP = FlowShape(10, 10, 400, 800, 0.03)
FLOOD = FlowShape(4, 2, 70, 70, 0.008)  # short bursts of small packets
SCAN = FlowShape(1, 1, 0, 0, 0.0005)  # one probe per port, usually one reply
HOG = FlowShape(400, 20, 1400, 60, 0.002)  # sustained one-way bulk transfer


@dataclass(frozen=True)
class TrafficSource:
    name: str
    traffic_class: str  # critical, video, normal, file, or attack
    client: str
    server: str
    port: int
    protocol: int
    offered_bps: float
    inbound: bool  # the volume travels server → client (a download) when True, client → server when False
    shape: FlowShape
    flows_per_second: float
    legitimate: bool = True
    random_port: bool = False

    @property
    def sender(self) -> str:
        return self.server if self.inbound else self.client

    @property
    def receiver(self) -> str:
        return self.client if self.inbound else self.server


def baseline_sources(capacity_bps: float) -> List[TrafficSource]:
    """Ordinary office traffic: about 40 % of the link, so a healthy network has headroom."""
    share = capacity_bps * 0.40
    return [
        TrafficSource("Critical application", "critical", "10.20.1.15", "198.51.100.50", 8443, 6, share * 0.20, True, APP, 1),
        TrafficSource("Video conference", "video", "10.20.1.11", "198.51.100.20", 3478, 17, share * 0.30, True, VIDEO, 1),
        TrafficSource("Web browsing A", "normal", "10.20.1.12", "198.51.100.30", 443, 6, share * 0.15, True, WEB, 2),
        TrafficSource("Web browsing B", "normal", "10.20.1.13", "198.51.100.31", 443, 6, share * 0.10, True, WEB, 2),
        TrafficSource("File transfer", "file", "10.20.1.14", "198.51.100.40", 445, 6, share * 0.25, True, FILE, 1),
    ]


def attack_sources(scenario: str, capacity_bps: float) -> List[TrafficSource]:
    if scenario == "ddos":
        return [TrafficSource(f"Flood source {i}", "attack", "10.20.0.10", f"203.0.113.{i}", 80, 6,
                              capacity_bps * 0.90 / 30, True, FLOOD, 1, legitimate=False) for i in range(1, 31)]
    if scenario == "port_scan":
        return [TrafficSource("Port scanner", "attack", "10.20.0.10", "198.51.100.66", 0, 6, capacity_bps * 0.005, True,
                              SCAN, 40, legitimate=False, random_port=True)]
    if scenario == "bandwidth_hog":
        return [TrafficSource("Bandwidth hog", "attack", "10.20.1.99", "203.0.113.200", 443, 6, capacity_bps * 0.75, False,
                              HOG, 1, legitimate=False)]
    if scenario == "normal":
        return []
    raise SimulationError("Unknown scenario.")


SCENARIOS = {
    "ddos": ("DDoS-like flood", "30 outside sources flood one internal server with about 90 % of the link."),
    "port_scan": ("Port scan", "One outside host probes many ports of an internal server. Very little bandwidth."),
    "bandwidth_hog": ("Bandwidth hog", "One internal host pushes a sustained upload using about 75 % of the link."),
    "normal": ("Normal traffic only", "No attack. Use it to check how often the models flag ordinary traffic."),
}


def delivered_share(offered: Sequence[float], capacity_bps: float) -> float:
    """Fraction of offered traffic the link carries: 1, or an equal cut when offered exceeds capacity (pure)."""
    total = sum(offered)
    return 1.0 if total <= capacity_bps or total <= 0 else capacity_bps / total


def allowed_rates(sources: Sequence[TrafficSource], policy: Optional[LinkPolicy]) -> List[float]:
    """What the controller lets through for each source, before the link is considered (pure)."""
    if policy is None:
        return [s.offered_bps for s in sources]
    towards: Dict[str, float] = defaultdict(float)
    for s in sources:
        towards[s.receiver] += s.offered_bps
    allowed = []
    for s in sources:
        rate = s.offered_bps
        if s.sender in policy.blocked or s.sender in policy.isolated or s.receiver in policy.isolated:
            rate = 0.0
        if s.sender in policy.source_limits:
            rate = min(rate, policy.source_limits[s.sender])
        if s.receiver in policy.destination_limits:
            rate = min(rate, policy.destination_limits[s.receiver] * s.offered_bps / towards[s.receiver])
        if not s.inbound and s.sender in policy.sender_caps:
            rate = min(rate, policy.sender_caps[s.sender])
        allowed.append(rate)
    return allowed


def link_model(sources: Sequence[TrafficSource], capacity_bps: float, policy: Optional[LinkPolicy] = None) -> Dict[str, Any]:
    """Per-source rates on the link and after the controller (pure). See the module docstring for the reasoning."""
    allowed = allowed_rates(sources, policy)
    entering = [s.offered_bps if s.inbound else rate for s, rate in zip(sources, allowed)]
    share = delivered_share(entering, capacity_bps)
    on_link = [rate * share for rate in entering]
    delivered = [min(carried, rate) if s.inbound else carried for s, carried, rate in zip(sources, on_link, allowed)]
    return {"allowed": allowed, "on_link": on_link, "delivered": delivered, "share": share}


def link_rates(sources: Sequence[TrafficSource], on_link: Sequence[float]) -> Dict[str, float]:
    """Link totals from the internal network's point of view (pure)."""
    incoming = sum(rate for s, rate in zip(sources, on_link) if s.inbound)
    outgoing = sum(rate for s, rate in zip(sources, on_link) if not s.inbound)
    return {"incoming_bps": incoming, "outgoing_bps": outgoing, "throughput_bps": incoming + outgoing}


def flow_packets(source: TrafficSource, start: float, client_port: int, server_port: int) -> List[tuple]:
    """Packet records (the same 8 fields as a captured packet) for one representative flow (pure)."""
    shape, packets, t = source.shape, [], start
    for i in range(max(shape.forward_packets, shape.backward_packets)):
        if i < shape.forward_packets:
            packets.append((t, source.client, source.server, client_port, server_port, source.protocol,
                            shape.forward_size, 0x10))
            t += shape.gap_seconds
        if i < shape.backward_packets:
            packets.append((t, source.server, source.client, server_port, client_port, source.protocol,
                            shape.backward_size, 0x10))
            t += shape.gap_seconds
    if source.protocol == 6:  # TCP closes with FIN, which ends the flow
        packets.append((t, source.client, source.server, client_port, server_port, source.protocol, 0, 0x01))
    return packets


def attacker_flow_packets(source: TrafficSource, start: float, client_port: int, server_port: int) -> List[tuple]:
    """An attack flow is opened by the outside host when the volume is inbound, so its 'forward' side is the attacker."""
    if source.legitimate or not source.inbound:
        return flow_packets(source, start, client_port, server_port)
    mirrored = replace(source, client=source.server, server=source.client)
    return flow_packets(mirrored, start, client_port, server_port)


class TrafficGenerator:
    """One simulated second at a time: exact totals for the meter, representative flows for the models."""

    def __init__(self, scenario: str, capacity_bps: float, *, attack_delay_seconds: float = DEFAULT_ATTACK_DELAY_SECONDS,
                 seed: int = 7):
        if capacity_bps <= 0:
            raise SimulationError("Link capacity must be positive.")
        self.scenario = scenario
        self.capacity_bps = float(capacity_bps)
        self.attack_delay = float(attack_delay_seconds)
        self.baseline = baseline_sources(self.capacity_bps)
        self.attack = attack_sources(scenario, self.capacity_bps)
        self.rng = random.Random(seed)
        self.elapsed = 0.0

    def active_sources(self) -> List[TrafficSource]:
        return self.baseline + (self.attack if self.elapsed >= self.attack_delay else [])

    @property
    def attack_active(self) -> bool:
        return bool(self.attack) and self.elapsed >= self.attack_delay

    def tick(self, now: float, seconds: float = TICK_SECONDS, policy: Optional[LinkPolicy] = None) -> Dict[str, Any]:
        sources = self.active_sources()
        model = link_model(sources, self.capacity_bps, policy)
        packets: List[tuple] = []
        for source, allowed in zip(sources, model["allowed"]):
            # A limited source gets fewer flows past the controller; the models only see what passes it.
            count = source.flows_per_second * seconds * (allowed / source.offered_bps if source.offered_bps else 0.0)
            for _ in range(int(count) + (self.rng.random() < count - int(count))):
                start = now + self.rng.uniform(0, max(seconds * 0.5, 0.001))
                port = self.rng.randint(1, 1024) if source.random_port else source.port
                packets.extend(attacker_flow_packets(source, start, self.rng.randint(30000, 60000), port))
        self.elapsed += seconds
        packets.sort(key=lambda p: p[0])
        return {"sources": sources, "share": model["share"], "delivered": model["delivered"],
                "offered_bps": sum(s.offered_bps for s in sources), "packets": packets,
                **link_rates(sources, model["on_link"])}


def meter_totals(meter: HostMeter, sources: Sequence[TrafficSource], delivered: Sequence[float], seconds: float) -> None:
    """Add each source's delivered bytes and packets to the meter, without enumerating the packets."""
    for s, rate in zip(sources, delivered):
        delivered_bytes = rate * seconds / 8
        size = max(s.shape.forward_size, s.shape.backward_size) + 40  # plus IP and TCP/UDP headers
        if delivered_bytes > 0:
            meter.add_bulk(s.sender, s.receiver, int(delivered_bytes), int(delivered_bytes / size))


# ------------------------------------------------------------------ engine

@dataclass
class SimulationStatus:
    running: bool = False
    finished: bool = False
    session_id: Optional[int] = None
    scenario: Optional[str] = None
    scenario_title: Optional[str] = None
    capacity_bps: Optional[float] = None
    attack_delay_seconds: float = DEFAULT_ATTACK_DELAY_SECONDS
    attack_active: bool = False
    elapsed_seconds: float = 0.0
    duration_seconds: float = 0.0
    model_version: Optional[str] = None
    model_active: bool = False
    flows_scored: int = 0
    flagged: int = 0
    by_category: Dict[str, int] = field(default_factory=dict)
    alerts: List[int] = field(default_factory=list)
    incidents: List[int] = field(default_factory=list)
    offered_bps: Optional[float] = None
    throughput_bps: Optional[float] = None
    loss_ratio: Optional[float] = None
    flows_per_second: Optional[float] = None
    last_error: Optional[str] = None


def live_compatible_model(principal: Principal) -> Tuple[Optional[ModelRecord], Optional[ModelRecord]]:
    """The classifier to use: the active one if every feature is computable from packets, else the newest that is.

    Simulated flows carry only features a flow extractor can compute, and features are never zero-filled. Returns
    (classifier, anomaly detector of the same version if there is one).
    """
    def usable(record: ModelRecord) -> bool:
        return all(f in LIVE_FLOW_FEATURES for f in record.training_metadata.get("feature_names", ["?"]))

    classifiers = sorted(model_registry_service.list_models(principal, "intrusion_classifier"),
                         key=lambda m: (m.is_active, m.trained_at), reverse=True)
    classifier = next((m for m in classifiers if usable(m)), None)
    if classifier is None:
        return None, None
    detector = next((m for m in model_registry_service.list_models(principal, "anomaly_detector")
                     if m.version == classifier.version and usable(m)), None)
    return classifier, detector


class SimulationEngine:
    def __init__(self, tick_seconds: float = TICK_SECONDS):
        self._tick = tick_seconds
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.status = SimulationStatus()
        self._principal: Optional[Principal] = None
        self._generator: Optional[TrafficGenerator] = None
        self._table: Optional[FlowTable] = None
        self._meter: Optional[HostMeter] = None
        self._classifier: Optional[Dict[str, Any]] = None
        self._detector: Optional[Dict[str, Any]] = None
        self._models: Dict[str, Dict[str, Any]] = {}
        self._pending: Dict[Tuple[str, int], List[Dict[str, Any]]] = defaultdict(list)

    def start(self, principal: Principal, scenario: str, *, capacity_bps: float = 100e6,
              attack_delay_seconds: float = DEFAULT_ATTACK_DELAY_SECONDS, duration_seconds: float = 300, seed: int = 7) -> int:
        require_permission(principal, Permission.RUN_DETECTION, action="simulation.start", details={"scenario": scenario})
        if scenario not in SCENARIOS:
            raise SimulationError("Unknown scenario.")
        if not 1e6 <= float(capacity_bps) <= 10e9:
            raise SimulationError("Simulated link capacity must be between 1 Mbit/s and 10 Gbit/s.")
        if not 0 <= float(attack_delay_seconds) <= MAX_DURATION_SECONDS:
            raise SimulationError("The attack delay is out of range.")
        if not 10 <= float(duration_seconds) <= MAX_DURATION_SECONDS:
            raise SimulationError(f"A simulation runs for 10–{MAX_DURATION_SECONDS} seconds.")
        with self._lock:
            if self.status.running:
                raise SimulationError("A simulation is already running. Stop it first.")
            classifier_record, detector_record = live_compatible_model(principal)
            if classifier_record is None:
                raise SimulationError(
                    "No live-compatible intrusion model is registered. Simulated flows only carry features computable "
                    "from packets, and features are never zero-filled. In the ML Laboratory, train Smart Shield models "
                    "with the live-compatible feature set.")
            try:
                self._classifier = model_registry_service.load_bundle(classifier_record)
                self._detector = model_registry_service.load_bundle(detector_record) if detector_record else None
            except model_registry_service.ModelRegistryError as exc:
                raise SimulationError(str(exc)) from exc
            self._models = {"classifier": {"id": classifier_record.id, "version": classifier_record.version}}
            if detector_record is not None:
                self._models["anomaly"] = {"id": detector_record.id, "version": detector_record.version}
            title = SCENARIOS[scenario][0]
            configuration = {
                "purpose": "simulation", "mode": "packets", "scenario": scenario, "scenario_title": title, "seed": seed,
                "capacity_bps": float(capacity_bps), "capacity_provenance": "configured",
                "attack_delay_seconds": float(attack_delay_seconds), "duration_seconds": float(duration_seconds),
                "classifier": self._models["classifier"], "anomaly_detector": self._models.get("anomaly"),
                "note": "Synthetic traffic created in memory. No packets were sent. " + SAMPLE_NOTE,
            }
            with database_service.session(write=True) as conn:
                session_id = monitoring_service.create_session(
                    conn, user_id=principal.user_id, source_type=SourceType.SIMULATION, interface_name=SIMULATED_INTERFACE,
                    configuration=configuration)
                monitoring_service.transition(conn, session_id, SessionState.RUNNING, f"Simulating '{title}'.")
                audit_service.record(conn, user_id=principal.user_id, action="simulation.start",
                                     details={"session_id": session_id, "scenario": scenario, "capacity_bps": capacity_bps})
            self._principal = principal
            self._generator = TrafficGenerator(scenario, capacity_bps, attack_delay_seconds=attack_delay_seconds, seed=seed)
            self._table = FlowTable(active_timeout=FLOW_ACTIVE_TIMEOUT_SECONDS)
            self._meter = HostMeter()
            self._pending = defaultdict(list)
            self.status = SimulationStatus(
                running=True, session_id=session_id, scenario=scenario, scenario_title=title,
                capacity_bps=float(capacity_bps), attack_delay_seconds=float(attack_delay_seconds),
                duration_seconds=float(duration_seconds), model_version=classifier_record.version,
                model_active=classifier_record.is_active)
            self._stop = threading.Event()
            self._thread = threading.Thread(target=self._run, name="smart-shield-simulation", daemon=True)
            self._thread.start()
            return session_id

    def stop(self, principal: Optional[Principal], reason: str = "Stopped by user") -> None:
        if principal is not None:
            require_permission(principal, Permission.RUN_DETECTION, action="simulation.stop")
        with self._lock:
            if not self.status.running:
                raise SimulationError("No simulation is running.")
            session_id = self.status.session_id
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=30)
        with self._lock:
            if self.status.running:
                self._finish(SessionState.STOPPED, f"{reason} after {self.status.elapsed_seconds:.0f} s.")
        if principal is not None:
            audit_service.record_standalone(user_id=principal.user_id, action="simulation.stop", outcome="success",
                                            details={"session_id": session_id, "flagged": self.status.flagged})

    # ---------------------------------------------------------- the loop
    def _run(self) -> None:
        try:
            while not self._stop.wait(self._tick):
                if not self.step(time.time()):
                    break
        except Exception as exc:  # never leave a simulation RUNNING after a failure
            with self._lock:
                self.status.last_error = f"Simulation stopped after an error: {type(exc).__name__}: {exc}"
                if self.status.running:
                    self._finish(SessionState.ERROR, self.status.last_error[:500])

    def step(self, now: float, seconds: float = TICK_SECONDS) -> bool:
        """One simulated interval. Public so tests can drive it without the thread. False when finished."""
        with self._lock:
            if not self.status.running:
                return False
            if not self._session_still_running():
                self.status.running = False
                self.status.last_error = "This simulation's session was closed outside the engine."
                mitigation_service.end_session(self.status.session_id, "The simulation's session was closed.")
                return False
        moment = datetime.fromtimestamp(now, tz=timezone.utc)
        session_id, capacity = self.status.session_id, self.status.capacity_bps
        sources = self._generator.active_sources()
        plan = mitigation_service.plan_interval(session_id, capacity, [
            SenderDemand(s.sender, s.receiver, "critical" if s.traffic_class == "critical" else "normal", s.offered_bps)
            for s in sources], moment)
        tick = self._generator.tick(now, seconds, plan.policy)
        finished = []
        for packet in tick["packets"]:
            finished.extend(self._table.add(packet))
        finished.extend(self._table.expire(now + seconds))
        meter_totals(self._meter, tick["sources"], tick["delivered"], seconds)
        hosts = self._meter.sample(seconds, connections_by_host(self._table.active))
        verdicts = self._score(finished)
        created = self._store(now, seconds, tick, hosts, finished, verdicts)
        mitigation_service.record_interval(
            session_id, plan, hosts, {s.sender for s in sources if s.traffic_class == "critical"},
            datetime.fromtimestamp(now + seconds, tz=timezone.utc))
        with self._lock:
            status = self.status
            status.elapsed_seconds = self._generator.elapsed
            status.attack_active = self._generator.attack_active
            status.flows_scored += len(finished)
            status.flagged += sum(1 for v in verdicts if v["category"])
            for v in verdicts:
                if v["category"]:
                    status.by_category[v["category"]] = status.by_category.get(v["category"], 0) + 1
            status.alerts.extend(created)
            status.offered_bps = tick["offered_bps"]
            status.throughput_bps = tick["throughput_bps"]
            status.loss_ratio = 1 - tick["share"]
            status.flows_per_second = len(finished) / seconds
            done = status.elapsed_seconds >= status.duration_seconds
        if created:
            self._correlate()
        if done:
            created_last = self._flush_alerts(now + seconds)
            if created_last:
                self._correlate()
            with self._lock:
                if self.status.running:
                    self.status.alerts.extend(created_last)
                    self._finish(SessionState.STOPPED, f"Finished after {self.status.elapsed_seconds:.0f} s.")
                    self.status.finished = True
            return False
        return True

    def _session_still_running(self) -> bool:
        with database_service.session() as conn:
            row = conn.execute("SELECT status FROM monitoring_sessions WHERE id = ?", (self.status.session_id,)).fetchone()
        return row is not None and row["status"] == SessionState.RUNNING.value

    def _score(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not flows:
            return []
        frame = pd.DataFrame([f["features"] for f in flows], columns=list(LIVE_FLOW_FEATURES))
        verdicts = intrusion_inference_service.score_frame(frame, self._classifier, self._detector)
        return [{"score": float(verdicts.scores.iat[i]), "category": verdicts.category.iat[i] or None,
                 "anomaly_score": None if verdicts.anomaly_scores is None else float(verdicts.anomaly_scores.iat[i])}
                for i in range(len(flows))]

    def _store(self, now: float, seconds: float, tick: Dict[str, Any], hosts: List[Dict[str, Any]],
               flows: List[Dict[str, Any]], verdicts: List[Dict[str, Any]]) -> List[int]:
        session_id = self.status.session_id
        capacity = self.status.capacity_bps
        at = datetime.fromtimestamp(now, tz=timezone.utc).isoformat(timespec="microseconds")
        loss = 1 - tick["share"]
        metric = (session_id, at, SIMULATION_SOURCE_NAME, SIMULATED_INTERFACE, tick["incoming_bps"] / 8,
                  tick["outgoing_bps"] / 8, None, None, tick["throughput_bps"], None, loss,
                  min(1.0, tick["throughput_bps"] / capacity), capacity, METHOD, "derived", "valid", "derived", "derived",
                  "configured")
        host_rows = [(session_id, at, h["host"], h["sent_bps"], h["received_bps"], h["sent_pps"], h["received_pps"],
                      h["active_connections"], "derived") for h in hosts]
        flow_rows = []
        for flow, verdict in zip(flows, verdicts):
            model = self._models.get("anomaly") if verdict["category"] == "Anomalous flows" else self._models["classifier"]
            features = {k: (None if v is None else round(float(v), 6)) for k, v in flow["features"].items()}
            flow_rows.append((
                session_id, datetime.fromtimestamp(flow["start"], tz=timezone.utc).isoformat(timespec="microseconds"),
                flow["src_ip"], flow["dst_ip"], flow["src_port"], flow["dst_port"], flow["protocol"], flow["packet_count"],
                flow["byte_count"], flow["duration_s"], verdict["category"], verdict["anomaly_score"], model["id"],
                model["version"], json.dumps({"simulated": True, "features": features, "end_reason": flow["end_reason"],
                                              "model_score_uncalibrated": round(verdict["score"], 4)}), "derived"))
            if verdict["category"]:
                window = int(flow["start"] // ALERT_WINDOW_SECONDS) * ALERT_WINDOW_SECONDS
                self._pending[(verdict["category"], window)].append({**flow, **verdict})
        due = [k for k in self._pending if k[1] + ALERT_WINDOW_SECONDS <= now]
        created: List[int] = []
        with database_service.session(write=True) as conn:
            telemetry_repository.insert_many(conn, [metric])
            if host_rows:
                telemetry_repository.insert_host_metrics(conn, host_rows)
            if flow_rows:
                conn.executemany(
                    "INSERT INTO network_flows (session_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, "
                    "packet_count, byte_count, duration, intrusion_prediction, anomaly_score, model_id, model_version, "
                    "feature_summary_json, provenance) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", flow_rows)
            for key in sorted(due):
                alert_id = self._raise_alert(conn, key, self._pending.pop(key))
                if alert_id is not None:
                    created.append(alert_id)
        return created

    def _flush_alerts(self, now: float) -> List[int]:
        created: List[int] = []
        finished = self._table.flush()
        verdicts = self._score(finished)
        for flow, verdict in zip(finished, verdicts):
            if verdict["category"]:
                window = int(flow["start"] // ALERT_WINDOW_SECONDS) * ALERT_WINDOW_SECONDS
                self._pending[(verdict["category"], window)].append({**flow, **verdict})
        with database_service.session(write=True) as conn:
            for key in sorted(self._pending):
                alert_id = self._raise_alert(conn, key, self._pending[key])
                if alert_id is not None:
                    created.append(alert_id)
        self._pending.clear()
        return created

    def _raise_alert(self, conn, key: Tuple[str, int], members: List[Dict[str, Any]]) -> Optional[int]:
        category, window = key
        frame = pd.DataFrame({
            "source_ip": [m["src_ip"] for m in members], "destination_ip": [m["dst_ip"] for m in members],
            "destination_port": [m["dst_port"] for m in members]})
        timestamps = pd.Series(pd.to_datetime([m["start"] for m in members], unit="s", utc=True), index=frame.index)
        is_anomaly = category == "Anomalous flows"
        scores = pd.Series([-(m["anomaly_score"] or 0.0) if is_anomaly else m["score"] for m in members], index=frame.index)
        ddos = None if is_anomaly else intrusion_inference_service._potential_ddos(frame, timestamps)
        evidence = intrusion_inference_service._evidence(frame, scores, timestamps, len(frame), None)
        for key_name in ("share_of_scored_rows", "example_rows"):
            evidence.pop(key_name, None)
        evidence.update({"source": "simulation", "simulation_session_id": self.status.session_id,
                         "interface": SIMULATED_INTERFACE, "note": "Synthetic traffic. " + SAMPLE_NOTE})
        if ddos:
            evidence["potential_ddos"] = ddos
        alert_type = "anomaly" if is_anomaly else "security"
        model = self._models.get("anomaly") if is_anomaly else self._models["classifier"]
        reason = (f"Simulation: the {'anomaly detector' if is_anomaly else 'intrusion classifier'} flagged {len(members):,} "
                  f"sampled flow(s) as '{category}'.")
        if ddos:
            reason += (f" Potential DDoS: {ddos['distinct_sources']} distinct sources targeted {ddos['destination']} within "
                       f"{intrusion_inference_service.DDOS_WINDOW_SECONDS} s.")
        return alert_service.create_alert(
            conn, alert_type=alert_type,
            severity=intrusion_inference_service.severity_for(category, len(members), alert_type, bool(ddos)),
            category=category, reason=reason, evidence=evidence,
            dedup_key=f"simulation:{self.status.session_id}:{category}:{window}", session_id=self.status.session_id,
            model_id=(model or {}).get("id"), model_version=(model or {}).get("version"),
            created_by=self._principal.user_id if self._principal else None)

    def _correlate(self) -> None:
        try:
            run = incident_correlation_service.correlate(self._principal, origin="simulation")
        except Exception as exc:  # correlation problems must not stop the simulation
            with self._lock:
                self.status.last_error = f"Correlation failed: {exc}"
            return
        with self._lock:
            for incident_id in run.incidents_created + run.incidents_updated:
                if incident_id not in self.status.incidents:
                    self.status.incidents.append(incident_id)

    def _finish(self, state: SessionState, message: str) -> None:
        """Close the session. Caller holds the lock."""
        self.status.running = False
        try:
            mitigation_service.end_session(self.status.session_id, "The simulation ended.")
            with database_service.session(write=True) as conn:
                monitoring_service.transition(conn, self.status.session_id, SessionState.STOPPING)
                monitoring_service.transition(conn, self.status.session_id, state, message)
        except (monitoring_service.InvalidTransition, monitoring_service.SessionNotFound):
            pass


# ------------------------------------------------------------------ service API

def data_counts(principal: Principal) -> Dict[str, int]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="simulation.view")
    with database_service.session() as conn:
        return _counts(conn)


def _counts(conn) -> Dict[str, int]:
    one = lambda sql, *args: int(conn.execute(sql, args).fetchone()[0])  # noqa: E731
    sessions = "SELECT id FROM monitoring_sessions WHERE source_type = 'simulation'"
    return {
        "sessions": one(f"SELECT COUNT(*) FROM ({sessions})"),
        "flows": one(f"SELECT COUNT(*) FROM network_flows WHERE session_id IN ({sessions})"),
        "metrics": one(f"SELECT COUNT(*) FROM network_metrics WHERE session_id IN ({sessions})"),
        "host_samples": one(f"SELECT COUNT(*) FROM host_metrics WHERE session_id IN ({sessions})"),
        "alerts": one(f"SELECT COUNT(*) FROM alerts WHERE session_id IN ({sessions})"),
        "incidents": one("SELECT COUNT(*) FROM incidents WHERE is_simulation = 1"),
        "mitigations": mitigation_service.data_count(conn),
    }


def clear_simulation_data(principal: Principal) -> Dict[str, int]:
    """Delete every simulation session with its data. Admin only, audited. Real data is never touched."""
    require_permission(principal, Permission.DELETE_DATA, action="simulation.clear")
    engine = get_engine()
    if engine.status.running:
        engine.stop(None, "Stopped to clear simulation data")
    with database_service.session(write=True) as conn:
        counts = _counts(conn)
        mitigation_service.clear_simulation(conn)
        conn.execute("DELETE FROM incidents WHERE is_simulation = 1")
        conn.execute("DELETE FROM alerts WHERE session_id IN (SELECT id FROM monitoring_sessions "
                     "WHERE source_type = 'simulation')")
        conn.execute("DELETE FROM congestion_predictions WHERE source_name = ?", (SIMULATION_SOURCE_NAME,))
        # Flows, metrics and host samples go with their sessions (ON DELETE CASCADE).
        conn.execute("DELETE FROM monitoring_sessions WHERE source_type = 'simulation'")
        audit_service.record(conn, user_id=principal.user_id, action="simulation.clear", details=counts)
    with engine._lock:
        engine.status = SimulationStatus()
    return counts


_ENGINE: Optional[SimulationEngine] = None
_ENGINE_LOCK = threading.Lock()


def get_engine() -> SimulationEngine:
    """The process-wide engine. Creating it closes simulation sessions orphaned by a previous run."""
    global _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is None:
            monitoring_service.recover_interrupted_sessions(SourceType.SIMULATION.value)
            _ENGINE = SimulationEngine()
        return _ENGINE


def reset_engine_for_tests(engine: Optional[SimulationEngine] = None) -> None:
    global _ENGINE
    _ENGINE = engine


def status_copy() -> SimulationStatus:
    engine = get_engine()
    with engine._lock:
        return replace(engine.status, alerts=list(engine.status.alerts), incidents=list(engine.status.incidents),
                       by_category=dict(engine.status.by_category))


def elapsed_note(status: SimulationStatus) -> str:
    if status.session_id is None:
        return "Nothing is simulating."
    left = status.attack_delay_seconds - status.elapsed_seconds
    if not status.attack_delay_seconds or status.attack_active:
        return "Attack traffic active." if status.scenario != "normal" else "Normal traffic only."
    return f"Normal traffic; attack starts in {max(0, left):.0f} s." if status.scenario != "normal" else "Normal traffic only."
