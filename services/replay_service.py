"""Replay / demo mode: a labelled dataset played back through the real detection pipeline.

* What happens to each row is exactly what happens in dataset detection: the registered (hash-verified)
  classifier and anomaly detector score it via intrusion_inference_service.score_frame, flagged rows
  raise alerts, and alerts are correlated into incidents. Nothing is invented: every flow, alert and
  metric comes from a row of the dataset or from a model's output on it.
* Rows keep their own dataset timestamps. A replay clock walks through the dataset's time at 1×–30×
  wall-clock speed, so a 30-minute port scan plays in one minute at 30×. Timestamps are never
  rewritten to "now"; the UI shows a persistent DATASET REPLAY banner and badges instead.
* Replay data is stored under monitoring sessions with source_type 'replay'. Correlation only groups
  replay alerts with other replay alerts, and an administrator can clear all of it in one audited step.
* Alerts are raised once per category per ALERT_WINDOW_SECONDS of dataset time, when that window has
  fully played, so each alert summarises a complete window (like a 5-minute aggregation in a SOC tool).
* Throughput samples for PredictNet are DERIVED: bytes of the replayed flow records per
  METRIC_INTERVAL_SECONDS of dataset time (by flow start). Utilization exists only if the user configures
  a capacity for the replay; otherwise it is unavailable.
* One replay at a time, run by a background thread owned by a process-wide singleton (get_engine()),
  so Streamlit reruns never start a second one.
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

from repositories import dataset_repository, telemetry_repository
from repositories.incident_repository import REPLAY_SOURCE_NAME
from services import (
    alert_service, audit_service, congestion_prediction_service, database_service, incident_correlation_service,
    intrusion_inference_service, model_registry_service, monitoring_service,
)
from services.authorization import Permission, Principal, require_permission
from services.dataset_service import LABEL_COLUMN, PROTOCOL_NAMES
from services.intrusion_features import BENIGN_LABELS, clean_label, compatibility, header_columns, load_dataset_frame
from services.monitoring_service import SessionState, SourceType
from services.timeutil import utc_now_iso

SPEEDS = (1, 5, 10, 30)
TICK_SECONDS = 1.0
MAX_ROWS_PER_TICK = 2_000
MAX_REPLAY_ROWS = 200_000
ALERT_WINDOW_SECONDS = 300
METRIC_INTERVAL_SECONDS = 60
REPLAY_INTERFACE = "replay"
RATE_WINDOW_SECONDS = 10.0


class ReplayError(Exception):
    pass


# ------------------------------------------------------------------ pure helpers

@dataclass(frozen=True)
class Scenario:
    key: str
    title: str
    description: str
    labels: Optional[Tuple[str, ...]]  # None = every row of the dataset

    def matches(self, label: str) -> bool:
        return self.labels is None or label in self.labels


_SCAN = re.compile(r"portscan|port scan", re.I)
_DDOS = re.compile(r"\bddos\b", re.I)
_BRUTE = re.compile(r"patator|brute", re.I)


def scenarios_for(label_counts: Mapping[str, int]) -> List[Scenario]:
    """Scenarios a dataset can honestly play, from the labels it actually contains (pure).

    A scenario is only offered when the dataset has rows for it; "SSH brute force" is not offered for a
    dataset without SSH-Patator rows, for example.
    """
    counts = {clean_label(k): int(v) for k, v in label_counts.items() if int(v) > 0}
    benign = sorted(label for label in counts if label.upper() in BENIGN_LABELS)
    attacks = sorted((label for label in counts if label.upper() not in BENIGN_LABELS), key=lambda l: (-counts[l], l))
    out = [Scenario("all", "Whole capture in time order",
                    f"Every row as recorded: {sum(counts.values()):,} flows "
                    f"({', '.join(f'{l} {counts[l]:,}' for l in benign + attacks)}).", None)]
    scans = [l for l in attacks if _SCAN.search(l)]
    floods = [l for l in attacks if _DDOS.search(l)]
    if scans and floods:
        out.append(Scenario("scan_ddos", "Port scan → DDoS",
                            "Reconnaissance followed by a distributed flood, with benign background traffic.",
                            tuple(benign + scans + floods)))
    brute = [l for l in attacks if _BRUTE.search(l)]
    if brute:
        out.append(Scenario("brute_force", f"Brute force ({', '.join(brute)})",
                            "Repeated login attempts against a service, with benign background traffic.",
                            tuple(benign + brute)))
    for label in attacks:
        out.append(Scenario(f"label:{label}", f"{label} only", f"{counts[label]:,} {label} flows with benign "
                            "background traffic.", tuple(benign + [label])))
    if benign:
        out.append(Scenario("benign", "Benign busy day (congestion only)",
                            "Only benign rows: any alert here is a false positive, and any incident is about load, "
                            "not an attack.", tuple(benign)))
    return out


def advance(replay_time: float, wall_elapsed: float, speed: int) -> float:
    """Dataset seconds after `wall_elapsed` wall seconds at `speed`× (pure)."""
    if speed not in SPEEDS:
        raise ReplayError(f"Speed must be one of {', '.join(f'{s}×' for s in SPEEDS)}.")
    return replay_time + max(0.0, wall_elapsed) * speed


def rows_due(times: np.ndarray, cursor: int, replay_time: float, limit: int = MAX_ROWS_PER_TICK) -> int:
    """End index (exclusive) of the rows whose dataset time has been reached, at most `limit` rows (pure).

    `times` are seconds since the dataset start, sorted ascending.
    """
    end = int(np.searchsorted(times, replay_time, side="right"))
    return max(cursor, min(end, cursor + limit))


def window_start(seconds: float, width: int) -> int:
    """Start (in dataset seconds) of the fixed window that contains `seconds` (pure)."""
    return int(seconds // width) * width


def complete_windows(pending: Sequence[int], replay_time: float, width: int, *, finished: bool = False) -> List[int]:
    """Windows that have fully played (all of them once the replay has finished) (pure)."""
    return sorted(w for w in pending if finished or w + width <= replay_time)


def throughput_sample(byte_total: float, packet_total: float, width: int,
                      capacity_bps: Optional[float]) -> Dict[str, Any]:
    """One derived throughput sample from the bytes of the flows that started in a window (pure)."""
    throughput = 8.0 * byte_total / width
    utilization = None
    if capacity_bps:
        # Recorded flows cannot really exceed the link, so >100 % means the configured capacity is too low.
        utilization = min(1.0, throughput / capacity_bps)
    return {"throughput_bps": throughput, "packets_per_second": packet_total / width, "utilization_ratio": utilization}


# ------------------------------------------------------------------ engine

@dataclass
class ReplayStatus:
    running: bool = False
    paused: bool = False
    finished: bool = False
    session_id: Optional[int] = None
    dataset_id: Optional[int] = None
    dataset_name: Optional[str] = None
    scenario_key: Optional[str] = None
    scenario_title: Optional[str] = None
    speed: int = 10
    capacity_bps: Optional[float] = None
    dataset_start: Optional[str] = None
    dataset_end: Optional[str] = None
    replay_time: Optional[str] = None  # current position on the dataset's own clock
    progress: float = 0.0
    rows_total: int = 0
    rows_done: int = 0
    flagged: int = 0
    alerts: List[int] = field(default_factory=list)
    incidents: List[int] = field(default_factory=list)
    forecast_note: Optional[str] = None
    last_error: Optional[str] = None
    rows_per_second: Optional[float] = None  # wall-clock replay rate over the last few seconds
    synthetic: bool = False


class ReplayEngine:
    def __init__(self, tick_seconds: float = TICK_SECONDS):
        self._tick = tick_seconds
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.status = ReplayStatus()
        self._principal: Optional[Principal] = None
        self._frame: Optional[pd.DataFrame] = None
        self._times: Optional[np.ndarray] = None
        self._t0: Optional[pd.Timestamp] = None
        self._cursor = 0
        self._clock = 0.0
        self._classifier: Optional[Dict[str, Any]] = None
        self._detector: Optional[Dict[str, Any]] = None
        self._models: Dict[str, Any] = {}
        self._pending_alerts: Dict[Tuple[str, int], List[Any]] = {}
        self._pending_metrics: Dict[int, List[float]] = {}
        self._last_forecast_window: Optional[int] = None
        self._recent: List[Tuple[float, int]] = []

    # --------------------------------------------------------- control
    def start(self, principal: Principal, dataset_id: int, scenario_key: str, *, speed: int = 10,
              capacity_bps: Optional[float] = None) -> int:
        require_permission(principal, Permission.RUN_DETECTION, action="replay.start",
                           details={"dataset_id": dataset_id, "scenario": scenario_key})
        if speed not in SPEEDS:
            raise ReplayError(f"Speed must be one of {', '.join(f'{s}×' for s in SPEEDS)}.")
        if capacity_bps is not None and capacity_bps <= 0:
            raise ReplayError("Configured capacity must be positive.")
        with self._lock:
            if self.status.running:
                raise ReplayError("A replay is already running. Stop it before starting another.")
            prepared = self._prepare(principal, dataset_id, scenario_key)
            frame, scenario, dataset = prepared["frame"], prepared["scenario"], prepared["dataset"]
            configuration = {
                "purpose": "replay", "dataset_id": dataset_id, "dataset_name": dataset["name"],
                "scenario": scenario.key, "scenario_title": scenario.title, "speed": speed, "rows": int(len(frame)),
                "capacity_bps": capacity_bps, "capacity_provenance": "configured" if capacity_bps else "unavailable",
                "classifier": self._models["classifier"], "anomaly_detector": self._models.get("anomaly"),
                "alert_window_seconds": ALERT_WINDOW_SECONDS, "metric_interval_seconds": METRIC_INTERVAL_SECONDS,
                "note": "Recorded dataset rows replayed through the detection pipeline. Not live traffic.",
            }
            with database_service.session(write=True) as conn:
                session_id = monitoring_service.create_session(
                    conn, user_id=principal.user_id, source_type=SourceType.REPLAY, interface_name=REPLAY_INTERFACE,
                    configuration=configuration, dataset_id=dataset_id)
                monitoring_service.transition(conn, session_id, SessionState.RUNNING,
                                              f"Replaying '{scenario.title}' at {speed}×.")
                audit_service.record(conn, user_id=principal.user_id, action="replay.start",
                                     details={"session_id": session_id, "dataset_id": dataset_id,
                                              "scenario": scenario.key, "speed": speed, "rows": int(len(frame))})
            self._principal = principal
            self._frame = frame
            self._t0 = frame["_ts"].iloc[0]
            self._times = (frame["_ts"] - self._t0).dt.total_seconds().to_numpy()
            self._cursor, self._clock = 0, 0.0
            self._pending_alerts, self._pending_metrics = {}, {}
            self._last_forecast_window, self._recent = None, []
            self.status = ReplayStatus(
                running=True, session_id=session_id, dataset_id=dataset_id, dataset_name=dataset["name"],
                scenario_key=scenario.key, scenario_title=scenario.title, speed=speed, capacity_bps=capacity_bps,
                dataset_start=self._t0.isoformat(), dataset_end=frame["_ts"].iloc[-1].isoformat(),
                replay_time=self._t0.isoformat(), rows_total=int(len(frame)),
                synthetic="synthetic" in f"{dataset['name']} {dataset['original_filename']}".lower())
            self._stop = threading.Event()
            self._thread = threading.Thread(target=self._run, name="smart-shield-replay", daemon=True)
            self._thread.start()
            return session_id

    def _prepare(self, principal: Principal, dataset_id: int, scenario_key: str) -> Dict[str, Any]:
        with database_service.session() as conn:
            dataset = dataset_repository.get(conn, dataset_id)
        if dataset is None or dataset["kind"] != "intrusion_flows" or not dataset["stored_path"]:
            raise ReplayError("Choose a registered intrusion dataset.")
        path = Path(dataset["stored_path"])
        if not path.is_file():
            raise ReplayError("The dataset's stored file is missing.")
        labels = json.loads(dataset["label_distribution_json"]) if dataset["label_distribution_json"] else {}
        scenario = next((s for s in scenarios_for(labels) if s.key == scenario_key), None)
        if scenario is None:
            raise ReplayError("That scenario is not available for this dataset.")
        classifier_record = model_registry_service.active_model(principal, "intrusion_classifier")
        if classifier_record is None:
            raise ReplayError("There is no active intrusion classifier. Train one in the ML Laboratory and ask an "
                              "administrator to activate it.")
        anomaly_record = model_registry_service.active_model(principal, "anomaly_detector")
        try:
            classifier = model_registry_service.load_bundle(classifier_record)
            detector = model_registry_service.load_bundle(anomaly_record) if anomaly_record else None
        except model_registry_service.ModelRegistryError as exc:
            raise ReplayError(str(exc)) from exc
        columns = header_columns(path)
        compat = compatibility(columns, classifier["feature_names"])
        if not compat.compatible:
            raise ReplayError(f"The active classifier is REJECTED for this dataset: {compat.message} "
                              "Features are never zero-filled.")
        if detector is not None and not compatibility(columns, detector["feature_names"]).compatible:
            detector, anomaly_record = None, None
        frame = load_dataset_frame(path, max_rows=MAX_REPLAY_ROWS)
        if "timestamp" not in frame.columns:
            raise ReplayError("This dataset has no Timestamp column, so it cannot be replayed in time order.")
        parsed = pd.to_datetime(frame["timestamp"].astype(str).str.strip(), errors="coerce", dayfirst=True)
        if parsed.notna().mean() < 0.99:
            raise ReplayError("Fewer than 99 % of the timestamps could be read, so this dataset cannot be replayed.")
        if getattr(parsed.dt, "tz", None) is None:
            parsed = parsed.dt.tz_localize("UTC")
        frame["_label"] = frame[LABEL_COLUMN].astype(str).map(clean_label)
        frame["_ts"] = parsed.dt.tz_convert("UTC")
        frame = frame[frame["_ts"].notna() & frame["_label"].map(scenario.matches)]
        if frame.empty:
            raise ReplayError("No rows match this scenario.")
        # Stable sort keeps the file order for equal timestamps; the index stays the file row (index + 2).
        frame = frame.sort_values("_ts", kind="mergesort")
        frame["_score"], frame["_category"], frame["_anomaly"] = np.nan, "", np.nan
        self._classifier, self._detector = classifier, detector
        self._models = {"classifier": {"id": classifier_record.id, "version": classifier_record.version}}
        if anomaly_record is not None:
            self._models["anomaly"] = {"id": anomaly_record.id, "version": anomaly_record.version}
        return {"frame": frame, "scenario": scenario, "dataset": dataset}

    def pause(self, principal: Principal) -> None:
        self._set_paused(principal, True)

    def resume(self, principal: Principal) -> None:
        self._set_paused(principal, False)

    def _set_paused(self, principal: Principal, paused: bool) -> None:
        action = "replay.pause" if paused else "replay.resume"
        require_permission(principal, Permission.RUN_DETECTION, action=action)
        with self._lock:
            if not self.status.running:
                raise ReplayError("No replay is running.")
            self.status.paused = paused
            session_id = self.status.session_id
        audit_service.record_standalone(user_id=principal.user_id, action=action, outcome="success",
                                        details={"session_id": session_id})

    def set_speed(self, principal: Principal, speed: int) -> None:
        require_permission(principal, Permission.RUN_DETECTION, action="replay.speed", details={"speed": speed})
        if speed not in SPEEDS:
            raise ReplayError(f"Speed must be one of {', '.join(f'{s}×' for s in SPEEDS)}.")
        with self._lock:
            if not self.status.running:
                raise ReplayError("No replay is running.")
            self.status.speed = speed
            session_id = self.status.session_id
        audit_service.record_standalone(user_id=principal.user_id, action="replay.speed", outcome="success",
                                        details={"session_id": session_id, "speed": speed})

    def stop(self, principal: Optional[Principal], reason: str = "Stopped by user") -> None:
        if principal is not None:
            require_permission(principal, Permission.RUN_DETECTION, action="replay.stop")
        with self._lock:
            if not self.status.running:
                raise ReplayError("No replay is running.")
            session_id = self.status.session_id
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=30)
        with self._lock:
            if self.status.running:
                self._finish(SessionState.STOPPED, f"{reason} after {self.status.rows_done:,} of "
                                                   f"{self.status.rows_total:,} rows.")
        if principal is not None:
            audit_service.record_standalone(user_id=principal.user_id, action="replay.stop", outcome="success",
                                            details={"session_id": session_id, "rows_done": self.status.rows_done})

    def restart(self, principal: Principal) -> int:
        """Stop the current replay (if any) and play the same scenario again from the start in a new session."""
        require_permission(principal, Permission.RUN_DETECTION, action="replay.restart")
        with self._lock:
            dataset_id, scenario = self.status.dataset_id, self.status.scenario_key
            speed, capacity = self.status.speed, self.status.capacity_bps
            running = self.status.running
        if dataset_id is None or scenario is None:
            raise ReplayError("Nothing has been replayed yet.")
        if running:
            self.stop(principal, "Restarted")
        return self.start(principal, dataset_id, scenario, speed=speed, capacity_bps=capacity)

    # ---------------------------------------------------------- the loop
    def _run(self) -> None:
        last = time.monotonic()
        try:
            while not self._stop.wait(self._tick):
                now = time.monotonic()
                elapsed, last = now - last, now
                with self._lock:
                    if self.status.paused:
                        continue
                    speed = self.status.speed
                if not self.step(elapsed * speed):
                    break
        except Exception as exc:  # never leave a replay RUNNING after a failure
            message = f"Replay stopped after an error: {type(exc).__name__}: {exc}"
            with self._lock:
                self.status.last_error = message
                if self.status.running:
                    self._finish(SessionState.ERROR, message[:500])

    def step(self, dataset_seconds: float) -> bool:
        """Advance the replay clock and process the rows that became due. Returns False when finished.

        Public so tests can drive the replay deterministically without the background thread.
        """
        with self._lock:
            if not self.status.running:
                return False
            if not self._session_still_running():
                # The session was closed elsewhere (for example, startup recovery after the code reloaded):
                # stop quietly rather than keep writing into a closed session.
                self.status.running = False
                self.status.last_error = "This replay's session was closed outside the replay engine."
                return False
            target = self._clock + max(0.0, dataset_seconds)
            end = rows_due(self._times, self._cursor, target)
            if end < len(self._times) and end - self._cursor >= MAX_ROWS_PER_TICK:
                # Too many rows for one tick: the clock only moves as far as the rows actually processed.
                target = float(self._times[end - 1])
            batch = self._frame.iloc[self._cursor:end]
            self._cursor, self._clock = end, target
            finished = end >= len(self._times)
        new_alerts = self._process(batch, finished)
        with self._lock:
            self.status.rows_done = self._cursor
            self.status.progress = self._cursor / max(1, len(self._times))
            self.status.replay_time = (self._t0 + pd.Timedelta(seconds=self._clock)).isoformat()
            stamp = time.monotonic()
            self._recent = [(t, n) for t, n in self._recent if stamp - t <= RATE_WINDOW_SECONDS] + [(stamp, len(batch))]
            span = stamp - self._recent[0][0]
            self.status.rows_per_second = sum(n for _, n in self._recent) / span if span > 0 else None
        if new_alerts:
            self._correlate()
        if finished:
            with self._lock:
                if self.status.running:
                    self._finish(SessionState.STOPPED, f"Replay finished: {self.status.rows_done:,} rows, "
                                                       f"{len(self.status.alerts)} alert(s).")
                    self.status.finished = True
            return False
        return True

    def _session_still_running(self) -> bool:
        with database_service.session() as conn:
            row = conn.execute("SELECT status FROM monitoring_sessions WHERE id = ?", (self.status.session_id,)).fetchone()
        return row is not None and row["status"] == SessionState.RUNNING.value

    def _process(self, batch: pd.DataFrame, finished: bool) -> List[int]:
        verdicts = None
        if not batch.empty:
            verdicts = intrusion_inference_service.score_frame(batch, self._classifier, self._detector)
            for idx in batch.index[(verdicts.category != "").to_numpy()]:
                key = (verdicts.category.at[idx], window_start(self._seconds(idx, batch), ALERT_WINDOW_SECONDS))
                self._pending_alerts.setdefault(key, []).append(idx)
            for idx in batch.index:
                w = window_start(self._seconds(idx, batch), METRIC_INTERVAL_SECONDS)
                acc = self._pending_metrics.setdefault(w, [0.0, 0.0])
                acc[0] += _number(batch, idx, ("total_length_of_fwd_packets", "total_length_of_bwd_packets"))
                acc[1] += _number(batch, idx, ("total_fwd_packets", "total_backward_packets"))
            self._remember_scores(batch, verdicts)
        session_id = self.status.session_id
        created: List[int] = []
        metric_windows = complete_windows(list(self._pending_metrics), self._clock, METRIC_INTERVAL_SECONDS,
                                          finished=finished)
        with database_service.session(write=True) as conn:
            if verdicts is not None:
                conn.executemany(
                    "INSERT INTO network_flows (session_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, "
                    "packet_count, byte_count, duration, intrusion_prediction, anomaly_score, model_id, model_version, "
                    "feature_summary_json, provenance) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [self._flow_row(session_id, batch, idx, verdicts) for idx in batch.index])
            if metric_windows:
                telemetry_repository.insert_many(conn, [self._metric_row(session_id, w) for w in metric_windows])
            alert_windows = complete_windows(sorted({w for _, w in self._pending_alerts}), self._clock,
                                             ALERT_WINDOW_SECONDS, finished=finished)
            for key in sorted(k for k in self._pending_alerts if k[1] in alert_windows):
                alert_id = self._raise_alert(conn, key, self._pending_alerts.pop(key))
                if alert_id is not None:
                    created.append(alert_id)
        for w in metric_windows:
            self._pending_metrics.pop(w, None)
        with self._lock:
            if verdicts is not None:
                self.status.flagged += int((verdicts.category != "").sum())
            self.status.alerts.extend(created)
        if metric_windows:
            self._forecast(max(metric_windows))
        return created

    # ------------------------------------------------------------ helpers
    def _seconds(self, idx, batch: pd.DataFrame) -> float:
        return (batch.at[idx, "_ts"] - self._t0).total_seconds()

    def _remember_scores(self, batch: pd.DataFrame, verdicts) -> None:
        """Keep each row's verdict on the replay frame; alerts are built from it when their window completes."""
        self._frame.loc[batch.index, "_score"] = verdicts.scores
        self._frame.loc[batch.index, "_category"] = verdicts.category
        if verdicts.anomaly_scores is not None:
            self._frame.loc[batch.index, "_anomaly"] = verdicts.anomaly_scores

    def _flow_row(self, session_id: int, batch: pd.DataFrame, idx, verdicts) -> tuple:
        row = batch.loc[idx]
        protocol = pd.to_numeric(row.get("protocol"), errors="coerce") if "protocol" in batch.columns else np.nan
        category = verdicts.category.at[idx] or None
        anomaly = None if verdicts.anomaly_scores is None else float(verdicts.anomaly_scores.at[idx])
        features = {}
        for name in self._classifier["feature_names"]:
            value = pd.to_numeric(row.get(name), errors="coerce")
            features[name] = None if pd.isna(value) or not np.isfinite(value) else round(float(value), 6)
        return (
            session_id, row["_ts"].isoformat(timespec="microseconds"),
            intrusion_inference_service._cell(row, "source_ip"), intrusion_inference_service._cell(row, "destination_ip"),
            intrusion_inference_service._port(row, "source_port"),
            intrusion_inference_service._port(row, "destination_port"),
            None if pd.isna(protocol) else PROTOCOL_NAMES.get(int(protocol), str(int(protocol))),
            intrusion_inference_service._count(row, ("total_fwd_packets", "total_backward_packets")),
            intrusion_inference_service._count(row, ("total_length_of_fwd_packets", "total_length_of_bwd_packets")),
            intrusion_inference_service._duration(row), category, anomaly,
            self._models["classifier"]["id"], self._models["classifier"]["version"],
            json.dumps({"replay": True, "dataset_row": int(idx) + 2, "dataset_label": row["_label"],
                        "model_score_uncalibrated": round(float(verdicts.scores.at[idx]), 4), "features": features}),
            "measured",
        )

    def _metric_row(self, session_id: int, window: int) -> tuple:
        byte_total, packet_total = self._pending_metrics[window]
        sample = throughput_sample(byte_total, packet_total, METRIC_INTERVAL_SECONDS, self.status.capacity_bps)
        at = (self._t0 + pd.Timedelta(seconds=window)).isoformat(timespec="microseconds")
        capacity = self.status.capacity_bps
        return (session_id, at, REPLAY_SOURCE_NAME, REPLAY_INTERFACE, None, None, None, None,
                sample["throughput_bps"], None, None, sample["utilization_ratio"], capacity,
                "replay: bytes of replayed flow records per interval (by flow start time)", "derived", "partial",
                "derived", "derived" if sample["utilization_ratio"] is not None else "unavailable",
                "configured" if capacity else "unavailable")

    def _raise_alert(self, conn, key: Tuple[str, int], indexes: List[Any]) -> Optional[int]:
        category, window = key
        group = self._frame.loc[indexes]
        timestamps = self._frame["_ts"]
        is_anomaly = category == "Anomalous flows"
        ddos = None if is_anomaly else intrusion_inference_service._potential_ddos(group, timestamps)
        scores = -group["_anomaly"] if is_anomaly else group["_score"]
        evidence = intrusion_inference_service._evidence(group, scores, timestamps, len(group), group["_label"])
        evidence.pop("share_of_scored_rows", None)
        evidence.update({"source": "dataset replay", "replay_session_id": self.status.session_id,
                         "dataset_id": self.status.dataset_id, "alert_window_seconds": ALERT_WINDOW_SECONDS})
        if ddos:
            evidence["potential_ddos"] = ddos
        alert_type = "anomaly" if is_anomaly else "security"
        model = self._models.get("anomaly") if is_anomaly else self._models["classifier"]
        start = (self._t0 + pd.Timedelta(seconds=window)).strftime("%H:%M")
        if is_anomaly:
            reason = (f"Replay: {len(group):,} flows from {start} look unusual compared with benign training traffic, "
                      "although the classifier did not flag them.")
        else:
            reason = f"Replay: the intrusion classifier flagged {len(group):,} flows from {start} as '{category}'."
            if ddos:
                reason += (f" Potential DDoS: {ddos['distinct_sources']} distinct sources targeted "
                           f"{ddos['destination']} within {intrusion_inference_service.DDOS_WINDOW_SECONDS} s.")
        return alert_service.create_alert(
            conn, alert_type=alert_type,
            severity=intrusion_inference_service.severity_for(category, len(group), alert_type, bool(ddos)),
            category=category, reason=reason, evidence=evidence,
            dedup_key=f"replay:{self.status.session_id}:{category}:{window}", session_id=self.status.session_id,
            model_id=(model or {}).get("id"), model_version=(model or {}).get("version"),
            created_by=self._principal.user_id if self._principal else None)

    def _correlate(self) -> None:
        try:
            run = incident_correlation_service.correlate(self._principal)
        except Exception as exc:  # correlation problems must not stop the replay
            with self._lock:
                self.status.last_error = f"Correlation failed: {exc}"
            return
        with self._lock:
            for incident_id in run.incidents_created + run.incidents_updated:
                if incident_id not in self.status.incidents:
                    self.status.incidents.append(incident_id)

    def _forecast(self, latest_window: int) -> None:
        """Ask PredictNet for a forecast once per forecaster interval of replayed time, if one is active."""
        principal = self._principal
        record = model_registry_service.active_model(principal, "congestion_forecaster") if principal else None
        if record is None:
            self.status.forecast_note = "No active PredictNet forecaster, so the replay has no forecasts."
            return
        interval = int(record.training_metadata.get("interval_seconds") or 300)
        current = window_start(latest_window, interval)
        if self._last_forecast_window is not None and current <= self._last_forecast_window:
            return
        self._last_forecast_window = current
        try:
            congestion_prediction_service.generate_forecast(principal, self.status.session_id, REPLAY_INTERFACE)
            self.status.forecast_note = f"Forecast updated at replay time {self.status.replay_time}."
        except congestion_prediction_service.PredictionError as exc:
            self.status.forecast_note = f"No forecast yet: {exc}"

    def _finish(self, state: SessionState, message: str) -> None:
        """Close the session. Caller holds the lock."""
        self.status.running = False
        self.status.paused = False
        try:
            with database_service.session(write=True) as conn:
                monitoring_service.transition(conn, self.status.session_id, SessionState.STOPPING)
                monitoring_service.transition(conn, self.status.session_id, state, message)
        except (monitoring_service.InvalidTransition, monitoring_service.SessionNotFound):
            pass


def _number(batch: pd.DataFrame, idx, columns: Tuple[str, ...]) -> float:
    total = 0.0
    for column in columns:
        if column in batch.columns:
            value = pd.to_numeric(batch.at[idx, column], errors="coerce")
            if pd.notna(value) and np.isfinite(value) and value >= 0:
                total += float(value)
    return total


# ------------------------------------------------------------------ service API

def scenarios(principal: Principal, dataset_id: int) -> List[Scenario]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="replay.view")
    with database_service.session() as conn:
        dataset = dataset_repository.get(conn, dataset_id)
    if dataset is None or dataset["kind"] != "intrusion_flows":
        return []
    labels = json.loads(dataset["label_distribution_json"]) if dataset["label_distribution_json"] else {}
    return scenarios_for(labels)


def replay_counts(principal: Principal) -> Dict[str, int]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="replay.view")
    with database_service.session() as conn:
        return _counts(conn)


def _counts(conn) -> Dict[str, int]:
    one = lambda sql, *args: int(conn.execute(sql, args).fetchone()[0])  # noqa: E731
    sessions = "SELECT id FROM monitoring_sessions WHERE source_type = 'replay'"
    return {
        "sessions": one(f"SELECT COUNT(*) FROM ({sessions})"),
        "flows": one(f"SELECT COUNT(*) FROM network_flows WHERE session_id IN ({sessions})"),
        "metrics": one(f"SELECT COUNT(*) FROM network_metrics WHERE session_id IN ({sessions})"),
        "alerts": one(f"SELECT COUNT(*) FROM alerts WHERE session_id IN ({sessions})"),
        "incidents": one("SELECT COUNT(*) FROM incidents WHERE is_replay = 1"),
        "predictions": one("SELECT COUNT(*) FROM congestion_predictions WHERE source_name = ?", REPLAY_SOURCE_NAME),
    }


def clear_replay_data(principal: Principal) -> Dict[str, int]:
    """Delete every replay session with its flows, metrics, alerts, incidents and forecasts. Admin only, audited.

    Real captured or imported data is never touched: everything is selected by the replay source type.
    """
    require_permission(principal, Permission.DELETE_DATA, action="replay.clear")
    engine = get_engine()
    if engine.status.running:
        engine.stop(None, "Stopped to clear replay data")
    with database_service.session(write=True) as conn:
        counts = _counts(conn)
        sessions = "SELECT id FROM monitoring_sessions WHERE source_type = 'replay'"
        conn.execute("DELETE FROM incidents WHERE is_replay = 1")
        conn.execute(f"DELETE FROM alerts WHERE session_id IN ({sessions})")
        conn.execute("DELETE FROM congestion_predictions WHERE source_name = ?", (REPLAY_SOURCE_NAME,))
        # Flows and metrics go with their sessions (ON DELETE CASCADE).
        conn.execute("DELETE FROM monitoring_sessions WHERE source_type = 'replay'")
        audit_service.record(conn, user_id=principal.user_id, action="replay.clear", details=counts)
    with engine._lock:
        engine.status = ReplayStatus(speed=engine.status.speed)
    return counts


_ENGINE: Optional[ReplayEngine] = None
_ENGINE_LOCK = threading.Lock()


def get_engine() -> ReplayEngine:
    """The process-wide replay engine. Creating it closes replay sessions orphaned by a previous run."""
    global _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is None:
            monitoring_service.recover_interrupted_sessions(SourceType.REPLAY.value)
            _ENGINE = ReplayEngine()
        return _ENGINE


def reset_engine_for_tests(engine: Optional[ReplayEngine] = None) -> None:
    global _ENGINE
    _ENGINE = engine


def status_copy() -> ReplayStatus:
    engine = get_engine()
    with engine._lock:
        return replace(engine.status, alerts=list(engine.status.alerts), incidents=list(engine.status.incidents))
