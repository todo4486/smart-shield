"""Smart Shield detection: run registered models over a dataset and raise alerts.

* Models are loaded only through the registry (hash-verified).
* The data must contain every feature the model was trained on. Otherwise the
  model is REJECTED for this data. Missing features are never zero-filled.
* Flagged rows are grouped into one alert per detected category per run, so a
  run never produces thousands of identical alerts, and re-running the same
  model on the same data does not duplicate unresolved alerts.
* Scores are reported as uncalibrated model scores, never as probabilities.
* Every flow, prediction and alert carries the model id and version.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from repositories import dataset_repository, monitoring_repository
from services import alert_service, audit_service, database_service, model_registry_service, monitoring_service
from services.authorization import Permission, Principal, require_permission
from services.dataset_service import LABEL_COLUMN, PROTOCOL_NAMES
from services.intrusion_features import (
    CompatibilityReport, build_label_map, compatibility, header_columns, load_dataset_frame, numeric_feature_frame,
)
from services.model_registry_service import ModelRecord
from services.monitoring_service import SessionState, SourceType

MAX_DETECTION_ROWS = 500_000
MAX_STORED_FLAGGED_FLOWS = 50_000
DDOS_MIN_SOURCES = 20
DDOS_WINDOW_SECONDS = 60

# Severity rules (documented in the Security Center).
CRITICAL_TYPES = re.compile(r"heartbleed|infiltration|bot|sql injection", re.I)
HIGH_TYPES = re.compile(r"dos|ddos|patator|brute force|web attack|xss", re.I)
LARGE_GROUP = 1_000


class DetectionError(Exception):
    pass


@dataclass(frozen=True)
class DetectionOptions:
    dataset_id: int
    classifier_model_id: Optional[int] = None  # None -> active model
    anomaly_model_id: Optional[int] = None  # None -> active model (if any)
    use_anomaly_detector: bool = True
    max_rows: int = 200_000
    dayfirst: bool = True
    utc_offset_hours: float = 0.0


@dataclass
class DetectionReport:
    session_id: int
    dataset_id: int
    rows_scored: int
    flagged_attack: int
    flagged_anomaly_only: int
    by_category: Dict[str, int]
    alerts_created: List[int]
    alerts_deduplicated: int
    flows_stored: int
    classifier: Dict[str, Any]
    anomaly_detector: Optional[Dict[str, Any]]
    compatibility: Dict[str, Any]
    ground_truth: Optional[Dict[str, Any]] = None
    warnings: List[str] = field(default_factory=list)


def severity_for(category: str, count: int, alert_type: str, potential_ddos: bool) -> str:
    if alert_type == "anomaly":
        return "medium" if count >= 100 else "low"
    if CRITICAL_TYPES.search(category) or (potential_ddos and count >= LARGE_GROUP):
        return "critical"
    if HIGH_TYPES.search(category) or potential_ddos or count >= LARGE_GROUP:
        return "high"
    return "medium"


def _resolve_model(principal: Principal, family: str, model_id: Optional[int]) -> Optional[ModelRecord]:
    if model_id is not None:
        record = model_registry_service.get_model(principal, model_id)
        if record.family != family:
            raise DetectionError(f"Model #{model_id} is not a {family}.")
        return record
    return model_registry_service.active_model(principal, family)


def check_compatibility(principal: Principal, dataset_id: int, model_id: Optional[int] = None) -> CompatibilityReport:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="model.compatibility")
    record = _resolve_model(principal, "intrusion_classifier", model_id)
    if record is None:
        raise DetectionError("There is no active intrusion classifier.")
    with database_service.session() as conn:
        row = dataset_repository.get(conn, dataset_id)
    if row is None or not row["stored_path"]:
        raise DetectionError("Dataset not found or has no stored file.")
    return compatibility(header_columns(Path(row["stored_path"])), record.training_metadata.get("feature_names", []))


def _timestamps(frame: pd.DataFrame, options: DetectionOptions) -> Optional[pd.Series]:
    if "timestamp" not in frame.columns:
        return None
    parsed = pd.to_datetime(frame["timestamp"].astype(str).str.strip(), errors="coerce", dayfirst=options.dayfirst)
    if parsed.notna().mean() < 0.99:
        return None
    if getattr(parsed.dt, "tz", None) is None:
        parsed = (parsed - pd.Timedelta(hours=options.utc_offset_hours)).dt.tz_localize("UTC")
    return parsed.dt.tz_convert("UTC")


def _potential_ddos(group: pd.DataFrame, timestamps: Optional[pd.Series]) -> Optional[Dict[str, Any]]:
    """Many distinct sources hitting one destination inside a short window."""
    if timestamps is None or "source_ip" not in group.columns or "destination_ip" not in group.columns:
        return None
    frame = pd.DataFrame({"src": group["source_ip"].astype(str), "dst": group["destination_ip"].astype(str),
                          "window": timestamps.loc[group.index].dt.floor(f"{DDOS_WINDOW_SECONDS}s")})
    sources = frame.groupby(["dst", "window"])["src"].nunique()
    if sources.empty or sources.max() < DDOS_MIN_SOURCES:
        return None
    (dst, window) = sources.idxmax()
    return {"destination": dst, "window_start": str(window), "distinct_sources": int(sources.max()),
            "rule": f"≥ {DDOS_MIN_SOURCES} distinct sources to one destination within {DDOS_WINDOW_SECONDS} s"}


def _top(series: pd.Series, n: int = 5) -> List[Dict[str, Any]]:
    return [{"value": str(k), "flows": int(v)} for k, v in series.astype(str).value_counts().head(n).items()]


def _evidence(group: pd.DataFrame, scores: pd.Series, timestamps: Optional[pd.Series], total: int,
              labels: Optional[pd.Series]) -> Dict[str, Any]:
    evidence: Dict[str, Any] = {
        "flows": int(len(group)), "share_of_scored_rows": round(len(group) / max(total, 1), 4),
        "model_score_uncalibrated": {"min": float(scores.min()), "median": float(scores.median()),
                                     "max": float(scores.max())},
        "example_rows": [int(i) + 2 for i in group.index[:10]],
    }
    for column, key in (("source_ip", "top_sources"), ("destination_ip", "top_destinations"),
                        ("destination_port", "top_destination_ports")):
        if column in group.columns:
            evidence[key] = _top(group[column])
    if timestamps is not None:
        window = timestamps.loc[group.index]
        evidence["time_window_utc"] = [window.min().isoformat(), window.max().isoformat()]
    if labels is not None:
        evidence["dataset_labels_of_flagged_rows"] = _top(labels.loc[group.index], 8)
    return evidence


def run_detection(principal: Principal, options: DetectionOptions) -> DetectionReport:
    require_permission(principal, Permission.RUN_DETECTION, action="detection.run",
                       details={"dataset_id": options.dataset_id})
    try:
        return _run(principal, options)
    except DetectionError as exc:
        audit_service.record_standalone(user_id=principal.user_id, action="detection.run", outcome="failure",
                                        details={"dataset_id": options.dataset_id, "error": str(exc)[:300]})
        raise


def _run(principal: Principal, options: DetectionOptions) -> DetectionReport:
    if not 1 <= options.max_rows <= MAX_DETECTION_ROWS:
        raise DetectionError(f"Row limit must be between 1 and {MAX_DETECTION_ROWS:,}.")
    classifier_record = _resolve_model(principal, "intrusion_classifier", options.classifier_model_id)
    if classifier_record is None:
        raise DetectionError("There is no active intrusion classifier. Train one in the ML Laboratory and ask an "
                             "administrator to activate it.")
    anomaly_record = None
    if options.use_anomaly_detector:
        anomaly_record = _resolve_model(principal, "anomaly_detector", options.anomaly_model_id)

    with database_service.session() as conn:
        dataset = dataset_repository.get(conn, options.dataset_id)
    if dataset is None or dataset["kind"] != "intrusion_flows" or not dataset["stored_path"]:
        raise DetectionError("Choose a registered intrusion dataset.")
    path = Path(dataset["stored_path"])
    if not path.is_file():
        raise DetectionError("The dataset's stored file is missing.")

    try:
        classifier = model_registry_service.load_bundle(classifier_record)
        detector = model_registry_service.load_bundle(anomaly_record) if anomaly_record else None
    except model_registry_service.ModelRegistryError as exc:
        raise DetectionError(str(exc)) from exc

    columns = header_columns(path)
    compat = compatibility(columns, classifier["feature_names"])
    if not compat.compatible:
        raise DetectionError(compat.message + " Missing: " + ", ".join(compat.missing[:10]))
    warnings: List[str] = []
    if detector is not None and not compatibility(columns, detector["feature_names"]).compatible:
        warnings.append("The anomaly detector was skipped: this data lacks some of its features.")
        detector, anomaly_record = None, None

    frame = load_dataset_frame(path, max_rows=options.max_rows)
    if dataset["row_count"] > options.max_rows:
        warnings.append(f"Scored the first {options.max_rows:,} of {dataset['row_count']:,} rows (row limit).")
    features = numeric_feature_frame(frame, classifier["feature_names"])
    scores = pd.Series(classifier["model"].predict_proba(features)[:, 1], index=frame.index)
    flagged = scores >= classifier["score_threshold"]

    category = pd.Series("", index=frame.index, dtype=object)
    attack_model = classifier.get("attack_type_model")
    if flagged.any():
        if attack_model is not None:
            predicted = attack_model.predict(features[flagged.to_numpy()])
            # The type model may still say BENIGN for a flagged row; keep it flagged as an unclassified attack.
            category[flagged] = np.where(predicted == "BENIGN", "Attack (unclassified)", predicted)
        else:
            category[flagged] = "Attack (unclassified)"

    anomaly_scores = None
    anomaly_only = pd.Series(False, index=frame.index)
    if detector is not None:
        anomaly_features = numeric_feature_frame(frame, detector["feature_names"])
        anomaly_scores = pd.Series(detector["model"].score_samples(anomaly_features), index=frame.index)
        anomaly_only = (anomaly_scores < detector["threshold"]) & ~flagged
        category[anomaly_only] = "Anomalous flows"

    labels = frame[LABEL_COLUMN].astype(str) if LABEL_COLUMN in frame.columns else None
    ground_truth = None
    if labels is not None:
        truth = labels.map(build_label_map(labels).binary)
        tp = int((flagged & (truth == 1)).sum())
        fp = int((flagged & (truth == 0)).sum())
        fn = int((~flagged & (truth == 1)).sum())
        tn = int((~flagged & (truth == 0)).sum())
        ground_truth = {
            "note": "This dataset is labelled, so detections can be compared with its ground truth.",
            "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
            "recall": tp / (tp + fn) if tp + fn else None,
            "precision": tp / (tp + fp) if tp + fp else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        }

    timestamps = _timestamps(frame, options)
    if timestamps is None:
        warnings.append("This data has no usable timestamps, so flagged flows are summarised in alerts but not "
                        "stored as individual flows.")

    configuration = {
        "purpose": "detection", "dataset_id": dataset["id"], "dataset_name": dataset["name"],
        "classifier": {"id": classifier_record.id, "version": classifier_record.version},
        "anomaly_detector": {"id": anomaly_record.id, "version": anomaly_record.version} if anomaly_record else None,
        "rows_scored": int(len(frame)),
    }
    with database_service.session(write=True) as conn:
        session_id = monitoring_service.create_session(
            conn, user_id=principal.user_id, source_type=SourceType.DATASET, configuration=configuration,
            dataset_id=dataset["id"],
        )

    try:
        flows_stored = 0
        flow_rows = []
        if timestamps is not None:
            interesting = frame.index[(flagged | anomaly_only).to_numpy()][:MAX_STORED_FLAGGED_FLOWS]
            if len(interesting) < int((flagged | anomaly_only).sum()):
                warnings.append(f"Only the first {MAX_STORED_FLAGGED_FLOWS:,} flagged flows were stored as flows.")
            for idx in interesting:
                row = frame.loc[idx]
                protocol = pd.to_numeric(row.get("protocol"), errors="coerce") if "protocol" in frame.columns else np.nan
                flow_rows.append((
                    session_id, timestamps.at[idx].isoformat(timespec="microseconds"),
                    _cell(row, "source_ip"), _cell(row, "destination_ip"),
                    _port(row, "source_port"), _port(row, "destination_port"),
                    None if pd.isna(protocol) else PROTOCOL_NAMES.get(int(protocol), str(int(protocol))),
                    _count(row, ("total_fwd_packets", "total_backward_packets")),
                    _count(row, ("total_length_of_fwd_packets", "total_length_of_bwd_packets")),
                    _duration(row),
                    category.at[idx],
                    None if anomaly_scores is None else float(anomaly_scores.at[idx]),
                    classifier_record.id, classifier_record.version,
                    json.dumps({"dataset_label": labels.at[idx] if labels is not None else None,
                                "model_score_uncalibrated": round(float(scores.at[idx]), 4)}),
                    "measured",
                ))

        alerts_created: List[int] = []
        deduplicated = 0
        by_category = {str(k): int(v) for k, v in category[category != ""].value_counts().items()}
        with database_service.session(write=True) as conn:
            if flow_rows:
                conn.executemany(
                    "INSERT INTO network_flows (session_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, "
                    "packet_count, byte_count, duration, intrusion_prediction, anomaly_score, model_id, model_version, "
                    "feature_summary_json, provenance) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    flow_rows,
                )
                flows_stored = len(flow_rows)
            for name, count in by_category.items():
                group = frame[category == name]
                is_anomaly = name == "Anomalous flows"
                ddos = None if is_anomaly else _potential_ddos(group, timestamps)
                alert_type = "anomaly" if is_anomaly else "security"
                group_scores = (-anomaly_scores.loc[group.index]) if is_anomaly else scores.loc[group.index]
                evidence = _evidence(group, group_scores, timestamps, len(frame), labels)
                if ddos:
                    evidence["potential_ddos"] = ddos
                model = anomaly_record if is_anomaly else classifier_record
                if is_anomaly:
                    reason = (f"{count:,} flows look unusual compared with benign training traffic, although the "
                              "classifier did not flag them. Investigate before drawing conclusions.")
                else:
                    reason = f"The intrusion classifier flagged {count:,} flows as '{name}'."
                    if ddos:
                        reason += (f" Potential DDoS: {ddos['distinct_sources']} distinct sources targeted "
                                   f"{ddos['destination']} within {DDOS_WINDOW_SECONDS} s.")
                alert_id = alert_service.create_alert(
                    conn, alert_type=alert_type, severity=severity_for(name, count, alert_type, bool(ddos)),
                    category=name, reason=reason, evidence=evidence,
                    dedup_key=f"detect:{dataset['id']}:{model.family}:{model.version}:{name}",
                    session_id=session_id, model_id=model.id, model_version=model.version,
                    created_by=principal.user_id,
                )
                if alert_id is None:
                    deduplicated += 1
                else:
                    alerts_created.append(alert_id)
            configuration.update(flagged_attack=int(flagged.sum()), flagged_anomaly_only=int(anomaly_only.sum()),
                                 by_category=by_category, flows_stored=flows_stored, alerts=alerts_created)
            monitoring_repository.update_configuration(conn, session_id, json.dumps(configuration, default=str),
                                                       None, dataset["id"])
            monitoring_service.transition(conn, session_id, SessionState.STOPPED,
                                          f"Scored {len(frame):,} rows; {len(alerts_created)} alert(s)")
            audit_service.record(conn, user_id=principal.user_id, action="detection.run",
                                 details={"dataset_id": dataset["id"], "session_id": session_id,
                                          "classifier_version": classifier_record.version,
                                          "flagged": int(flagged.sum()), "alerts": alerts_created})
    except Exception as exc:
        monitoring_service.fail_session(session_id, f"Detection failed: {exc}")
        raise DetectionError(f"Detection failed and no alerts were stored: {exc}") from exc

    return DetectionReport(
        session_id=session_id, dataset_id=dataset["id"], rows_scored=int(len(frame)),
        flagged_attack=int(flagged.sum()), flagged_anomaly_only=int(anomaly_only.sum()), by_category=by_category,
        alerts_created=alerts_created, alerts_deduplicated=deduplicated, flows_stored=flows_stored,
        classifier={"id": classifier_record.id, "version": classifier_record.version, "name": classifier_record.name},
        anomaly_detector=({"id": anomaly_record.id, "version": anomaly_record.version} if anomaly_record else None),
        compatibility=compat.__dict__, ground_truth=ground_truth, warnings=warnings,
    )


def _cell(row: pd.Series, column: str) -> Optional[str]:
    if column not in row.index or pd.isna(row[column]):
        return None
    return str(row[column]).strip()[:64] or None


def _port(row: pd.Series, column: str) -> Optional[int]:
    if column not in row.index:
        return None
    value = pd.to_numeric(row[column], errors="coerce")
    return int(value) if pd.notna(value) and 0 <= value <= 65535 else None


def _count(row: pd.Series, columns: tuple) -> Optional[int]:
    if not all(c in row.index for c in columns):
        return None
    values = [pd.to_numeric(row[c], errors="coerce") for c in columns]
    if any(pd.isna(v) or not np.isfinite(v) or v < 0 for v in values):
        return None
    return int(sum(values))


def _duration(row: pd.Series) -> Optional[float]:
    if "flow_duration" not in row.index:
        return None
    value = pd.to_numeric(row["flow_duration"], errors="coerce")
    return float(value) / 1_000_000 if pd.notna(value) and np.isfinite(value) and value >= 0 else None
