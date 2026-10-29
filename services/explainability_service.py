""""Why was this flagged?": a plain, inspectable explanation for a security or anomaly alert.

Nothing here is a black-box attribution method, and nothing is presented as a probability:

* Global view: the Random Forest's own feature importances (mean decrease in impurity, from training).
* Per-alert view: the median of the flagged flows, feature by feature, against the median of a benign
  reference. Deviation is a robust z-score, (flagged median − benign median) / (1.4826 × benign MAD),
  plus the plain ratio to the benign median where that median is above zero.
  - Replayed and dataset alerts: the flows come from the dataset file; the reference is the dataset's
    BENIGN-labelled rows (up to REFERENCE_ROWS).
  - Live alerts: the stored features of the flagged flows; the reference is the flows of the same capture
    the classifier did not flag.
* Attack type: the attack-type forest's vote shares, averaged over the flagged flows. They are the share
  of trees voting for each class, not calibrated probabilities.
* Anomaly: the Isolation Forest score of the flagged flows on a line from normal to anomalous, with the
  model's decision threshold marked.
* The summary sentence is filled from a template with the numbers above, never generated text.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from repositories import alert_repository
from services import alert_service, database_service, model_registry_service
from services.authorization import Permission, Principal, require_permission
from services.dataset_service import LABEL_COLUMN
from services.intrusion_features import BENIGN_LABELS, clean_label, load_dataset_frame, numeric_feature_frame

REFERENCE_ROWS = 5_000
MAX_MEMBER_FLOWS = 500
MAX_SESSION_FLOWS = 50_000
TOP_DEVIATIONS = 6
TOP_IMPORTANCES = 10
MAD_SCALE = 1.4826
Z_CAP = 99.0


class ExplainError(Exception):
    pass


@dataclass
class Deviation:
    feature: str
    flagged_median: float
    benign_median: float
    robust_z: float
    ratio: Optional[float]
    importance: Optional[float]


@dataclass
class Explanation:
    alert_id: int
    category: str
    alert_type: str
    model_version: Optional[str]
    model_score: Optional[float]  # median classifier score of the flagged flows (uncalibrated)
    score_threshold: Optional[float]
    type_votes: List[Dict[str, Any]]  # [{"label", "share"}], share of trees, not a probability
    importances: List[Dict[str, Any]]
    deviations: List[Deviation]
    anomaly: Optional[Dict[str, Any]]
    context: Dict[str, Any]
    summary: str
    basis: Dict[str, str]
    flows_used: int
    reference_rows: int
    notes: List[str] = field(default_factory=list)


# ------------------------------------------------------------------ pure helpers

_WORDS = {"iat": "IAT", "fwd": "Fwd", "bwd": "Bwd", "psh": "PSH", "urg": "URG", "fin": "FIN", "syn": "SYN",
          "rst": "RST", "ack": "ACK", "ece": "ECE", "cwe": "CWE", "ip": "IP"}


def pretty(feature: str) -> str:
    """'flow_iat_mean' → 'Flow IAT mean', 'flow_bytes_s' → 'Flow bytes/s' (pure)."""
    words = feature.split("_")
    if len(words) > 1 and words[-1] == "s":
        words = words[:-2] + [words[-2] + "/s"]
    words = [_WORDS.get(w, w) for w in words]
    text = " ".join(words)
    return text[:1].upper() + text[1:]


def robust_deviations(flagged: pd.DataFrame, reference: pd.DataFrame, features: List[str],
                      importances: Optional[Dict[str, float]] = None, top: int = TOP_DEVIATIONS) -> List[Deviation]:
    """Features where the flagged flows' median sits furthest from the benign median (pure).

    A feature with no spread in the reference (MAD 0) still counts when the medians differ: its z-score
    is capped at Z_CAP instead of being infinite. Missing values are ignored, never treated as 0.
    """
    out: List[Deviation] = []
    for name in features:
        if name not in flagged.columns or name not in reference.columns:
            continue
        values = pd.to_numeric(flagged[name], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
        base = pd.to_numeric(reference[name], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
        if values.empty or base.empty:
            continue
        median, base_median = float(values.median()), float(base.median())
        mad = float((base - base_median).abs().median()) * MAD_SCALE
        diff = median - base_median
        if mad > 0:
            z = max(-Z_CAP, min(Z_CAP, diff / mad))
        else:
            z = 0.0 if diff == 0 else (Z_CAP if diff > 0 else -Z_CAP)
        ratio = median / base_median if base_median > 0 else None
        out.append(Deviation(name, median, base_median, z, ratio, (importances or {}).get(name)))
    out.sort(key=lambda d: (-abs(d.robust_z), d.feature))
    return [d for d in out if d.robust_z != 0][:top]


def vote_shares(probabilities: np.ndarray, classes: List[str], top: int = 3) -> List[Dict[str, Any]]:
    """Mean share of trees voting for each class over the flagged flows, largest first (pure)."""
    if probabilities.size == 0:
        return []
    mean = probabilities.mean(axis=0)
    order = sorted(range(len(classes)), key=lambda i: (-mean[i], str(classes[i])))
    return [{"label": str(classes[i]), "share": float(mean[i])} for i in order[:top] if mean[i] > 0]


def anomaly_position(score: float, threshold: float, low: float, high: float) -> Dict[str, float]:
    """Where a score and the threshold sit on a 0 (normal) → 1 (anomalous) line (pure).

    Isolation Forest scores are higher for normal points, so the line runs from `high` down to `low`.
    """
    span = high - low
    if span <= 0:
        return {"score": 0.5, "threshold": 0.5}
    clip = lambda v: float(min(1.0, max(0.0, (high - v) / span)))  # noqa: E731
    return {"score": clip(score), "threshold": clip(threshold)}


def _times(ratio: float) -> str:
    if ratio >= 10:
        return f"{ratio:,.0f}×"
    if ratio >= 1:
        return f"{ratio:,.1f}×"
    return f"{ratio:.0%} of"


def summary_sentence(category: str, alert_type: str, model_score: Optional[float], top_vote: Optional[Dict[str, Any]],
                     deviation: Optional[Deviation], context: Dict[str, Any]) -> str:
    """Template-based plain-English summary; every number comes from the explanation (pure)."""
    if alert_type == "anomaly":
        head = "Flagged as unusual by the anomaly detector (the classifier did not call it an attack)"
    else:
        head = f"Flagged as {category}"
        bits = []
        if model_score is not None:
            bits.append(f"model score {model_score:.2f}, uncalibrated")
        if top_vote and top_vote["label"] == category:
            bits.append(f"{top_vote['share']:.0%} of attack-type trees agree")
        if bits:
            head += f" ({'; '.join(bits)})"
    clauses = []
    flows, sources = context.get("flows"), context.get("top_source")
    ports, span = context.get("distinct_destination_ports"), context.get("span_seconds")
    if flows:
        clause = f"{flows:,} flow{'s' if flows != 1 else ''}"
        if sources:
            clause += f", mostly from {sources}"
        if ports and ports > 1:
            clause += f", reached {ports:,} distinct destination ports"
        if span is not None:
            clause += f" within {_duration(span)}"
        clauses.append(clause)
    if deviation is not None:
        if deviation.ratio is not None and deviation.ratio > 0:
            clauses.append(f"the typical flagged flow's {pretty(deviation.feature)} is {_times(deviation.ratio)} the "
                           "benign median")
        else:
            direction = "above" if deviation.robust_z > 0 else "below"
            clauses.append(f"the typical flagged flow's {pretty(deviation.feature)} is far {direction} the benign "
                           f"median ({deviation.flagged_median:,.4g} vs {deviation.benign_median:,.4g})")
    return head + (": " + "; ".join(clauses) if clauses else "") + "."


def _duration(seconds: float) -> str:
    if seconds < 1:
        return "under a second"
    if seconds < 120:
        return f"{seconds:,.0f} s"
    if seconds < 7200:
        return f"{seconds / 60:,.0f} min"
    return f"{seconds / 3600:,.1f} h"


def flow_context(flows: pd.DataFrame) -> Dict[str, Any]:
    """Counts the summary sentence quotes, from the flagged flows (pure). Missing columns give no number."""
    context: Dict[str, Any] = {"flows": int(len(flows))}
    if flows.empty:
        return context
    if "src_ip" in flows.columns and flows["src_ip"].notna().any():
        top = flows["src_ip"].dropna().astype(str).value_counts()
        context["top_source"] = top.index[0] if len(top) == 1 or top.iloc[0] / top.sum() >= 0.5 else \
            f"{len(top):,} sources"
        context["distinct_sources"] = int(len(top))
    if "dst_port" in flows.columns and flows["dst_port"].notna().any():
        context["distinct_destination_ports"] = int(flows["dst_port"].dropna().nunique())
    if "timestamp" in flows.columns:
        times = pd.to_datetime(flows["timestamp"], errors="coerce", utc=True).dropna()
        if len(times) > 1:
            context["span_seconds"] = float((times.max() - times.min()).total_seconds())
    return context


# ------------------------------------------------------------------ data access

@lru_cache(maxsize=4)
def _dataset_frame(path: str, mtime_ns: int) -> pd.DataFrame:
    return load_dataset_frame(Path(path))


def _dataset(conn, session_id: Optional[int]) -> Optional[Dict[str, Any]]:
    if session_id is None:
        return None
    row = conn.execute("SELECT s.source_type, s.dataset_id, d.stored_path FROM monitoring_sessions s "
                       "LEFT JOIN datasets d ON d.id = s.dataset_id WHERE s.id = ?", (session_id,)).fetchone()
    return dict(row) if row else None


def _member_flows(conn, alert: alert_service.Alert) -> pd.DataFrame:
    """The alert's flagged flows: same session and category, inside the alert's network-time window."""
    rows = conn.execute(
        "SELECT timestamp, src_ip, dst_ip, dst_port, anomaly_score, feature_summary_json FROM network_flows "
        "WHERE session_id = ? AND intrusion_prediction = ? ORDER BY timestamp, id LIMIT ?",
        (alert.session_id, alert.category, MAX_SESSION_FLOWS)).fetchall()
    flows = pd.DataFrame([dict(r) for r in rows],
                         columns=["timestamp", "src_ip", "dst_ip", "dst_port", "anomaly_score", "feature_summary_json"])
    window = alert.evidence.get("time_window_utc")
    if isinstance(window, list) and len(window) == 2 and not flows.empty:
        # Compare parsed times: stored timestamps carry microseconds, so string comparison would be wrong.
        times = pd.to_datetime(flows["timestamp"], utc=True, format="ISO8601")
        start, end = pd.to_datetime(window[0], utc=True), pd.to_datetime(window[1], utc=True)
        flows = flows[(times >= start) & (times <= end)]
    return flows.head(MAX_MEMBER_FLOWS).reset_index(drop=True)


def _features_from_json(flows: pd.DataFrame) -> pd.DataFrame:
    records = []
    for text in flows.get("feature_summary_json", []):
        summary = json.loads(text) if text else {}
        records.append(summary.get("features") or {})
    return pd.DataFrame(records)


def _dataset_rows(flows: pd.DataFrame, alert: alert_service.Alert) -> List[int]:
    rows = []
    for text in flows.get("feature_summary_json", []):
        row = (json.loads(text) if text else {}).get("dataset_row")
        if isinstance(row, int):
            rows.append(row)
    return rows or [r for r in alert.evidence.get("example_rows", []) if isinstance(r, int)]


def explain_alert(principal: Principal, alert_id: int) -> Explanation:
    require_permission(principal, Permission.VIEW_ALERTS, action="alert.explain", details={"alert_id": alert_id})
    with database_service.session() as conn:
        row = alert_repository.get(conn, alert_id)
        if row is None:
            raise ExplainError("Alert not found.")
        alert = alert_service.Alert.from_row(row)
        if alert.alert_type not in ("security", "anomaly"):
            raise ExplainError("Explanations are for security and anomaly alerts. Congestion alerts come from "
                               "PredictNet forecasts and show their own evidence.")
        source = _dataset(conn, alert.session_id)
        flows = _member_flows(conn, alert) if alert.session_id is not None else pd.DataFrame()
        reference_flows = None
        if source and source["source_type"] == "live_capture":
            reference_flows = conn.execute(
                "SELECT feature_summary_json FROM network_flows WHERE session_id = ? AND intrusion_prediction IS NULL "
                "ORDER BY id DESC LIMIT ?", (alert.session_id, REFERENCE_ROWS)).fetchall()
    notes: List[str] = []

    classifier = detector = None
    model_record = None
    if alert.model_id is not None:
        try:
            model_record = model_registry_service.get_model(principal, alert.model_id)
            bundle = model_registry_service.load_bundle(model_record)
            if model_record.family == "intrusion_classifier":
                classifier = bundle
            elif model_record.family == "anomaly_detector":
                detector = bundle
        except model_registry_service.ModelRegistryError as exc:
            notes.append(f"The model that raised this alert cannot be loaded ({exc}), so model-based parts are "
                         "unavailable.")
    if detector is None:
        anomaly_record = model_registry_service.active_model(principal, "anomaly_detector")
        if anomaly_record is not None and alert.alert_type == "security":
            try:
                detector = model_registry_service.load_bundle(anomaly_record)
            except model_registry_service.ModelRegistryError:
                detector = None
    features = (classifier or detector or {}).get("feature_names", [])
    if not features:
        raise ExplainError("The model behind this alert is unavailable, so there is nothing to explain against.")

    # Flagged flows and the benign reference, as feature frames.
    member = pd.DataFrame()
    reference = pd.DataFrame()
    basis: Dict[str, str] = {}
    stored_path = source.get("stored_path") if source else None
    if stored_path and Path(stored_path).is_file() and source["source_type"] in ("dataset", "replay"):
        frame = _dataset_frame(stored_path, Path(stored_path).stat().st_mtime_ns)
        wanted = [r - 2 for r in _dataset_rows(flows, alert) if 0 <= r - 2 < len(frame)]
        member = frame.loc[wanted]
        labels = frame[LABEL_COLUMN].astype(str).map(clean_label) if LABEL_COLUMN in frame.columns else None
        if labels is not None:
            benign = frame[labels.str.upper().isin(BENIGN_LABELS)]
            reference = benign.iloc[:: max(1, len(benign) // REFERENCE_ROWS)][:REFERENCE_ROWS]
        basis["flagged"] = f"{len(member):,} flagged rows of the dataset file"
        basis["reference"] = f"{len(reference):,} BENIGN-labelled rows of the same dataset"
        if flows.empty and member.shape[0]:
            notes.append("This alert came from a dataset detection run, which keeps only the first example rows, "
                         "so the explanation uses those examples.")
    elif not flows.empty:
        member = _features_from_json(flows)
        reference = _features_from_json(pd.DataFrame([dict(r) for r in (reference_flows or [])],
                                                     columns=["feature_summary_json"]))
        basis["flagged"] = f"{len(member):,} stored flows of this alert"
        basis["reference"] = f"{len(reference):,} flows of the same capture that the classifier did not flag"
    if member.empty:
        raise ExplainError("The flows behind this alert are no longer stored (or its dataset file is gone), so it "
                           "cannot be explained.")
    present = [f for f in features if f in member.columns]
    if len(present) < len(features):
        notes.append(f"{len(features) - len(present)} model feature(s) are not stored for these flows and are left out.")

    importances: Dict[str, float] = {}
    if classifier is not None:
        forest = classifier["model"].named_steps.get("model") if hasattr(classifier["model"], "named_steps") else None
        if forest is not None and hasattr(forest, "feature_importances_"):
            importances = {f: float(v) for f, v in zip(classifier["feature_names"], forest.feature_importances_)}
    deviations = robust_deviations(member, reference, present, importances) if not reference.empty else []
    if reference.empty:
        notes.append("No benign reference flows are available, so per-flow deviations cannot be computed.")

    model_score = None
    score_threshold = None
    type_votes: List[Dict[str, Any]] = []
    if classifier is not None and len(present) == len(classifier["feature_names"]):
        x = numeric_feature_frame(member, classifier["feature_names"])
        model_score = float(np.median(classifier["model"].predict_proba(x)[:, 1]))
        score_threshold = float(classifier["score_threshold"])
        attack_model = classifier.get("attack_type_model")
        if attack_model is not None and hasattr(attack_model, "predict_proba"):
            type_votes = vote_shares(attack_model.predict_proba(x), list(attack_model.classes_))
    elif alert.evidence.get("model_score_uncalibrated", {}).get("median") is not None and alert.alert_type == "security":
        model_score = float(alert.evidence["model_score_uncalibrated"]["median"])

    anomaly = None
    if detector is not None and all(f in member.columns for f in detector["feature_names"]):
        member_scores = detector["model"].score_samples(numeric_feature_frame(member, detector["feature_names"]))
        reference_scores = (detector["model"].score_samples(numeric_feature_frame(reference, detector["feature_names"]))
                            if not reference.empty and all(f in reference.columns for f in detector["feature_names"])
                            else np.array([]))
        pool = np.concatenate([member_scores, reference_scores, [detector["threshold"]]])
        score = float(np.median(member_scores))
        anomaly = {"score": score, "threshold": float(detector["threshold"]),
                   "benign_median": float(np.median(reference_scores)) if reference_scores.size else None,
                   "position": anomaly_position(score, float(detector["threshold"]), float(pool.min()),
                                                float(pool.max())),
                   "below_threshold_share": float((member_scores < detector["threshold"]).mean())}

    context = flow_context(flows) if not flows.empty else {"flows": int(alert.evidence.get("flows", len(member)))}
    if flows.empty:
        window = alert.evidence.get("time_window_utc")
        if isinstance(window, list) and len(window) == 2:
            span = pd.to_datetime(window[1], utc=True) - pd.to_datetime(window[0], utc=True)
            context["span_seconds"] = float(span.total_seconds())
        tops = alert.evidence.get("top_sources") or []
        if tops:
            context["top_source"] = tops[0]["value"]
    summary = summary_sentence(alert.category, alert.alert_type, model_score, type_votes[0] if type_votes else None,
                               deviations[0] if deviations else None, context)
    return Explanation(
        alert_id=alert.id, category=alert.category, alert_type=alert.alert_type, model_version=alert.model_version,
        model_score=model_score, score_threshold=score_threshold, type_votes=type_votes,
        importances=[{"feature": f, "importance": v} for f, v in
                     sorted(importances.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_IMPORTANCES]],
        deviations=deviations, anomaly=anomaly, context=context, summary=summary, basis=basis,
        flows_used=int(len(member)), reference_rows=int(len(reference)), notes=notes)
