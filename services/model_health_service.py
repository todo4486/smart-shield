"""Model health: one card per registered model, and a read-only drift check for intrusion models.

* Cards only show what the registry stored at training time: data, split, metrics, and whether the artifact's
  SHA-256 still matches (model_registry_service.is_verified). Nothing is recomputed.
* Drift compares recent feature values with the distributions stored from the model's TRAINING split
  (services/drift.py). Recent values come from either
    - a monitoring session whose flows store their features (live capture, replay), or
    - a registered dataset file.
  Dataset-detection sessions do not store features per flow, so they are not offered.
* Models trained before distributions were stored report drift as unavailable until they are retrained.
  This check never retrains, re-activates or changes a model.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from repositories import dataset_repository
from services import database_service, drift, model_registry_service, settings_service
from services.authorization import Permission, Principal, require_permission
from services.intrusion_features import load_dataset_frame
from services.model_registry_service import ModelRecord

MAX_RECENT_ROWS = 20_000
INTRUSION_FAMILIES = ("intrusion_classifier", "anomaly_detector")


class HealthError(Exception):
    pass


@dataclass
class ModelCard:
    id: int
    family: str
    name: str
    version: str
    trained_at: str
    active: bool
    verified: bool
    trained_on: List[str]
    split: Optional[str]
    split_sizes: Dict[str, int]
    metrics: Dict[str, Any]  # family-specific headline metrics, straight from the registry
    confusion_matrix: Optional[Dict[str, int]]
    drift_ready: bool
    notes: List[str] = field(default_factory=list)


@dataclass
class FeatureDrift:
    feature: str
    psi: Optional[float]
    level: str
    importance: Optional[float]
    expected: List[float]
    actual: List[float]
    edges: List[float]
    rows: int


@dataclass
class DriftReport:
    model_id: int
    source: str
    rows: int
    threshold: float
    features: List[FeatureDrift]
    overall: str  # worst level among the checked features
    notes: List[str] = field(default_factory=list)


def _trained_on(meta: Dict[str, Any]) -> List[str]:
    names = [d.get("name", f"dataset #{d.get('id')}") for d in meta.get("datasets", [])]
    if not names and meta.get("session_id"):
        names = [f"telemetry session #{meta['session_id']}" + (f" ({meta['interface_name']})"
                                                               if meta.get("interface_name") else "")]
    return names


def card_for(record: ModelRecord, verified: bool) -> ModelCard:
    """Headline facts for one registered model (pure, given the verification result)."""
    meta, metrics = record.training_metadata, record.metrics
    split = meta.get("split") or ("chronological" if meta.get("split_periods") else None)
    notes: List[str] = []
    headline: Dict[str, Any] = {}
    matrix = None
    if record.family == "intrusion_classifier":
        test = metrics.get("test") or {}
        headline = {k: test.get(k) for k in ("precision", "recall", "f1", "false_positive_rate", "roc_auc")}
        matrix = test.get("confusion_matrix")
        notes.append(metrics.get("score_note") or "Scores are uncalibrated.")
    elif record.family == "anomaly_detector":
        test = metrics.get("test") or {}
        headline = {k: test.get(k) for k in ("precision", "recall", "f1", "false_positive_rate")}
        headline["threshold"] = metrics.get("threshold")
        matrix = test.get("confusion_matrix")
        if metrics.get("threshold_note"):
            notes.append(metrics["threshold_note"])
    elif record.family == "congestion_forecaster":
        summary = metrics.get("summary") or {}
        for label in sorted(summary, key=lambda k: int("".join(ch for ch in k if ch.isdigit()) or 0)):
            headline[f"{label} MAE"] = summary[label].get("test", {}).get("mae")
            headline[f"{label} baseline MAE"] = summary[label].get("best_baseline_test", {}).get("mae")
        notes.append("Forecaster drift is not checked here: its inputs are the link's own recent history.")
    else:
        test = metrics.get("test") or {}
        headline = {k: v for k, v in test.items() if isinstance(v, (int, float))}
    if split == "stratified_random":
        notes.append("Trained with a stratified random split (no usable timestamps), not a chronological one.")
    ready = record.family in INTRUSION_FAMILIES and bool(meta.get("feature_distributions"))
    if record.family in INTRUSION_FAMILIES and not ready:
        notes.append("Drift check unavailable: this model was trained before training distributions were stored. "
                     "Retrain it to enable the check (nothing is retrained automatically).")
    return ModelCard(record.id, record.family, record.name, record.version, record.trained_at, record.is_active,
                     verified, _trained_on(meta), split, meta.get("split_sizes") or {}, headline, matrix, ready, notes)


def model_cards(principal: Principal) -> List[ModelCard]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="model_health.view")
    return [card_for(r, model_registry_service.is_verified(r)) for r in model_registry_service.list_models(principal)]


def drift_sources(principal: Principal) -> List[Dict[str, Any]]:
    """Recent-data sources that carry model features: sessions with stored flow features, and datasets."""
    require_permission(principal, Permission.VIEW_DASHBOARD, action="model_health.view")
    with database_service.session() as conn:
        sessions = conn.execute(
            "SELECT s.id, s.source_type, s.started_at, COUNT(f.id) AS flows FROM monitoring_sessions s "
            "JOIN network_flows f ON f.session_id = s.id WHERE s.source_type IN ('live_capture', 'replay') "
            "AND f.feature_summary_json LIKE '%\"features\"%' GROUP BY s.id ORDER BY s.id DESC LIMIT 50").fetchall()
        datasets = conn.execute("SELECT id, name, row_count FROM datasets WHERE kind = 'intrusion_flows' "
                                "ORDER BY id DESC").fetchall()
    out = [{"kind": "session", "id": r["id"], "label": f"Session #{r['id']} · "
            f"{'DATASET REPLAY' if r['source_type'] == 'replay' else 'live capture'} · {r['flows']:,} flows"}
           for r in sessions]
    out += [{"kind": "dataset", "id": r["id"], "label": f"Dataset #{r['id']} · {r['name']} · {r['row_count']:,} rows"}
            for r in datasets]
    return out


def _recent_frame(kind: str, source_id: int) -> pd.DataFrame:
    if kind == "session":
        with database_service.session() as conn:
            rows = conn.execute("SELECT feature_summary_json FROM network_flows WHERE session_id = ? "
                                "ORDER BY timestamp DESC, id DESC LIMIT ?", (source_id, MAX_RECENT_ROWS)).fetchall()
        return pd.DataFrame([(json.loads(r[0]) if r[0] else {}).get("features") or {} for r in rows])
    if kind == "dataset":
        with database_service.session() as conn:
            row = dataset_repository.get(conn, source_id)
        if row is None or not row["stored_path"] or not Path(row["stored_path"]).is_file():
            raise HealthError("The dataset's stored file is missing.")
        return load_dataset_frame(Path(row["stored_path"]), max_rows=MAX_RECENT_ROWS)
    raise HealthError("Unknown data source.")


def check_drift(principal: Principal, model_id: int, kind: str, source_id: int) -> DriftReport:
    """PSI per top feature for one intrusion model against one recent-data source. Read-only."""
    require_permission(principal, Permission.VIEW_DASHBOARD, action="model_health.drift",
                       details={"model_id": model_id, "source": f"{kind}:{source_id}"})
    record = model_registry_service.get_model(principal, model_id)
    references = record.training_metadata.get("feature_distributions") or {}
    if record.family not in INTRUSION_FAMILIES:
        raise HealthError("Drift is checked for intrusion models only.")
    if not references:
        raise HealthError("This model has no stored training distributions. Retrain it to enable the drift check.")
    settings = settings_service.get_drift_settings()
    importance = {}
    classifier = record if record.family == "intrusion_classifier" else next(
        (m for m in model_registry_service.list_models(principal, "intrusion_classifier")
         if m.version == record.version), None)
    if classifier is not None:
        importance = {i["feature"]: float(i["importance"]) for i in classifier.metrics.get("feature_importance", [])}
    ranked = sorted(references, key=lambda f: (-importance.get(f, -1.0), f))[:settings.top_features]
    recent = _recent_frame(kind, source_id)
    notes: List[str] = []
    if len(recent) < drift.MIN_ROWS:
        raise HealthError(f"Only {len(recent):,} recent rows; at least {drift.MIN_ROWS} are needed for a "
                          "meaningful drift check.")
    if kind == "session":
        notes.append("Recent values are the features stored with each flow of this session (newest "
                     f"{MAX_RECENT_ROWS:,}).")
    else:
        notes.append(f"Recent values are the first {MAX_RECENT_ROWS:,} rows of the dataset file.")
    results = []
    for name in ranked:
        reference = references[name]
        if name not in recent.columns:
            results.append(FeatureDrift(name, None, "unavailable", importance.get(name), reference["proportions"],
                                        [], reference["edges"], 0))
            continue
        value = drift.feature_psi(recent[name], reference)
        actual = drift.actual_distribution(recent[name], reference)
        results.append(FeatureDrift(name, value, drift.level(value, settings.psi_threshold), importance.get(name),
                                    list(reference["proportions"]) + [reference["missing"]],
                                    actual["proportions"] + [actual["missing"]], reference["edges"], actual["rows"]))
    missing = [r.feature for r in results if r.level == "unavailable"]
    if missing:
        notes.append(f"{len(missing)} feature(s) are not present in this source and were not checked: "
                     + ", ".join(missing[:5]) + ".")
    order = ["unavailable", "stable", "moderate", "drift"]
    overall = max((r.level for r in results if r.level != "unavailable"), key=order.index, default="unavailable")
    return DriftReport(record.id, f"{kind} #{source_id}", int(len(recent)), settings.psi_threshold, results, overall,
                       notes)
