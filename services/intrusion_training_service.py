"""Smart Shield training: Random Forest intrusion classifier + Isolation Forest
anomaly detector (+ optional multiclass attack-type model) on registered datasets.

Leakage controls
* Identifier and target-service columns are dropped (see intrusion_features).
* Train / validation / test are split before anything is fitted. Imputation
  medians, constant-column removal and every model are fit on TRAIN only.
* With timestamps the split is chronological; otherwise it is a stratified
  random split, and the report says so (rows from one capture can then appear
  in both train and test, so scores are optimistic).
* Isolation Forest is fit on benign training rows only; its threshold is set
  on benign VALIDATION rows for a target false-positive rate.

Model scores are not calibrated probabilities and are never shown as such.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from repositories import dataset_repository
from services import audit_service, database_service, drift, model_registry_service
from services.authorization import Permission, Principal, require_permission
from services.dataset_service import LABEL_COLUMN
from services.intrusion_features import (
    FEATURE_SETS, FeatureError, build_label_map, candidate_features, load_dataset_frame, numeric_feature_frame,
    schema_version,
)

RANDOM_STATE = 42
MAX_TRAINING_ROWS = 500_000
DEFAULT_TRAINING_ROWS = 200_000
RARE_CLASS_KEEP = 500  # rare attack types are kept in full up to this many rows when sampling
MIN_ROWS_PER_SPLIT_CLASS = 5
MIN_MULTICLASS_TRAIN_ROWS = 10
MAX_IFOREST_ROWS = 100_000

Progress = Callable[[str, float], None]


class TrainingError(Exception):
    """A user-facing training failure. Nothing was registered."""


@dataclass(frozen=True)
class IntrusionTrainingOptions:
    dataset_ids: tuple
    feature_set: str = "full"
    split_strategy: str = "auto"  # auto | time | stratified
    max_rows: int = DEFAULT_TRAINING_ROWS
    train_multiclass: bool = True
    n_estimators: int = 100
    anomaly_target_fpr: float = 0.01
    dayfirst: bool = True
    activate: bool = False

    def validate(self) -> None:
        if not self.dataset_ids:
            raise TrainingError("Choose at least one dataset.")
        if self.feature_set not in FEATURE_SETS:
            raise TrainingError("Unknown feature set.")
        if self.split_strategy not in ("auto", "time", "stratified"):
            raise TrainingError("Unknown split strategy.")
        if not 1_000 <= self.max_rows <= MAX_TRAINING_ROWS:
            raise TrainingError(f"Row limit must be between 1,000 and {MAX_TRAINING_ROWS:,}.")
        if not 10 <= self.n_estimators <= 500:
            raise TrainingError("Number of trees must be between 10 and 500.")
        if not 0.001 <= self.anomaly_target_fpr <= 0.2:
            raise TrainingError("Anomaly target false-positive rate must be between 0.1% and 20%.")


@dataclass
class IntrusionTrainingReport:
    classifier_model_id: int
    anomaly_model_id: int
    version: str
    classifier_metrics: Dict[str, Any]
    anomaly_metrics: Dict[str, Any]
    multiclass_metrics: Optional[Dict[str, Any]]
    metadata: Dict[str, Any]
    activated: bool = False
    warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------- metrics

def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: Optional[np.ndarray] = None) -> Dict[str, Any]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    result = {
        "precision": float(precision), "recall": float(recall), "f1": float(f1),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "accuracy": float((tp + tn) / len(y_true)) if len(y_true) else 0.0,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "support": {"benign": int(tn + fp), "attack": int(tp + fn)},
    }
    if scores is not None and len(np.unique(y_true)) == 2:
        result["roc_auc"] = float(roc_auc_score(y_true, scores))
    return result


def per_type_detection(types: pd.Series, y_pred: np.ndarray) -> Dict[str, Dict[str, float]]:
    """For each ground-truth type: rows and the share flagged as attack (= FPR for BENIGN)."""
    frame = pd.DataFrame({"type": types.to_numpy(), "flagged": y_pred})
    out = {}
    for name, group in frame.groupby("type"):
        out[str(name)] = {"rows": int(len(group)), "flagged_share": float(group["flagged"].mean())}
    return out


def multiclass_metrics(y_true: pd.Series, y_pred: np.ndarray, classes: List[str]) -> Dict[str, Any]:
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, zero_division=0
    )
    matrix = confusion_matrix(y_true, y_pred, labels=classes)
    macro = precision_recall_fscore_support(y_true, y_pred, labels=classes, average="macro", zero_division=0)
    return {
        "classes": classes,
        "per_class": {
            c: {"precision": float(p), "recall": float(r), "f1": float(f), "support": int(s)}
            for c, p, r, f, s in zip(classes, precision, recall, f1, support)
        },
        "macro_f1": float(macro[2]),
        "confusion_matrix": matrix.tolist(),
    }


# --------------------------------------------------------------- helpers

def _sample(frame: pd.DataFrame, max_rows: int) -> tuple:
    if len(frame) <= max_rows:
        return frame, None
    counts = frame["_type"].value_counts()
    rare = counts[counts <= RARE_CLASS_KEEP]
    kept_rare = frame[frame["_type"].isin(rare.index)]
    rest = frame[~frame["_type"].isin(rare.index)]
    budget = max(max_rows - len(kept_rare), 1)
    fraction = min(1.0, budget / max(len(rest), 1))
    sampled_rest = rest.groupby("_type", group_keys=False).apply(
        lambda g: g.sample(frac=fraction, random_state=RANDOM_STATE)
    )
    sampled = pd.concat([kept_rare, sampled_rest]).sort_index()
    note = (f"Sampled {len(sampled):,} of {len(frame):,} rows: each common type at {fraction:.1%}, "
            f"rare types (≤ {RARE_CLASS_KEEP} rows) kept in full.")
    return sampled, note


def _split(frame: pd.DataFrame, strategy: str, dayfirst: bool) -> tuple:
    if strategy in ("auto", "time") and "timestamp" in frame.columns:
        ts = pd.to_datetime(frame["timestamp"].astype(str).str.strip(), errors="coerce", dayfirst=dayfirst)
        if ts.notna().mean() >= 0.99:
            ordered = frame.assign(_ts=ts).dropna(subset=["_ts"]).sort_values("_ts", kind="mergesort")
            n = len(ordered)
            a, b = int(n * 0.70), int(n * 0.85)
            parts = ordered.iloc[:a], ordered.iloc[a:b], ordered.iloc[b:]
            periods = {name: [str(p["_ts"].min()), str(p["_ts"].max())]
                       for name, p in zip(("train", "validation", "test"), parts)}
            return parts, "chronological", periods
        if strategy == "time":
            raise TrainingError("A time-based split needs parseable timestamps on at least 99% of rows.")
    if strategy == "time":
        raise TrainingError("A time-based split needs a Timestamp column in every selected dataset.")
    # Each of train / validation / test needs a few benign and attack rows; check before sklearn raises.
    smallest = int(frame["_y"].value_counts().min())
    if smallest < 3 * MIN_ROWS_PER_SPLIT_CLASS:
        kind = "attack" if frame["_y"].value_counts().idxmin() == 1 else "benign"
        raise TrainingError(f"Only {smallest} {kind} row(s) are available; at least {3 * MIN_ROWS_PER_SPLIT_CLASS} "
                            "are needed so training, validation and test each get some. Add more data.")
    stratify = frame["_type"]
    if stratify.value_counts().min() < 3:
        stratify = frame["_y"]
    try:
        train, rest = train_test_split(frame, test_size=0.30, random_state=RANDOM_STATE, stratify=stratify)
        rest_stratify = rest["_type"] if rest["_type"].value_counts().min() >= 2 else rest["_y"]
        validation, test = train_test_split(rest, test_size=0.50, random_state=RANDOM_STATE, stratify=rest_stratify)
    except ValueError as exc:  # sklearn: a class is too small to stratify
        raise TrainingError(f"The data could not be split into training, validation and test sets: {exc}") from exc
    return (train, validation, test), "stratified_random", None


def _class_counts(part: pd.DataFrame) -> Dict[str, int]:
    return {str(k): int(v) for k, v in part["_type"].value_counts().items()}


# ---------------------------------------------------------------- training

def train_intrusion_models(
    principal: Principal, options: IntrusionTrainingOptions, progress: Optional[Progress] = None
) -> IntrusionTrainingReport:
    require_permission(principal, Permission.TRAIN_MODELS, action="model.train_intrusion",
                       details={"dataset_ids": list(options.dataset_ids)})
    if options.activate:
        require_permission(principal, Permission.ACTIVATE_MODELS, action="model.activate")
    try:
        return _train(principal, options, progress or (lambda message, fraction: None))
    except (TrainingError, FeatureError) as exc:
        audit_service.record_standalone(
            user_id=principal.user_id, action="model.train_intrusion", outcome="failure",
            details={"dataset_ids": list(options.dataset_ids), "error": str(exc)[:300]},
        )
        if isinstance(exc, FeatureError):
            raise TrainingError(str(exc)) from exc
        raise


def _train(principal: Principal, options: IntrusionTrainingOptions, progress: Progress) -> IntrusionTrainingReport:
    started = time.monotonic()
    options.validate()
    warnings: List[str] = []

    progress("Loading datasets", 0.05)
    with database_service.session() as conn:
        rows = [dataset_repository.get(conn, int(i)) for i in options.dataset_ids]
    if any(r is None or r["kind"] != "intrusion_flows" for r in rows):
        raise TrainingError("Every selected dataset must be a registered intrusion dataset.")
    frames = []
    for row in rows:
        path = Path(row["stored_path"] or "")
        if not path.is_file():
            raise TrainingError(f"The stored file for dataset #{row['id']} is missing.")
        frame = load_dataset_frame(path)
        frame["_dataset_id"] = row["id"]
        frames.append(frame)
    common = set.intersection(*(set(f.columns) for f in frames))
    frame = pd.concat([f[[c for c in f.columns if c in common]] for f in frames], ignore_index=True)

    label_map = build_label_map(frame[LABEL_COLUMN])
    raw_labels = frame[LABEL_COLUMN].astype(str)
    frame["_y"] = raw_labels.map(label_map.binary).astype(int)
    frame["_type"] = raw_labels.map(label_map.attack_type)
    if frame["_y"].nunique() < 2:
        raise TrainingError("Training needs both benign and attack rows; the selected data has only one kind.")

    features, dropped = candidate_features(frame.drop(columns=["_y", "_type", "_dataset_id"]), options.feature_set)
    total_rows = len(frame)
    frame, sample_note = _sample(frame, options.max_rows)
    if sample_note:
        warnings.append(sample_note)

    progress("Splitting train / validation / test", 0.15)
    (train, validation, test), split_kind, periods = _split(frame, options.split_strategy, options.dayfirst)
    if split_kind == "stratified_random":
        warnings.append("No usable timestamps, so a stratified random split was used. Flows from the same capture "
                        "can appear in both training and test data, so test scores are likely optimistic.")
    for name, part in (("train", train), ("validation", validation), ("test", test)):
        if part["_y"].nunique() < 2 or part["_y"].value_counts().min() < MIN_ROWS_PER_SPLIT_CLASS:
            raise TrainingError(f"The {name} split does not contain enough benign and attack rows. "
                                "Add more data or use a stratified split.")

    x_train = numeric_feature_frame(train, features)
    constant = [c for c in features if x_train[c].nunique(dropna=True) <= 1]
    features = [c for c in features if c not in constant]
    for column in constant:
        dropped[column] = "constant in training data"
    if not features:
        raise TrainingError("Every candidate feature is constant in the training data.")
    x_train = x_train[features]
    x_val = numeric_feature_frame(validation, features)
    x_test = numeric_feature_frame(test, features)
    y_train, y_val, y_test = train["_y"].to_numpy(), validation["_y"].to_numpy(), test["_y"].to_numpy()

    # ------------------------------------------------ random forest (binary)
    progress("Training Random Forest classifier", 0.30)
    classifier = Pipeline([
        ("impute", SimpleImputer(strategy="median")),
        ("model", RandomForestClassifier(
            n_estimators=options.n_estimators, class_weight="balanced_subsample", n_jobs=-1,
            random_state=RANDOM_STATE, min_samples_leaf=1,
        )),
    ])
    classifier.fit(x_train, y_train)
    val_scores = classifier.predict_proba(x_val)[:, 1]
    test_scores = classifier.predict_proba(x_test)[:, 1]
    threshold = 0.5
    clf_val = binary_metrics(y_val, (val_scores >= threshold).astype(int), val_scores)
    clf_test = binary_metrics(y_test, (test_scores >= threshold).astype(int), test_scores)
    importances = classifier.named_steps["model"].feature_importances_
    top_features = sorted(zip(features, importances), key=lambda kv: -kv[1])[:20]
    classifier_metrics = {
        "validation": clf_val, "test": clf_test, "score_threshold": threshold,
        "per_type_test": per_type_detection(test["_type"], (test_scores >= threshold).astype(int)),
        "feature_importance": [{"feature": f, "importance": float(v)} for f, v in top_features],
        "score_note": "Scores are the share of trees voting 'attack'; they are not calibrated probabilities.",
    }

    # ------------------------------------------- multiclass (attack type)
    multiclass = None
    multiclass_model = None
    classes: List[str] = []
    if options.train_multiclass:
        progress("Training attack-type classifier", 0.50)
        counts = train["_type"].value_counts()
        classes = sorted(counts[counts >= MIN_MULTICLASS_TRAIN_ROWS].index.astype(str))
        excluded = sorted(set(counts.index.astype(str)) - set(classes))
        if len(classes) >= 3:
            keep = train["_type"].isin(classes).to_numpy()
            multiclass_model = Pipeline([
                ("impute", SimpleImputer(strategy="median")),
                ("model", RandomForestClassifier(
                    n_estimators=options.n_estimators, class_weight="balanced_subsample", n_jobs=-1,
                    random_state=RANDOM_STATE,
                )),
            ])
            multiclass_model.fit(x_train[keep], train["_type"][keep])
            test_keep = test["_type"].isin(classes).to_numpy()
            multiclass = multiclass_metrics(test["_type"][test_keep], multiclass_model.predict(x_test[test_keep]), classes)
            multiclass["excluded_rare_types"] = excluded
            if excluded:
                warnings.append("Attack types with fewer than "
                                f"{MIN_MULTICLASS_TRAIN_ROWS} training rows were left out of the attack-type model: "
                                + ", ".join(excluded))
        else:
            warnings.append("The attack-type model was skipped: fewer than 2 attack types have enough training rows.")

    # ------------------------------------------- isolation forest (benign)
    progress("Training Isolation Forest on benign traffic", 0.70)
    benign_train = x_train[y_train == 0]
    if len(benign_train) > MAX_IFOREST_ROWS:
        benign_train = benign_train.sample(MAX_IFOREST_ROWS, random_state=RANDOM_STATE)
    detector = Pipeline([
        ("impute", SimpleImputer(strategy="median")),
        ("model", IsolationForest(n_estimators=200, contamination="auto", random_state=RANDOM_STATE, n_jobs=-1)),
    ])
    detector.fit(benign_train)
    benign_val_scores = detector.score_samples(x_val[y_val == 0])
    anomaly_threshold = float(np.quantile(benign_val_scores, options.anomaly_target_fpr))
    test_anomaly_scores = detector.score_samples(x_test)
    anomaly_pred = (test_anomaly_scores < anomaly_threshold).astype(int)
    anomaly_metrics = {
        "test": binary_metrics(y_test, anomaly_pred, -test_anomaly_scores),
        "per_type_test": per_type_detection(test["_type"], anomaly_pred),
        "threshold": anomaly_threshold,
        "target_false_positive_rate": options.anomaly_target_fpr,
        "threshold_note": "Rows scoring below the threshold are anomalous. The threshold is the "
                          f"{options.anomaly_target_fpr:.1%} quantile of benign validation scores.",
        "benign_training_rows": int(len(benign_train)),
    }

    # ------------------------------------------------------ persist
    progress("Saving and registering models", 0.85)
    version = model_registry_service.new_version("intrusion")
    feature_version = schema_version(features)
    environment = model_registry_service.environment_info()
    metadata = {
        "datasets": [{"id": r["id"], "name": r["name"], "sha256": r["sha256"], "rows": r["row_count"]} for r in rows],
        "feature_set": options.feature_set, "feature_count": len(features), "feature_names": features,
        "dropped_columns": dropped, "label_map": label_map.as_dict(),
        "rows_available": total_rows, "rows_used": int(len(frame)), "sampling": sample_note,
        "split": split_kind, "split_periods": periods,
        "split_sizes": {"train": len(train), "validation": len(validation), "test": len(test)},
        "class_counts": {"train": _class_counts(train), "validation": _class_counts(validation),
                         "test": _class_counts(test)},
        "parameters": {"n_estimators": options.n_estimators, "class_weight": "balanced_subsample",
                       "random_state": RANDOM_STATE, "anomaly_target_fpr": options.anomaly_target_fpr},
        "environment": environment, "warnings": warnings,
        # For the Model health drift check (PSI). Taken from the training split only; it does not affect training.
        "feature_distributions": drift.training_distributions(x_train, features),
        "feature_distributions_note": f"Decile bins and shares of the training split ({len(x_train):,} rows).",
    }
    classifier_bundle = {
        "family": "intrusion_classifier", "model": classifier, "feature_names": features,
        "feature_set": options.feature_set, "label_map": label_map.as_dict(), "score_threshold": threshold,
        "attack_type_model": multiclass_model, "attack_type_classes": classes, "environment": environment,
    }
    anomaly_bundle = {
        "family": "anomaly_detector", "model": detector, "feature_names": features,
        "feature_set": options.feature_set, "threshold": anomaly_threshold, "environment": environment,
    }
    saved: List[Path] = []
    try:
        clf_path, clf_sha = model_registry_service.save_artifact(classifier_bundle, "intrusion_classifier", version)
        saved.append(clf_path)
        det_path, det_sha = model_registry_service.save_artifact(anomaly_bundle, "anomaly_detector", version)
        saved.append(det_path)
        metadata["training_seconds"] = round(time.monotonic() - started, 1)
        with database_service.session(write=True) as conn:
            clf_id = model_registry_service.register(
                conn, family="intrusion_classifier", name=f"random_forest_{options.feature_set}", version=version,
                artifact_path=clf_path, artifact_sha256=clf_sha, feature_schema_version=feature_version,
                metrics={**classifier_metrics, "multiclass": multiclass}, training_metadata=metadata,
                created_by=principal.user_id,
            )
            det_id = model_registry_service.register(
                conn, family="anomaly_detector", name=f"isolation_forest_{options.feature_set}", version=version,
                artifact_path=det_path, artifact_sha256=det_sha, feature_schema_version=feature_version,
                metrics=anomaly_metrics, training_metadata=metadata, created_by=principal.user_id,
            )
            audit_service.record(
                conn, user_id=principal.user_id, action="model.train_intrusion",
                details={"version": version, "classifier_model_id": clf_id, "anomaly_model_id": det_id,
                         "test_f1": clf_test["f1"], "test_fpr": clf_test["false_positive_rate"]},
            )
    except Exception as exc:
        for path in saved:
            model_registry_service.discard_artifact(path)
        raise TrainingError(f"Saving the models failed; nothing was registered: {exc}") from exc

    report = IntrusionTrainingReport(
        classifier_model_id=clf_id, anomaly_model_id=det_id, version=version,
        classifier_metrics=classifier_metrics, anomaly_metrics=anomaly_metrics, multiclass_metrics=multiclass,
        metadata=metadata, warnings=warnings,
    )
    if options.activate:
        progress("Activating models", 0.95)
        model_registry_service.activate(principal, clf_id)
        model_registry_service.activate(principal, det_id)
        report.activated = True
    progress("Done", 1.0)
    return report
