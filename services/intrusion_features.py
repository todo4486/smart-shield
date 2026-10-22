"""Smart Shield feature engineering shared by training and inference.

Everything here is deterministic and inspectable: the label map, the columns
that are dropped as identifiers or leakage, and the "live-compatible" feature
set that Phase 7's flow extractor will be able to compute from captured packets.
"""
from __future__ import annotations

import hashlib
import io
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from services.dataset_service import IDENTIFIER_COLUMNS, LABEL_COLUMN, unique_normalized_columns

BENIGN_LABELS = frozenset({"BENIGN", "NORMAL"})

# Dropped in addition to identifiers: they let a model memorise the capture
# environment (which service was targeted) instead of learning behaviour.
LEAKAGE_COLUMNS = ("destination_port", "dst_port")

# Features a live flow extractor can compute from packet headers alone, using
# the same definitions and units as CIC-IDS2017 (durations in microseconds).
LIVE_FLOW_FEATURES: Tuple[str, ...] = (
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "total_length_of_fwd_packets",
    "total_length_of_bwd_packets",
    "fwd_packet_length_max",
    "fwd_packet_length_min",
    "fwd_packet_length_mean",
    "bwd_packet_length_max",
    "bwd_packet_length_min",
    "bwd_packet_length_mean",
    "flow_bytes_s",
    "flow_packets_s",
    "flow_iat_mean",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_packets_s",
    "bwd_packets_s",
    "min_packet_length",
    "max_packet_length",
    "packet_length_mean",
)

FEATURE_SETS = {
    "full": "All numeric flow statistics in the dataset (best offline accuracy).",
    "live_compatible": "Only features a live flow extractor can compute from packet headers (usable in live monitoring).",
}


class FeatureError(ValueError):
    """The data cannot be used with the requested features or model."""


@dataclass
class LabelMap:
    """raw label -> binary (0 benign / 1 attack) and -> cleaned attack type."""

    binary: Dict[str, int] = field(default_factory=dict)
    attack_type: Dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Dict[str, object]]:
        return {raw: {"binary": self.binary[raw], "type": self.attack_type[raw]} for raw in sorted(self.binary)}


def clean_label(raw: str) -> str:
    text = str(raw).strip()
    # CIC-IDS2017 files contain mis-encoded dashes, e.g. "Web Attack � Brute Force".
    text = text.replace("�", "-").replace("–", "-")
    return re.sub(r"\s+", " ", text)


def build_label_map(labels: pd.Series) -> LabelMap:
    label_map = LabelMap()
    for raw in sorted(labels.astype(str).unique()):
        cleaned = clean_label(raw)
        is_benign = cleaned.upper() in BENIGN_LABELS
        label_map.binary[raw] = 0 if is_benign else 1
        label_map.attack_type[raw] = "BENIGN" if is_benign else cleaned
    return label_map


def load_dataset_frame(path: Path, max_rows: Optional[int] = None) -> pd.DataFrame:
    """Read a registered CSV with normalized, de-duplicated column names."""
    frame = pd.read_csv(path, low_memory=False, encoding_errors="replace", nrows=max_rows)
    frame.columns = list(unique_normalized_columns([str(c) for c in frame.columns]).values())
    if LABEL_COLUMN not in frame.columns:
        raise FeatureError(f"{path.name} has no label column.")
    return frame


def numeric_feature_frame(frame: pd.DataFrame, feature_names: List[str]) -> pd.DataFrame:
    """Select features as float, converting +/-inf to NaN (imputed later from training medians)."""
    missing = [name for name in feature_names if name not in frame.columns]
    if missing:
        raise FeatureError(f"Missing {len(missing)} required feature(s): {', '.join(missing[:10])}"
                           + ("…" if len(missing) > 10 else ""))
    features = frame[feature_names].apply(pd.to_numeric, errors="coerce").astype("float64")
    return features.replace([np.inf, -np.inf], np.nan)


def candidate_features(frame: pd.DataFrame, feature_set: str) -> Tuple[List[str], Dict[str, str]]:
    """Return (features, dropped column -> reason). Constant columns are removed later, on train only."""
    if feature_set not in FEATURE_SETS:
        raise FeatureError(f"Unknown feature set {feature_set!r}.")
    dropped: Dict[str, str] = {}
    features: List[str] = []
    for column in frame.columns:
        if column == LABEL_COLUMN:
            continue
        if column in IDENTIFIER_COLUMNS:
            dropped[column] = "identifier"
            continue
        if column in LEAKAGE_COLUMNS:
            dropped[column] = "leakage risk (target service)"
            continue
        values = pd.to_numeric(frame[column], errors="coerce")
        if values.notna().mean() < 0.5:
            dropped[column] = "not numeric"
            continue
        if feature_set == "live_compatible" and column not in LIVE_FLOW_FEATURES:
            dropped[column] = "not computable from live packet headers"
            continue
        features.append(column)
    if feature_set == "live_compatible":
        absent = [f for f in LIVE_FLOW_FEATURES if f not in frame.columns]
        if absent:
            raise FeatureError("This dataset lacks live-compatible features: " + ", ".join(absent[:8])
                               + ("…" if len(absent) > 8 else ""))
    if not features:
        raise FeatureError("No usable numeric features were found.")
    return features, dropped


def schema_version(feature_names: List[str]) -> str:
    return hashlib.sha256("\n".join(feature_names).encode()).hexdigest()[:16]


@dataclass
class CompatibilityReport:
    compatible: bool
    required: int
    present: int
    missing: List[str]
    extra: int
    message: str


def compatibility(columns: List[str], feature_names: List[str]) -> CompatibilityReport:
    """A model is only usable when every feature it was trained on is present. Missing features are never zero-filled."""
    available = set(columns)
    missing = [f for f in feature_names if f not in available]
    extra = len(available - set(feature_names) - {LABEL_COLUMN})
    if missing:
        message = (f"REJECTED: {len(missing)} of {len(feature_names)} model features are missing from this data. "
                   "Missing features are never filled with zeros.")
    else:
        message = f"Compatible: all {len(feature_names)} model features are present."
    return CompatibilityReport(not missing, len(feature_names), len(feature_names) - len(missing), missing, extra, message)


def header_columns(path: Path) -> List[str]:
    with open(path, "rb") as handle:
        header = handle.readline()
    columns = pd.read_csv(io.BytesIO(header), nrows=0, encoding_errors="replace").columns
    return list(unique_normalized_columns([str(c) for c in columns]).values())
