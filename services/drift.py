"""Population Stability Index (PSI) for feature drift (pure functions).

Training stores, per feature, decile bin edges taken from the TRAINING split and the share of training rows in
each bin plus the share of missing values (reference_distribution). A drift check puts recent values into the
same bins and compares the shares:

    PSI = Σ (actual − expected) × ln(actual / expected)

over every bin, the missing-value bucket included. Shares of 0 are replaced by EPSILON so the sum stays finite.
Common reading (a rule of thumb, not a statistical test): < 0.10 stable, 0.10–0.25 moderate shift,
> 0.25 significant shift. The warning threshold is configurable in Settings.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

import numpy as np
import pandas as pd

BINS = 10
EPSILON = 1e-4
MIN_ROWS = 200
STABLE, MODERATE = 0.10, 0.25


def _clean(values) -> pd.Series:
    return pd.to_numeric(pd.Series(values), errors="coerce").replace([np.inf, -np.inf], np.nan)


def reference_distribution(values, bins: int = BINS) -> Dict[str, Any]:
    """Quantile bin edges and shares for one feature's training values."""
    series = _clean(values)
    present = series.dropna()
    missing = float(series.isna().mean()) if len(series) else 0.0
    if present.empty:
        return {"edges": [], "proportions": [], "missing": missing, "rows": int(len(series))}
    edges = sorted(set(float(q) for q in np.quantile(present, np.linspace(0, 1, bins + 1)[1:-1])))
    return {"edges": edges, "proportions": [float(p) * (1 - missing) for p in _shares(present, edges)],
            "missing": missing, "rows": int(len(series))}


def _shares(present: pd.Series, edges: Sequence[float]) -> List[float]:
    """Share of values per bin: (-inf, e0], (e0, e1], …, (e_last, inf)."""
    index = np.searchsorted(np.asarray(edges, dtype=float), present.to_numpy(dtype=float), side="left")
    counts = np.bincount(index, minlength=len(edges) + 1)
    return list(counts / max(1, counts.sum()))


def actual_distribution(values, reference: Dict[str, Any]) -> Dict[str, Any]:
    series = _clean(values)
    present = series.dropna()
    missing = float(series.isna().mean()) if len(series) else 0.0
    shares = _shares(present, reference["edges"]) if not present.empty else [0.0] * (len(reference["edges"]) + 1)
    return {"proportions": [float(p) * (1 - missing) for p in shares], "missing": missing, "rows": int(len(series))}


def psi(expected: Sequence[float], actual: Sequence[float], epsilon: float = EPSILON) -> float:
    e = np.maximum(np.asarray(expected, dtype=float), epsilon)
    a = np.maximum(np.asarray(actual, dtype=float), epsilon)
    return float(np.sum((a - e) * np.log(a / e)))


def feature_psi(values, reference: Dict[str, Any]) -> Optional[float]:
    """PSI of recent values against a stored reference; None if the reference has no bins."""
    if not reference.get("proportions"):
        return None
    actual = actual_distribution(values, reference)
    return psi(list(reference["proportions"]) + [reference["missing"]], actual["proportions"] + [actual["missing"]])


def level(value: Optional[float], threshold: float) -> str:
    """'unavailable', 'stable', 'moderate' or 'drift' (≥ the configured threshold)."""
    if value is None:
        return "unavailable"
    if value >= threshold:
        return "drift"
    return "stable" if value < min(STABLE, threshold) else "moderate"


def training_distributions(frame: pd.DataFrame, features: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    return {name: reference_distribution(frame[name]) for name in features if name in frame.columns}
