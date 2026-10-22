"""ML Laboratory — placeholder until Phases 3–4."""
from __future__ import annotations

from components.guard import require_principal
from components.ui import page_header, planned_notice

require_principal()

page_header("ML Laboratory", "Training, evaluation and the model registry.", eyebrow="Intelligence")
planned_notice(
    "Phases 3–4",
    "This page is not built yet",
    "Two independent workspaces — Smart Shield and PredictNet — for training models on uploaded data and reviewing honest evaluation results."
    " Nothing on this page is simulated in the meantime.",
    [
        "Dataset upload with schema validation",
        "Train/validation/test splits without leakage (chronological for time series)",
        "Precision, recall, F1, confusion matrix and false-positive rate",
        "Model registry with SHA-256-verified artifacts and one active model per family",
    ],
)
