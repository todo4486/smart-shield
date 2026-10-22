"""Model registry and artifact integrity.

* Artifacts are joblib bundles written under SMART_SHIELD_ARTIFACT_DIR.
* An artifact is only ever loaded if it is registered, lives inside the
  artifact directory, and its SHA-256 matches the registry.
* Registration happens only after a training run fully succeeds, so a failed
  run can never replace the active model. Activation is a separate,
  admin-only step (one active model per family, enforced by the database).
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import sklearn

from config import get_settings
from repositories import model_repository
from services import audit_service, database_service
from services.authorization import Permission, Principal, require_permission
from services.timeutil import utc_now, utc_now_iso

FAMILIES = ("intrusion_classifier", "anomaly_detector", "congestion_forecaster", "congestion_classifier")
FAMILY_LABELS = {
    "intrusion_classifier": "Intrusion classifier (Smart Shield)",
    "anomaly_detector": "Anomaly detector (Smart Shield)",
    "congestion_forecaster": "Congestion forecaster (PredictNet)",
    "congestion_classifier": "Congestion classifier (PredictNet)",
}


class ModelRegistryError(Exception):
    pass


class ArtifactIntegrityError(ModelRegistryError):
    """The artifact is missing, outside the artifact directory, or its hash does not match."""


@dataclass(frozen=True)
class ModelRecord:
    id: int
    family: str
    name: str
    version: str
    artifact_path: str
    artifact_sha256: str
    feature_schema_version: str
    metrics: Dict[str, Any]
    training_metadata: Dict[str, Any]
    trained_at: str
    created_by_email: Optional[str]
    is_active: bool

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "ModelRecord":
        keys = row.keys()
        return cls(
            id=row["id"], family=row["model_family"], name=row["model_name"], version=row["version"],
            artifact_path=row["artifact_path"], artifact_sha256=row["artifact_sha256"],
            feature_schema_version=row["feature_schema_version"],
            metrics=json.loads(row["metrics_json"]) if row["metrics_json"] else {},
            training_metadata=json.loads(row["training_metadata_json"]) if row["training_metadata_json"] else {},
            trained_at=row["trained_at"],
            created_by_email=row["created_by_email"] if "created_by_email" in keys else None,
            is_active=bool(row["is_active"]),
        )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def new_version(family: str) -> str:
    return utc_now().strftime("%Y%m%d-%H%M%S-%f")[:-3]


def environment_info() -> Dict[str, str]:
    return {"python": platform.python_version(), "scikit_learn": sklearn.__version__, "joblib": joblib.__version__}


def save_artifact(bundle: Dict[str, Any], family: str, version: str) -> tuple:
    """Write the bundle atomically and return (path, sha256)."""
    if family not in FAMILIES:
        raise ModelRegistryError(f"Unknown model family {family!r}.")
    directory = get_settings().artifact_dir / family
    directory.mkdir(parents=True, exist_ok=True)
    final_path = directory / f"{version}.joblib"
    if final_path.exists():
        raise ModelRegistryError(f"An artifact for version {version} already exists.")
    fd, tmp_name = tempfile.mkstemp(dir=directory, suffix=".tmp")
    os.close(fd)
    try:
        joblib.dump(bundle, tmp_name, compress=3)
        os.replace(tmp_name, final_path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return final_path, sha256_file(final_path)


def discard_artifact(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def register(
    conn: sqlite3.Connection,
    *,
    family: str,
    name: str,
    version: str,
    artifact_path: Path,
    artifact_sha256: str,
    feature_schema_version: str,
    metrics: Dict[str, Any],
    training_metadata: Dict[str, Any],
    created_by: Optional[int],
) -> int:
    return model_repository.insert(conn, {
        "model_family": family, "model_name": name, "version": version,
        "artifact_path": str(artifact_path), "artifact_sha256": artifact_sha256,
        "feature_schema_version": feature_schema_version,
        "metrics_json": json.dumps(metrics, default=_json_default),
        "training_metadata_json": json.dumps(training_metadata, default=_json_default),
        "trained_at": utc_now_iso(), "created_by": created_by, "is_active": 0,
    })


def _json_default(value: Any) -> Any:
    try:
        import numpy as np

        if isinstance(value, np.generic):
            return value.item()
        if isinstance(value, np.ndarray):
            return value.tolist()
    except ImportError:  # pragma: no cover
        pass
    return str(value)


def _verified_path(record: ModelRecord) -> Path:
    artifact_root = get_settings().artifact_dir.resolve()
    path = Path(record.artifact_path).resolve()
    if artifact_root not in path.parents:
        raise ArtifactIntegrityError("Refusing to load an artifact outside the artifact directory.")
    if not path.is_file():
        raise ArtifactIntegrityError(f"The artifact file for {record.name} {record.version} is missing.")
    if sha256_file(path) != record.artifact_sha256:
        raise ArtifactIntegrityError(
            f"The artifact for {record.name} {record.version} does not match its registered SHA-256. It will not be loaded."
        )
    return path


def load_bundle(record: ModelRecord) -> Dict[str, Any]:
    """Load a registered, hash-verified artifact. Never call joblib.load on anything else."""
    bundle = joblib.load(_verified_path(record))
    if not isinstance(bundle, dict) or bundle.get("family") != record.family:
        raise ArtifactIntegrityError("The artifact does not contain a model of the registered family.")
    return bundle


def get_model(principal: Principal, model_id: int) -> ModelRecord:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="model.view")
    with database_service.session() as conn:
        row = model_repository.get(conn, model_id)
    if row is None:
        raise ModelRegistryError("Model not found.")
    return ModelRecord.from_row(row)


def active_model(principal: Principal, family: str) -> Optional[ModelRecord]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="model.view")
    with database_service.session() as conn:
        row = model_repository.active_for_family(conn, family)
    return ModelRecord.from_row(row) if row else None


def list_models(principal: Principal, family: Optional[str] = None) -> List[ModelRecord]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="model.list")
    with database_service.session() as conn:
        rows = model_repository.list_models(conn, family)
    return [ModelRecord.from_row(r) for r in rows]


def activate(principal: Principal, model_id: int) -> ModelRecord:
    """Validate the artifact (hash, family, loadable) and make it the family's active model."""
    require_permission(principal, Permission.ACTIVATE_MODELS, action="model.activate", details={"model_id": model_id})
    with database_service.session() as conn:
        row = model_repository.get(conn, model_id)
    if row is None:
        raise ModelRegistryError("Model not found.")
    record = ModelRecord.from_row(row)
    try:
        bundle = load_bundle(record)
        if not bundle.get("feature_names"):
            raise ArtifactIntegrityError("The artifact has no feature schema.")
    except Exception as exc:
        audit_service.record_standalone(
            user_id=principal.user_id, action="model.activate", outcome="failure",
            details={"model_id": model_id, "error": str(exc)[:300]},
        )
        if isinstance(exc, ModelRegistryError):
            raise
        raise ArtifactIntegrityError(f"The artifact could not be loaded: {exc}") from exc
    with database_service.session(write=True) as conn:
        previous = model_repository.active_for_family(conn, record.family)
        model_repository.deactivate_family(conn, record.family)
        model_repository.set_active(conn, model_id)
        audit_service.record(
            conn, user_id=principal.user_id, action="model.activate",
            details={"model_id": model_id, "family": record.family, "version": record.version,
                     "previous_model_id": previous["id"] if previous else None},
        )
    return get_model(principal, model_id)
