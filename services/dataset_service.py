"""Labelled intrusion datasets (CIC-IDS2017 style): registration and profiling.

Registering a dataset stores the original CSV (named by its SHA-256) and a
profile: normalized column names, label distribution, inf/NaN counts and the
identifier/leakage columns that Phase 3 training will drop. Nothing is
modified in the file itself.

Optionally, rows that carry a real timestamp are copied into the shared
network_flows table (5-tuple, packets, bytes, duration). The dataset's label is
ground truth and is stored as `dataset_label` in feature_summary_json — never
as a model prediction.
"""
from __future__ import annotations

import hashlib
import io
import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from config import get_settings
from repositories import dataset_repository, flow_repository, monitoring_repository
from services import audit_service, database_service, monitoring_service
from services.authorization import Permission, Principal, require_permission
from services.monitoring_service import SessionState, SourceType
from services.telemetry_schema import normalize_column_name
from services.timeutil import utc_now_iso

MAX_DATASET_BYTES = 512 * 1024 * 1024
MAX_FLOW_IMPORT_ROWS = 200_000
PROFILE_CHUNK_ROWS = 100_000
FLOW_INSERT_BATCH = 20_000

LABEL_COLUMN = "label"

# Columns that identify a specific host/flow/time rather than behaviour. Training
# on them leaks capture-specific information, so Phase 3 drops them.
IDENTIFIER_COLUMNS = (
    "flow_id", "source_ip", "src_ip", "destination_ip", "dst_ip",
    "source_port", "src_port", "timestamp",
)

FLOW_FIELD_ALIASES = {
    "src_ip": ("source_ip", "src_ip"),
    "dst_ip": ("destination_ip", "dst_ip"),
    "src_port": ("source_port", "src_port"),
    "dst_port": ("destination_port", "dst_port"),
    "protocol": ("protocol",),
    "timestamp": ("timestamp",),
    "duration_us": ("flow_duration",),
    "fwd_packets": ("total_fwd_packets", "tot_fwd_pkts"),
    "bwd_packets": ("total_backward_packets", "tot_bwd_pkts"),
    "fwd_bytes": ("total_length_of_fwd_packets", "totlen_fwd_pkts"),
    "bwd_bytes": ("total_length_of_bwd_packets", "totlen_bwd_pkts"),
}

PROTOCOL_NAMES = {0: "HOPOPT", 1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


class DatasetError(Exception):
    """A user-facing dataset failure. Nothing was stored."""


@dataclass(frozen=True)
class FlowImportOptions:
    enabled: bool = False
    dayfirst: bool = True  # CIC-IDS2017 writes 3/7/2017 for 3 July 2017
    utc_offset_hours: float = 0.0  # offset of the naive timestamps in the file
    max_rows: int = MAX_FLOW_IMPORT_ROWS


@dataclass
class DatasetReport:
    dataset_id: int
    name: str
    filename: str
    sha256: str
    size_bytes: int
    row_count: int
    columns: List[str]
    renamed_columns: Dict[str, str]
    label_distribution: Dict[str, int]
    numeric_columns: int
    infinite_values: Dict[str, int]
    missing_values: Dict[str, int]
    identifier_columns: List[str]
    has_timestamps: bool
    flow_session_id: Optional[int] = None
    flows_imported: int = 0
    flows_skipped: Dict[str, int] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class DatasetSummary:
    id: int
    name: str
    kind: str
    original_filename: str
    size_bytes: int
    row_count: int
    column_count: int
    label_distribution: Dict[str, int]
    has_timestamps: bool
    uploaded_at: str
    uploaded_by_email: Optional[str]
    profile: Dict[str, Any]


# --------------------------------------------------------------- helpers

def unique_normalized_columns(columns: List[str]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    used: Dict[str, int] = {}
    for original in columns:
        base = normalize_column_name(original) or "column"
        # pandas renames repeated headers "X" -> "X.1"; normalize gives "x_1".
        name = base
        while name in used:
            used[base] += 1
            name = f"{base}_{used[base]}"
        used.setdefault(name, 0)
        mapping[original] = name
    return mapping


def _resolve(columns: List[str], aliases: tuple) -> Optional[str]:
    for alias in aliases:
        if alias in columns:
            return alias
    return None


def _flow_rows(chunk: pd.DataFrame, fields: Dict[str, Optional[str]], options: FlowImportOptions,
               session_id: int, skipped: Dict[str, int]) -> List[tuple]:
    ts_raw = chunk[fields["timestamp"]].astype(str).str.strip()
    parsed = pd.to_datetime(ts_raw.where(ts_raw != ""), errors="coerce", dayfirst=options.dayfirst)
    if getattr(parsed.dt, "tz", None) is None:
        parsed = (parsed - pd.Timedelta(hours=options.utc_offset_hours)).dt.tz_localize("UTC")
    else:
        parsed = parsed.dt.tz_convert("UTC")
    bad_ts = parsed.isna()
    if bad_ts.any():
        skipped["unparseable timestamp"] = skipped.get("unparseable timestamp", 0) + int(bad_ts.sum())

    def numeric(key: str) -> pd.Series:
        column = fields.get(key)
        if column is None:
            return pd.Series(np.nan, index=chunk.index)
        values = pd.to_numeric(chunk[column], errors="coerce")
        return values.where(np.isfinite(values))

    def port(key: str) -> pd.Series:
        values = numeric(key)
        return values.where((values >= 0) & (values <= 65535))

    packets = numeric("fwd_packets") + numeric("bwd_packets")
    byte_count = numeric("fwd_bytes") + numeric("bwd_bytes")
    duration = numeric("duration_us") / 1_000_000.0
    protocol_num = numeric("protocol")
    labels = chunk[LABEL_COLUMN].astype(str).str.strip()

    rows = []
    for idx in chunk.index[~bad_ts]:
        proto = protocol_num.at[idx]
        proto_name = None if pd.isna(proto) else PROTOCOL_NAMES.get(int(proto), str(int(proto)))
        rows.append((
            session_id,
            parsed.at[idx].isoformat(timespec="microseconds"),
            _text(chunk, fields.get("src_ip"), idx),
            _text(chunk, fields.get("dst_ip"), idx),
            _int_or_none(port("src_port").at[idx]),
            _int_or_none(port("dst_port").at[idx]),
            proto_name,
            _int_or_none(packets.at[idx] if packets.at[idx] >= 0 else np.nan),
            _int_or_none(byte_count.at[idx] if byte_count.at[idx] >= 0 else np.nan),
            None if pd.isna(duration.at[idx]) or duration.at[idx] < 0 else float(duration.at[idx]),
            json.dumps({"dataset_label": labels.at[idx]}),
            "measured",
        ))
    return rows


def _text(chunk: pd.DataFrame, column: Optional[str], idx: Any) -> Optional[str]:
    if column is None:
        return None
    value = str(chunk.at[idx, column]).strip()
    return value[:64] or None


def _int_or_none(value: Any) -> Optional[int]:
    if value is None or (isinstance(value, float) and math.isnan(value)) or pd.isna(value):
        return None
    return int(value)


# ---------------------------------------------------------- registration

def register_intrusion_dataset(
    principal: Principal,
    data: bytes,
    filename: str,
    name: str,
    flow_options: FlowImportOptions = FlowImportOptions(),
) -> DatasetReport:
    require_permission(principal, Permission.MANAGE_DATASETS, action="dataset.register",
                       details={"filename": filename})
    try:
        return _register(principal, data, filename, name, flow_options)
    except DatasetError as exc:
        audit_service.record_standalone(
            user_id=principal.user_id, action="dataset.register", outcome="failure",
            details={"filename": filename, "error": str(exc)[:300]},
        )
        raise


def _register(principal: Principal, data: bytes, filename: str, name: str,
              flow_options: FlowImportOptions) -> DatasetReport:
    filename = Path(filename or "dataset.csv").name[:255]
    name = (name or "").strip() or Path(filename).stem
    if len(name) > 200:
        raise DatasetError("Dataset name must be at most 200 characters.")
    if not data:
        raise DatasetError("The file is empty.")
    if len(data) > MAX_DATASET_BYTES:
        raise DatasetError(f"The file is larger than {MAX_DATASET_BYTES // (1024 * 1024)} MB.")
    if not 1 <= flow_options.max_rows <= MAX_FLOW_IMPORT_ROWS:
        raise DatasetError(f"Flow import limit must be between 1 and {MAX_FLOW_IMPORT_ROWS:,}.")
    if not -14 <= flow_options.utc_offset_hours <= 14:
        raise DatasetError("UTC offset must be between -14 and +14 hours.")
    sha256 = hashlib.sha256(data).hexdigest()
    with database_service.session() as conn:
        existing = dataset_repository.find_by_sha(conn, "intrusion_flows", sha256)
    if existing is not None:
        raise DatasetError(f"This exact file is already registered (dataset #{existing['id']}, '{existing['name']}').")

    try:
        reader = pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False, chunksize=PROFILE_CHUNK_ROWS,
                             encoding_errors="replace", low_memory=False)
        first = next(reader)
    except StopIteration as exc:
        raise DatasetError("The file has no data rows.") from exc
    except pd.errors.EmptyDataError as exc:
        raise DatasetError("The file is empty.") from exc
    except (pd.errors.ParserError, UnicodeDecodeError, ValueError) as exc:
        raise DatasetError(f"The file could not be read as CSV: {exc}") from exc

    original_columns = [str(c) for c in first.columns]
    mapping = unique_normalized_columns(original_columns)
    columns = list(mapping.values())
    if LABEL_COLUMN not in columns:
        raise DatasetError("No 'Label' column found. Intrusion datasets must be labelled (e.g. BENIGN, DDoS).")

    fields = {key: _resolve(columns, aliases) for key, aliases in FLOW_FIELD_ALIASES.items()}
    has_timestamps = fields["timestamp"] is not None
    warnings: List[str] = []
    import_flows = flow_options.enabled
    if import_flows and not has_timestamps:
        import_flows = False
        warnings.append("Flows were not imported: the file has no Timestamp column, so flows cannot be placed "
                        "on a timeline. The dataset is still registered for model training.")

    session_id: Optional[int] = None
    if import_flows:
        with database_service.session(write=True) as conn:
            session_id = monitoring_service.create_session(
                conn, user_id=principal.user_id, source_type=SourceType.DATASET,
                configuration={"filename": filename, "sha256": sha256, "flow_options": asdict(flow_options)},
            )

    label_counts: Dict[str, int] = {}
    infinite: Dict[str, int] = {}
    missing: Dict[str, int] = {}
    numeric_columns: set = set()
    row_count = 0
    flows: List[tuple] = []
    skipped: Dict[str, int] = {}
    truncated = False

    try:
        chunk: Optional[pd.DataFrame] = first
        while chunk is not None:
            chunk = chunk.rename(columns=mapping)
            row_count += len(chunk)
            labels = chunk[LABEL_COLUMN].astype(str).str.strip()
            for label, count in labels.value_counts().items():
                label_counts[label] = label_counts.get(label, 0) + int(count)
            for column in columns:
                if column == LABEL_COLUMN or column in IDENTIFIER_COLUMNS:
                    continue
                text = chunk[column].astype(str).str.strip()
                values = pd.to_numeric(text, errors="coerce")
                lowered = text.str.lower()
                inf_mask = lowered.isin(["inf", "+inf", "-inf", "infinity", "-infinity"]) | np.isinf(values.fillna(0))
                blank = text.isin(["", "nan", "NaN"])
                if values.notna().any() or inf_mask.any():
                    numeric_columns.add(column)
                if inf_mask.any():
                    infinite[column] = infinite.get(column, 0) + int(inf_mask.sum())
                if blank.any():
                    missing[column] = missing.get(column, 0) + int(blank.sum())
            if import_flows and len(flows) < flow_options.max_rows:
                remaining = flow_options.max_rows - len(flows)
                flows.extend(_flow_rows(chunk.head(remaining), fields, flow_options, session_id, skipped))
                if len(chunk) > remaining:
                    truncated = True
            elif import_flows:
                truncated = True
            chunk = next(reader, None)
    except (pd.errors.ParserError, UnicodeDecodeError, ValueError) as exc:
        if session_id is not None:
            monitoring_service.fail_session(session_id, f"Profiling failed: {exc}")
        raise DatasetError(f"The file could not be read as CSV: {exc}") from exc

    if len(label_counts) < 2:
        warnings.append("Only one label value is present. Training a classifier needs both benign and attack rows.")
    if truncated:
        warnings.append(f"Only the first {flow_options.max_rows:,} rows were imported as flows (limit). "
                        "The full file is registered for training.")
    identifier_cols = [c for c in columns if c in IDENTIFIER_COLUMNS]

    settings = get_settings()
    settings.dataset_dir.mkdir(parents=True, exist_ok=True)
    stored_path = settings.dataset_dir / f"{sha256}.csv"
    stored_path.write_bytes(data)

    report = DatasetReport(
        dataset_id=0, name=name, filename=filename, sha256=sha256, size_bytes=len(data), row_count=row_count,
        columns=columns, renamed_columns={o: n for o, n in mapping.items() if o != n},
        label_distribution=dict(sorted(label_counts.items(), key=lambda kv: -kv[1])),
        numeric_columns=len(numeric_columns), infinite_values=infinite, missing_values=missing,
        identifier_columns=identifier_cols, has_timestamps=has_timestamps, flow_session_id=session_id,
        flows_imported=len(flows), flows_skipped=skipped, warnings=warnings,
    )
    profile = {k: v for k, v in asdict(report).items() if k not in ("columns", "label_distribution")}

    try:
        with database_service.session(write=True) as conn:
            dataset_id = dataset_repository.insert(conn, {
                "name": name, "kind": "intrusion_flows", "original_filename": filename,
                "stored_path": str(stored_path), "sha256": sha256, "size_bytes": len(data),
                "row_count": row_count, "column_count": len(columns), "columns_json": json.dumps(columns),
                "label_column": LABEL_COLUMN, "label_distribution_json": json.dumps(report.label_distribution),
                "has_timestamps": 1 if has_timestamps else 0, "profile_json": json.dumps(profile, default=str),
                "uploaded_by": principal.user_id, "uploaded_at": utc_now_iso(),
            })
            report.dataset_id = dataset_id
            if session_id is not None:
                for start in range(0, len(flows), FLOW_INSERT_BATCH):
                    flow_repository.insert_many(conn, flows[start:start + FLOW_INSERT_BATCH])
                configuration = {"filename": filename, "sha256": sha256, "flow_options": asdict(flow_options),
                                 "dataset_id": dataset_id, "flows_imported": len(flows), "flows_skipped": skipped}
                monitoring_repository.update_configuration(conn, session_id, json.dumps(configuration, sort_keys=True),
                                                           None, dataset_id)
                monitoring_service.transition(conn, session_id, SessionState.STOPPED,
                                              f"Imported {len(flows):,} flows from {filename}")
            audit_service.record(
                conn, user_id=principal.user_id, action="dataset.register",
                details={"dataset_id": dataset_id, "filename": filename, "rows": row_count,
                         "flows_imported": len(flows), "session_id": session_id},
            )
    except Exception as exc:
        if session_id is not None:
            monitoring_service.fail_session(session_id, f"Dataset registration failed: {exc}")
        # Remove the stored copy unless another registration already references it.
        with database_service.session() as conn:
            referenced = conn.execute("SELECT 1 FROM datasets WHERE stored_path = ?", (str(stored_path),)).fetchone()
        if not referenced:
            stored_path.unlink(missing_ok=True)
        raise DatasetError(f"Registration failed and nothing was stored: {exc}") from exc
    return report


# ---------------------------------------------------------------- queries

def list_datasets(principal: Principal, kind: Optional[str] = None) -> List[DatasetSummary]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="dataset.list")
    with database_service.session() as conn:
        rows = dataset_repository.list_all(conn, kind)
    return [
        DatasetSummary(
            id=r["id"], name=r["name"], kind=r["kind"], original_filename=r["original_filename"],
            size_bytes=r["size_bytes"], row_count=r["row_count"], column_count=r["column_count"],
            label_distribution=json.loads(r["label_distribution_json"]) if r["label_distribution_json"] else {},
            has_timestamps=bool(r["has_timestamps"]), uploaded_at=r["uploaded_at"],
            uploaded_by_email=r["uploaded_by_email"],
            profile=json.loads(r["profile_json"]) if r["profile_json"] else {},
        )
        for r in rows
    ]


def delete_dataset(principal: Principal, dataset_id: int) -> None:
    """Remove a dataset record and its stored file. Sessions created from it keep their data."""
    require_permission(principal, Permission.DELETE_DATA, action="dataset.delete", details={"dataset_id": dataset_id})
    settings = get_settings()
    with database_service.session(write=True) as conn:
        row = dataset_repository.get(conn, dataset_id)
        if row is None:
            raise DatasetError("Dataset not found.")
        dataset_repository.delete(conn, dataset_id)
        audit_service.record(conn, user_id=principal.user_id, action="dataset.delete",
                             details={"dataset_id": dataset_id, "name": row["name"], "kind": row["kind"]})
    stored = row["stored_path"]
    if stored:
        path = Path(stored).resolve()
        # Only ever delete files inside the configured dataset directory.
        if settings.dataset_dir.resolve() in path.parents and path.exists():
            path.unlink()
