"""Historical telemetry ingestion (CSV -> network_metrics) and telemetry queries.

Import rules
* The file must follow the common schema in services/telemetry_schema.py.
* Timestamps are ISO-8601 and stored as UTC. Timestamps without a timezone are
  rejected unless the importer explicitly says they are UTC.
* Empty cells stay NULL (unavailable). Nothing is zero-filled.
* Invalid rows (bad timestamp, non-numeric, negative, ratio outside 0..1) are
  rejected and counted with a reason; valid rows are imported.
* Derived values are labelled: throughput = (in + out) x 8 when absent;
  utilization = throughput / capacity only when capacity is known and the
  result is <= 1. Capacity is always a configured value.
* The import is atomic: either every valid row is stored or none are.
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

from repositories import dataset_repository, monitoring_repository, telemetry_repository
from services import audit_service, database_service, monitoring_service
from services.authorization import Permission, Principal, require_permission
from services.monitoring_service import SessionState, SourceType
from services.telemetry_schema import (
    INTERFACE_COLUMN, MEASUREMENT_NAMES, METRIC_BY_NAME, METRIC_NAMES, TIMESTAMP_COLUMN, map_telemetry_columns,
)
from services.timeutil import utc_now_iso

MAX_TELEMETRY_BYTES = 200 * 1024 * 1024
MAX_TELEMETRY_ROWS = 2_000_000
MEASUREMENT_METHOD = "csv_import"
_TZ_SUFFIX = r"(?:Z|z|[+-]\d{2}:?\d{2})$"
_REASON_SAMPLE_ROWS = 5


class TelemetryImportError(Exception):
    """A user-facing import failure. Nothing was stored."""


@dataclass(frozen=True)
class TelemetryImportOptions:
    source_name: str
    default_interface: Optional[str] = None
    naive_timestamps_are_utc: bool = False
    utilization_unit: str = "ratio"  # ratio | percent
    packet_loss_unit: str = "ratio"  # ratio | percent
    capacity_override_bps: Optional[float] = None

    def validate(self) -> None:
        if not self.source_name or not self.source_name.strip():
            raise TelemetryImportError("Source name is required.")
        if len(self.source_name.strip()) > 100:
            raise TelemetryImportError("Source name must be at most 100 characters.")
        for unit in (self.utilization_unit, self.packet_loss_unit):
            if unit not in ("ratio", "percent"):
                raise TelemetryImportError("Units must be 'ratio' or 'percent'.")
        if self.capacity_override_bps is not None and not (
            math.isfinite(self.capacity_override_bps) and self.capacity_override_bps > 0
        ):
            raise TelemetryImportError("Configured capacity must be a positive number of bits per second.")


@dataclass
class SamplingSummary:
    interface: str
    samples: int
    start: str
    end: str
    median_interval_seconds: Optional[float]
    gaps: int  # intervals longer than 2x the median


@dataclass
class TelemetryImportReport:
    session_id: int
    dataset_id: int
    filename: str
    rows_read: int
    rows_imported: int
    rows_rejected: int
    duplicate_rows: int
    rejection_reasons: Dict[str, int]
    rejection_examples: Dict[str, List[int]]
    columns_found: List[str]
    unknown_columns: List[str]
    column_coverage: Dict[str, float]
    derived_counts: Dict[str, int]
    interfaces: List[str]
    time_start: str
    time_end: str
    sampling: List[SamplingSummary]
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------- parsing

def _read_csv(data: bytes) -> pd.DataFrame:
    try:
        frame = pd.read_csv(
            io.BytesIO(data), dtype=str, keep_default_na=False, skipinitialspace=True,
            nrows=MAX_TELEMETRY_ROWS + 1, encoding_errors="replace",
        )
    except pd.errors.EmptyDataError as exc:
        raise TelemetryImportError("The file is empty.") from exc
    except (pd.errors.ParserError, UnicodeDecodeError, ValueError) as exc:
        raise TelemetryImportError(f"The file could not be read as CSV: {exc}") from exc
    if len(frame) > MAX_TELEMETRY_ROWS:
        raise TelemetryImportError(f"The file has more than {MAX_TELEMETRY_ROWS:,} rows. Split it into smaller files.")
    return frame


class _RowRejections:
    def __init__(self, n_rows: int):
        self.bad = np.zeros(n_rows, dtype=bool)
        self.counts: Dict[str, int] = {}
        self.examples: Dict[str, List[int]] = {}

    def add(self, mask: pd.Series, reason: str) -> None:
        mask = mask.to_numpy(dtype=bool) & ~self.bad  # count each row once, under its first reason
        if not mask.any():
            return
        self.bad |= mask
        self.counts[reason] = self.counts.get(reason, 0) + int(mask.sum())
        # +2: one for the header line, one for 1-based numbering.
        self.examples[reason] = [int(i) + 2 for i in np.flatnonzero(mask)[:_REASON_SAMPLE_ROWS]]


def _parse_timestamps(raw: pd.Series, naive_is_utc: bool, rejections: _RowRejections) -> pd.Series:
    text = raw.astype(str).str.strip()
    rejections.add(text == "", "timestamp: missing")
    parsed = pd.to_datetime(text.where(text != ""), utc=True, errors="coerce", format="ISO8601")
    rejections.add(parsed.isna() & (text != ""), "timestamp: not ISO-8601")
    if not naive_is_utc:
        has_tz = text.str.contains(_TZ_SUFFIX, regex=True)
        rejections.add((text != "") & ~has_tz, "timestamp: no timezone (enable 'timestamps are UTC' if they are)")
    return parsed


def _parse_metric(raw: pd.Series, name: str, unit: str, rejections: _RowRejections) -> pd.Series:
    text = raw.astype(str).str.strip()
    blank = text.isin(["", "nan", "NaN", "null", "NULL", "None", "NA", "N/A"])
    values = pd.to_numeric(text.where(~blank), errors="coerce")
    rejections.add(values.isna() & ~blank, f"{name}: not a number")
    rejections.add(np.isinf(values.fillna(0)), f"{name}: infinite")
    spec = METRIC_BY_NAME[name]
    if spec.kind == "ratio" and unit == "percent":
        values = values / 100.0
    rejections.add(values < 0, f"{name}: negative")
    if spec.kind == "ratio":
        rejections.add(values > 1, f"{name}: outside 0–1" + (" (after % conversion)" if unit == "percent" else ""))
    if spec.kind == "positive":
        rejections.add(values == 0, f"{name}: must be greater than 0")
    return values


def _sampling(frame: pd.DataFrame) -> List[SamplingSummary]:
    summaries = []
    for interface, group in frame.groupby("interface_key", sort=True):
        times = group["timestamp"].sort_values()
        diffs = times.diff().dropna().dt.total_seconds()
        median = float(diffs.median()) if len(diffs) else None
        gaps = int((diffs > 2 * median).sum()) if median else 0
        summaries.append(SamplingSummary(
            interface=interface or "(unnamed)", samples=int(len(times)),
            start=times.iloc[0].isoformat(timespec="microseconds"),
            end=times.iloc[-1].isoformat(timespec="microseconds"),
            median_interval_seconds=median, gaps=gaps,
        ))
    return summaries


def _python_row(row: tuple) -> tuple:
    """Convert numpy scalars to plain Python values for sqlite3."""
    out = []
    for value in row:
        if isinstance(value, np.generic):
            value = value.item()
        if isinstance(value, float) and math.isnan(value):
            value = None
        out.append(value)
    return tuple(out)


# ---------------------------------------------------------------- import

def import_telemetry_csv(
    principal: Principal, data: bytes, filename: str, options: TelemetryImportOptions
) -> TelemetryImportReport:
    require_permission(principal, Permission.MANAGE_DATASETS, action="telemetry.import",
                       details={"filename": filename})
    try:
        return _import(principal, data, filename, options)
    except TelemetryImportError as exc:
        audit_service.record_standalone(
            user_id=principal.user_id, action="telemetry.import", outcome="failure",
            details={"filename": filename, "error": str(exc)[:300]},
        )
        raise


def _import(principal: Principal, data: bytes, filename: str, options: TelemetryImportOptions) -> TelemetryImportReport:
    options.validate()
    filename = Path(filename or "upload.csv").name[:255]
    if len(data) > MAX_TELEMETRY_BYTES:
        raise TelemetryImportError(f"The file is larger than {MAX_TELEMETRY_BYTES // (1024 * 1024)} MB.")
    sha256 = hashlib.sha256(data).hexdigest()
    with database_service.session() as conn:
        existing = dataset_repository.find_by_sha(conn, "telemetry", sha256)
    if existing is not None:
        raise TelemetryImportError(
            f"This exact file was already imported (dataset #{existing['id']}, '{existing['name']}')."
        )

    raw = _read_csv(data)
    mapping, unknown, duplicates = map_telemetry_columns(list(raw.columns))
    if duplicates:
        raise TelemetryImportError(f"These columns appear more than once: {', '.join(sorted(set(duplicates)))}.")
    raw = raw[list(mapping)].rename(columns=mapping)
    if TIMESTAMP_COLUMN not in raw.columns:
        raise TelemetryImportError("The file has no 'timestamp' column.")
    measurements = [c for c in MEASUREMENT_NAMES if c in raw.columns]
    if not measurements:
        raise TelemetryImportError(
            "The file has no measurement columns. Include at least one of: " + ", ".join(MEASUREMENT_NAMES) + "."
        )
    if raw.empty:
        raise TelemetryImportError("The file has a header but no data rows.")

    rows_read = len(raw)
    rejections = _RowRejections(rows_read)
    frame = pd.DataFrame(index=raw.index)
    frame["timestamp"] = _parse_timestamps(raw[TIMESTAMP_COLUMN], options.naive_timestamps_are_utc, rejections)
    units = {"utilization_ratio": options.utilization_unit, "packet_loss_ratio": options.packet_loss_unit}
    for name in METRIC_NAMES:
        if name in raw.columns:
            frame[name] = _parse_metric(raw[name], name, units.get(name, "ratio"), rejections)
        else:
            frame[name] = np.nan

    if INTERFACE_COLUMN in raw.columns:
        interface = raw[INTERFACE_COLUMN].astype(str).str.strip().str.slice(0, 100)
    else:
        interface = pd.Series("", index=raw.index)
    default_interface = (options.default_interface or "").strip()[:100]
    frame["interface_key"] = interface.where(interface != "", default_interface)

    # Rows with no measurement at all carry no information.
    rejections.add(frame[measurements].isna().all(axis=1), "no measurement values in row")

    frame = frame[~rejections.bad]
    before = len(frame)
    frame = frame.drop_duplicates(subset=["interface_key", "timestamp"], keep="first")
    duplicate_rows = before - len(frame)
    if frame.empty:
        raise TelemetryImportError(
            "No valid rows to import. Problems found: "
            + "; ".join(f"{reason} ({count})" for reason, count in rejections.counts.items())
        )
    frame = frame.sort_values(["interface_key", "timestamp"])

    # Derived and configured values, each with its own provenance.
    measured_throughput = frame["throughput_bps"].notna()
    can_derive_tp = ~measured_throughput & frame["incoming_bytes_per_second"].notna() & frame["outgoing_bytes_per_second"].notna()
    frame.loc[can_derive_tp, "throughput_bps"] = (
        frame.loc[can_derive_tp, "incoming_bytes_per_second"] + frame.loc[can_derive_tp, "outgoing_bytes_per_second"]
    ) * 8
    frame["throughput_provenance"] = np.where(measured_throughput, "measured", np.where(can_derive_tp, "derived", "unavailable"))

    capacity_from_setting = frame["configured_capacity_bps"].isna() & (options.capacity_override_bps is not None)
    if options.capacity_override_bps is not None:
        frame["configured_capacity_bps"] = frame["configured_capacity_bps"].fillna(float(options.capacity_override_bps))
    frame["capacity_provenance"] = np.where(frame["configured_capacity_bps"].notna(), "configured", "unavailable")

    measured_util = frame["utilization_ratio"].notna()
    candidate = frame["throughput_bps"] / frame["configured_capacity_bps"]
    can_derive_util = ~measured_util & candidate.notna()
    over_capacity = can_derive_util & (candidate > 1)
    can_derive_util &= ~over_capacity
    frame.loc[can_derive_util, "utilization_ratio"] = candidate[can_derive_util]
    frame["utilization_provenance"] = np.where(measured_util, "measured", np.where(can_derive_util, "derived", "unavailable"))

    frame["validity_status"] = np.where(frame[measurements].notna().all(axis=1), "valid", "partial")

    warnings: List[str] = []
    if over_capacity.any():
        warnings.append(
            f"{int(over_capacity.sum())} rows have throughput above the configured capacity; utilization was left "
            "unavailable for them. Check the capacity value."
        )
    if frame["utilization_ratio"].isna().all():
        warnings.append("Utilization is unavailable for every row: no utilization column and no known capacity. "
                        "Absolute rates will be shown instead.")
    if unknown:
        warnings.append("Ignored columns not in the schema: " + ", ".join(unknown[:15]) + ("…" if len(unknown) > 15 else ""))
    if not default_interface and (frame["interface_key"] == "").any():
        warnings.append("Some rows have no interface name.")

    sampling = _sampling(frame)
    interfaces = sorted({s.interface for s in sampling})
    coverage = {name: round(float(frame[name].notna().mean()), 4) for name in METRIC_NAMES if name in raw.columns}
    derived_counts = {
        "throughput_bps": int(can_derive_tp.sum()),
        "utilization_ratio": int(can_derive_util.sum()),
        "configured_capacity_bps (from import setting)": int(capacity_from_setting.sum()),
    }

    source_name = options.source_name.strip()
    single_interface = interfaces[0] if len(interfaces) == 1 and interfaces[0] != "(unnamed)" else None
    configuration = {
        "filename": filename, "sha256": sha256, "options": asdict(options),
        "rows_read": rows_read, "rows_imported": int(len(frame)),
        "sampling": [asdict(s) for s in sampling],
    }

    with database_service.session(write=True) as conn:
        session_id = monitoring_service.create_session(
            conn, user_id=principal.user_id, source_type=SourceType.HISTORICAL_IMPORT,
            interface_name=single_interface, configuration=configuration,
        )
    try:
        timestamps = frame["timestamp"].map(lambda t: t.isoformat(timespec="microseconds"))
        ordered = pd.DataFrame({
            "session_id": session_id,
            "timestamp": timestamps,
            "source_name": source_name,
            "interface_name": frame["interface_key"].where(frame["interface_key"] != "", None),
            **{name: frame[name] for name in METRIC_NAMES},
            "measurement_method": MEASUREMENT_METHOD,
            "provenance": "measured",
            "validity_status": frame["validity_status"],
            "throughput_provenance": frame["throughput_provenance"],
            "utilization_provenance": frame["utilization_provenance"],
            "capacity_provenance": frame["capacity_provenance"],
        })[list(telemetry_repository.METRIC_INSERT_COLUMNS)].astype(object)
        ordered = ordered.where(ordered.notna(), None)
        rows = [_python_row(r) for r in ordered.itertuples(index=False, name=None)]
        report = TelemetryImportReport(
            session_id=session_id, dataset_id=0, filename=filename, rows_read=rows_read,
            rows_imported=len(rows), rows_rejected=int(rejections.bad.sum()), duplicate_rows=duplicate_rows,
            rejection_reasons=dict(rejections.counts), rejection_examples=dict(rejections.examples),
            columns_found=sorted(set(raw.columns)), unknown_columns=unknown, column_coverage=coverage,
            derived_counts=derived_counts, interfaces=interfaces,
            time_start=str(timestamps.min()), time_end=str(timestamps.max()), sampling=sampling, warnings=warnings,
        )
        with database_service.session(write=True) as conn:
            dataset_id = dataset_repository.insert(conn, {
                "name": source_name, "kind": "telemetry", "original_filename": filename, "stored_path": None,
                "sha256": sha256, "size_bytes": len(data), "row_count": rows_read, "column_count": len(raw.columns),
                "columns_json": json.dumps(sorted(set(raw.columns))), "label_column": None,
                "label_distribution_json": None, "has_timestamps": 1,
                "profile_json": json.dumps({k: v for k, v in report.to_dict().items() if k != "sampling"}, default=str),
                "uploaded_by": principal.user_id, "uploaded_at": utc_now_iso(),
            })
            report.dataset_id = dataset_id
            configuration["dataset_id"] = dataset_id
            monitoring_repository.update_configuration(
                conn, session_id, json.dumps(configuration, sort_keys=True, default=str), single_interface, dataset_id
            )
            telemetry_repository.insert_many(conn, rows)
            monitoring_service.transition(conn, session_id, SessionState.STOPPED,
                                          f"Imported {len(rows):,} of {rows_read:,} rows from {filename}")
            audit_service.record(
                conn, user_id=principal.user_id, action="telemetry.import",
                details={"filename": filename, "session_id": session_id, "dataset_id": dataset_id,
                         "rows_imported": len(rows), "rows_rejected": report.rows_rejected},
            )
    except Exception as exc:
        monitoring_service.fail_session(session_id, f"Import failed: {exc}")
        if isinstance(exc, TelemetryImportError):
            raise
        raise TelemetryImportError(f"The import failed and nothing was stored: {exc}") from exc
    return report
