"""The common telemetry schema shared by imports now and live monitoring later.

One definition drives CSV validation, the downloadable template and the
schema reference shown in the UI (and docs/TELEMETRY_SCHEMA.md).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

PROVENANCE_VALUES = ("measured", "derived", "predicted", "configured", "unavailable")


@dataclass(frozen=True)
class MetricColumn:
    name: str
    unit: str
    description: str
    kind: str = "rate"  # rate (>= 0), ratio (0..1), positive (> 0)


TIMESTAMP_COLUMN = "timestamp"
INTERFACE_COLUMN = "interface_name"

METRIC_COLUMNS: Tuple[MetricColumn, ...] = (
    MetricColumn("incoming_bytes_per_second", "B/s", "Bytes received per second."),
    MetricColumn("outgoing_bytes_per_second", "B/s", "Bytes sent per second."),
    MetricColumn("incoming_packets_per_second", "packets/s", "Packets received per second."),
    MetricColumn("outgoing_packets_per_second", "packets/s", "Packets sent per second."),
    MetricColumn("throughput_bps", "bit/s", "Total throughput in bits per second. Derived as (in + out) × 8 when absent."),
    MetricColumn("latency_ms", "ms", "Round-trip latency in milliseconds."),
    MetricColumn("packet_loss_ratio", "ratio 0–1", "Fraction of packets lost (0.02 = 2%).", kind="ratio"),
    MetricColumn("utilization_ratio", "ratio 0–1", "Link utilization (0.75 = 75%). Derived from throughput ÷ capacity when absent and capacity is known.", kind="ratio"),
    MetricColumn("configured_capacity_bps", "bit/s", "Link capacity for this row, if known. Stored as a configured value.", kind="positive"),
)

METRIC_NAMES: Tuple[str, ...] = tuple(c.name for c in METRIC_COLUMNS)
METRIC_BY_NAME: Dict[str, MetricColumn] = {c.name: c for c in METRIC_COLUMNS}

# Columns that count as an actual traffic or performance measurement.
# A file must contain at least one (capacity alone measures nothing).
MEASUREMENT_NAMES: Tuple[str, ...] = tuple(n for n in METRIC_NAMES if n != "configured_capacity_bps")

ALL_COLUMNS: Tuple[str, ...] = (TIMESTAMP_COLUMN, INTERFACE_COLUMN) + METRIC_NAMES

# Common spellings mapped onto the schema after normalization.
COLUMN_ALIASES: Dict[str, str] = {
    "time": TIMESTAMP_COLUMN,
    "datetime": TIMESTAMP_COLUMN,
    "ts": TIMESTAMP_COLUMN,
    "interface": INTERFACE_COLUMN,
    "iface": INTERFACE_COLUMN,
    "rx_bytes_per_second": "incoming_bytes_per_second",
    "tx_bytes_per_second": "outgoing_bytes_per_second",
    "rx_packets_per_second": "incoming_packets_per_second",
    "tx_packets_per_second": "outgoing_packets_per_second",
    "throughput": "throughput_bps",
    "latency": "latency_ms",
    "rtt_ms": "latency_ms",
    "packet_loss": "packet_loss_ratio",
    "utilization": "utilization_ratio",
    "capacity_bps": "configured_capacity_bps",
}


def normalize_column_name(name: str) -> str:
    """'  Flow Bytes/s ' -> 'flow_bytes_s'. Used for every uploaded CSV."""
    cleaned = re.sub(r"[^0-9a-zA-Z]+", "_", str(name).strip()).strip("_").lower()
    return cleaned


def map_telemetry_columns(columns: List[str]) -> Tuple[Dict[str, str], List[str], List[str]]:
    """Return (original -> schema name, unknown columns, duplicate targets)."""
    mapping: Dict[str, str] = {}
    unknown: List[str] = []
    seen: Dict[str, str] = {}
    duplicates: List[str] = []
    for original in columns:
        normalized = normalize_column_name(original)
        target: Optional[str] = normalized if normalized in ALL_COLUMNS else COLUMN_ALIASES.get(normalized)
        if target is None:
            unknown.append(str(original))
            continue
        if target in seen:
            duplicates.append(target)
            continue
        seen[target] = original
        mapping[str(original)] = target
    return mapping, unknown, duplicates


def template_csv() -> str:
    """Header-only template. Contains no example values (nothing fabricated)."""
    return ",".join(ALL_COLUMNS) + "\n"


def schema_markdown() -> str:
    lines = [
        "| Column | Required | Unit | Meaning |",
        "| --- | --- | --- | --- |",
        f"| `{TIMESTAMP_COLUMN}` | yes | ISO-8601 | When the sample was taken. Converted to UTC. |",
        f"| `{INTERFACE_COLUMN}` | no | text | Interface or link name. A default can be set at import time. |",
    ]
    for column in METRIC_COLUMNS:
        lines.append(f"| `{column.name}` | no* | {column.unit} | {column.description} |")
    lines.append("")
    lines.append("\\* At least one measurement column (anything except capacity) is required. "
                 "Leave a cell empty when a value was not measured — empty is stored as unavailable, never as 0.")
    return "\n".join(lines)
