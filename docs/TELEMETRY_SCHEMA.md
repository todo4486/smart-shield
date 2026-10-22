# Telemetry and dataset formats

This document is generated from `services/telemetry_schema.py`. It describes what the ML Laboratory accepts.

## Historical telemetry CSV

| Column | Required | Unit | Meaning |
| --- | --- | --- | --- |
| `timestamp` | yes | ISO-8601 | When the sample was taken. Converted to UTC. |
| `interface_name` | no | text | Interface or link name. A default can be set at import time. |
| `incoming_bytes_per_second` | no* | B/s | Bytes received per second. |
| `outgoing_bytes_per_second` | no* | B/s | Bytes sent per second. |
| `incoming_packets_per_second` | no* | packets/s | Packets received per second. |
| `outgoing_packets_per_second` | no* | packets/s | Packets sent per second. |
| `throughput_bps` | no* | bit/s | Total throughput in bits per second. Derived as (in + out) × 8 when absent. |
| `latency_ms` | no* | ms | Round-trip latency in milliseconds. |
| `packet_loss_ratio` | no* | ratio 0–1 | Fraction of packets lost (0.02 = 2%). |
| `utilization_ratio` | no* | ratio 0–1 | Link utilization (0.75 = 75%). Derived from throughput ÷ capacity when absent and capacity is known. |
| `configured_capacity_bps` | no* | bit/s | Link capacity for this row, if known. Stored as a configured value. |

\* At least one measurement column (anything except capacity) is required. Leave a cell empty when a value was not measured — empty is stored as unavailable, never as 0.

Rules:

- **Timestamps** must be ISO-8601 and are stored as UTC. Timestamps without a timezone are rejected unless the importer ticks "Timestamps without a timezone are UTC".
- **Column names** are matched case-insensitively, with spaces and punctuation treated as `_`. Common aliases are accepted: `time`, `interface`, `rtt_ms`, `throughput`, `utilization`, `capacity_bps`, and a few others. Unknown columns are ignored and listed in the report.
- **Invalid rows are rejected and counted with a reason.** Invalid means a bad timestamp, or a value that is non-numeric, infinite, negative, or a ratio outside 0–1. Example line numbers are shown for each reason.
- **Units:** ratios may be supplied as percent if the importer selects "percent".
- **Duplicates:** for the same interface and timestamp, the first row is kept.
- **Derived values are labelled `derived`:**
  - `throughput_bps` = (incoming + outgoing bytes/s) × 8, when absent.
  - `utilization_ratio` = throughput ÷ capacity, when absent. It is calculated only if capacity is known and the result is ≤ 1; otherwise it stays unavailable.
- **Capacity** is always a `configured` value.
- **Imports are atomic.** Each import becomes one monitoring session (`historical_import`).
- **Limits:** 200 MB and 2,000,000 rows per file. The same file (by SHA-256) cannot be imported twice.

## Labelled intrusion datasets (CIC-IDS2017 style)

- **Label required:** the file needs a `Label` column; leading spaces in the name are fine.
- **Column names** are normalized (e.g. ` Flow Bytes/s` → `flow_bytes_s`). Repeated headers get a numeric suffix (`fwd_header_length_1`).
- **Stored and profiled:** the file is kept unchanged under `SMART_SHIELD_DATASET_DIR`, named by its SHA-256. The profile records the label distribution, infinite and missing values per column, and the identifier/leakage columns that training will drop: flow ID, source/destination IP, source port and timestamp.
- **Optional flow import:** rows with a parseable `Timestamp` can be copied into `network_flows`, as a `dataset` monitoring session.
  - CIC-IDS2017 dates are day-first. They were captured at UTC-3, so set that offset.
  - The dataset label is stored as `dataset_label` in `feature_summary_json`. It is ground truth, never a prediction.
  - At most 200,000 flows are imported per file.
- **Limits:** 512 MB per file.
