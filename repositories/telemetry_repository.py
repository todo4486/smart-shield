"""SQL for network_metrics."""
from __future__ import annotations

import sqlite3
from typing import Iterable, List, Optional, Sequence

METRIC_INSERT_COLUMNS = (
    "session_id", "timestamp", "source_name", "interface_name",
    "incoming_bytes_per_second", "outgoing_bytes_per_second",
    "incoming_packets_per_second", "outgoing_packets_per_second",
    "throughput_bps", "latency_ms", "packet_loss_ratio", "utilization_ratio", "configured_capacity_bps",
    "measurement_method", "provenance", "validity_status",
    "throughput_provenance", "utilization_provenance", "capacity_provenance",
)


def insert_many(conn: sqlite3.Connection, rows: Iterable[Sequence]) -> None:
    placeholders = ", ".join("?" for _ in METRIC_INSERT_COLUMNS)
    conn.executemany(
        f"INSERT INTO network_metrics ({', '.join(METRIC_INSERT_COLUMNS)}) VALUES ({placeholders})", rows
    )


def metrics_for_session(conn: sqlite3.Connection, session_id: int, interface_name: Optional[str] = None,
                        limit: int = 500_000) -> List[sqlite3.Row]:
    sql = "SELECT * FROM network_metrics WHERE session_id = ?"
    params: list = [session_id]
    # None = every interface; "" = rows recorded without an interface name; anything else = that interface.
    if interface_name == "":
        sql += " AND (interface_name IS NULL OR interface_name = '')"
    elif interface_name is not None:
        sql += " AND interface_name = ?"
        params.append(interface_name)
    params.append(limit)
    return conn.execute(sql + " ORDER BY timestamp, id LIMIT ?", params).fetchall()


def recent_metrics(conn: sqlite3.Connection, session_id: int, limit: int) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM network_metrics WHERE session_id = ? ORDER BY timestamp DESC, id DESC LIMIT ?",
        (session_id, limit),
    ).fetchall()


def interfaces_for_session(conn: sqlite3.Connection, session_id: int) -> List[str]:
    return [
        r[0] for r in conn.execute(
            "SELECT DISTINCT COALESCE(interface_name, '') FROM network_metrics WHERE session_id = ? ORDER BY 1",
            (session_id,),
        )
    ]
