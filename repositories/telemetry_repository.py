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


# ---------------------------------------------------------------- per-host samples

HOST_INSERT_COLUMNS = ("session_id", "timestamp", "host", "sent_bps", "received_bps", "sent_pps", "received_pps",
                       "active_connections", "provenance")


def insert_host_metrics(conn: sqlite3.Connection, rows: Iterable[Sequence]) -> None:
    placeholders = ", ".join("?" for _ in HOST_INSERT_COLUMNS)
    conn.executemany(f"INSERT INTO host_metrics ({', '.join(HOST_INSERT_COLUMNS)}) VALUES ({placeholders})", rows)


def host_metrics_since(conn: sqlite3.Connection, session_id: int, since: str) -> List[sqlite3.Row]:
    return conn.execute("SELECT * FROM host_metrics WHERE session_id = ? AND timestamp >= ? ORDER BY timestamp, id",
                        (session_id, since)).fetchall()


def newest_host_metric_time(conn: sqlite3.Connection, session_id: int) -> Optional[str]:
    return conn.execute("SELECT MAX(timestamp) FROM host_metrics WHERE session_id = ?", (session_id,)).fetchone()[0]


def latest_session_with_metrics(conn: sqlite3.Connection, source_types: Sequence[str]) -> Optional[sqlite3.Row]:
    placeholders = ", ".join("?" for _ in source_types)
    return conn.execute(
        f"SELECT s.* FROM monitoring_sessions s WHERE s.source_type IN ({placeholders}) AND EXISTS "
        "(SELECT 1 FROM network_metrics m WHERE m.session_id = s.id) ORDER BY s.id DESC LIMIT 1",
        tuple(source_types)).fetchone()


def flows_of_session_since(conn: sqlite3.Connection, session_id: int, since: str, limit: int = 20_000) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT src_ip, dst_ip, dst_port, protocol, byte_count, intrusion_prediction FROM network_flows "
        "WHERE session_id = ? AND timestamp >= ? ORDER BY timestamp DESC LIMIT ?", (session_id, since, limit)).fetchall()
