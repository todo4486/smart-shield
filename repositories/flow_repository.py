"""SQL for network_flows."""
from __future__ import annotations

import sqlite3
from typing import Iterable, List, Sequence

FLOW_INSERT_COLUMNS = (
    "session_id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "packet_count", "byte_count", "duration", "feature_summary_json", "provenance",
)


def insert_many(conn: sqlite3.Connection, rows: Iterable[Sequence]) -> None:
    placeholders = ", ".join("?" for _ in FLOW_INSERT_COLUMNS)
    conn.executemany(f"INSERT INTO network_flows ({', '.join(FLOW_INSERT_COLUMNS)}) VALUES ({placeholders})", rows)


def protocol_counts(conn: sqlite3.Connection, session_id: int) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT COALESCE(protocol, 'unknown') AS protocol, COUNT(*) AS flows, SUM(byte_count) AS bytes "
        "FROM network_flows WHERE session_id = ? GROUP BY 1 ORDER BY flows DESC",
        (session_id,),
    ).fetchall()


def top_destination_ports(conn: sqlite3.Connection, session_id: int, limit: int = 10) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT dst_port, COUNT(*) AS flows FROM network_flows "
        "WHERE session_id = ? AND dst_port IS NOT NULL GROUP BY dst_port ORDER BY flows DESC LIMIT ?",
        (session_id, limit),
    ).fetchall()


def flows_per_minute(conn: sqlite3.Connection, session_id: int) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT substr(timestamp, 1, 16) AS minute, COUNT(*) AS flows FROM network_flows "
        "WHERE session_id = ? GROUP BY minute ORDER BY minute",
        (session_id,),
    ).fetchall()


def feature_summaries(conn: sqlite3.Connection, session_id: int) -> List[str]:
    """Raw feature_summary_json values (aggregated in Python; no JSON1 dependency)."""
    return [
        r[0] for r in conn.execute(
            "SELECT feature_summary_json FROM network_flows WHERE session_id = ? AND feature_summary_json IS NOT NULL",
            (session_id,),
        )
    ]
