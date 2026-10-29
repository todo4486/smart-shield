"""Host-and-link network map built from stored flows (read-only).

Encoding (documented here, explained in the page legend):
* Node  = a host (IP address). Size = bytes it sent plus received in the window.
* Edge  = traffic between two hosts in either direction. Thickness = average throughput over the window.
* Edge colour = utilization risk: the edge's throughput as a share of the session's configured link capacity,
  judged against the PredictNet thresholds. Without a configured capacity the risk is "unknown"; it is never
  guessed from the busiest edge.
* Node ring = the most severe unresolved alert that names the host in its evidence.
* Pulse = the host appears in an alert that belongs to an open or investigating incident.

Scale: only the top N hosts by traffic are drawn; the rest are merged into one "Others" node.
Times: the window ends at the newest flow in the session (datasets are historical), not at "now".

Host risk score (0–100), shown in the host panel:
    40 per unresolved critical alert naming the host, 20 per high, 8 per medium, 3 per low
    + 30 × the share of the host's flows in the window flagged by a model
    + 15 if the host is part of an open or investigating incident
    capped at 100.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np

from services import data_source, database_service, settings_service, severity
from services.authorization import Permission, Principal, require_permission
from services.timeutil import parse_iso, to_iso

OTHERS = "Others"
MAX_FLOWS = 50_000
DEFAULT_TOP_N = 25
SEVERITY_POINTS = {"critical": 40, "high": 20, "medium": 8, "low": 3}


class MapError(Exception):
    pass


@dataclass(frozen=True)
class MapFilters:
    session_id: int
    window_minutes: int = 60
    protocols: Tuple[str, ...] = ()
    min_severity: Optional[str] = None
    only_incident_hosts: bool = False
    top_n: int = DEFAULT_TOP_N


@dataclass
class Node:
    id: str
    bytes: int
    flows: int
    flagged_flows: int
    severity: Optional[str] = None
    in_incident: bool = False
    members: int = 1  # hosts merged into this node ("Others" > 1)
    x: float = 0.0
    y: float = 0.0


@dataclass
class Edge:
    source: str
    target: str
    bytes: int
    flows: int
    flagged_flows: int
    throughput_bps: float
    utilization: Optional[float]
    risk: str  # normal / elevated / high / critical / unknown


@dataclass
class NetworkMap:
    nodes: List[Node]
    edges: List[Edge]
    window_start: Optional[str]
    window_end: Optional[str]
    capacity_bps: Optional[float]
    source: data_source.DataSource
    flows_in_window: int
    hosts_total: int
    truncated: bool = False
    protocols: List[str] = field(default_factory=list)


# ------------------------------------------------------------------- pure

def edge_risk(throughput_bps: float, capacity_bps: Optional[float], thresholds: Dict[str, float]) -> Tuple[Optional[float], str]:
    if not capacity_bps:
        return None, "unknown"
    utilization = throughput_bps / capacity_bps
    level = ("critical" if utilization >= thresholds["critical"] else "high" if utilization >= thresholds["high"]
             else "elevated" if utilization >= thresholds["elevated"] else "normal")
    return utilization, level


def aggregate(flows: Iterable[Dict[str, Any]], *, top_n: int, window_seconds: float,
              capacity_bps: Optional[float], thresholds: Dict[str, float]) -> Tuple[List[Node], List[Edge], int]:
    """Hosts and undirected links from flow rows; hosts beyond the top N by bytes become one "Others" node."""
    host_bytes: Dict[str, int] = {}
    host_flows: Dict[str, int] = {}
    host_flagged: Dict[str, int] = {}
    pairs: Dict[Tuple[str, str], List[int]] = {}
    rows = list(flows)
    for f in rows:
        src, dst = str(f["src_ip"]), str(f["dst_ip"])
        size, flagged = int(f["byte_count"] or 0), int(bool(f.get("flagged")))
        for host in (src, dst):
            host_bytes[host] = host_bytes.get(host, 0) + size
            host_flows[host] = host_flows.get(host, 0) + 1
            host_flagged[host] = host_flagged.get(host, 0) + flagged
    ranked = sorted(host_bytes, key=lambda h: (-host_bytes[h], h))
    keep = set(ranked[:max(1, top_n)])
    merged = [h for h in ranked if h not in keep]

    def bucket(host: str) -> str:
        return host if host in keep else OTHERS

    for f in rows:
        a, b = sorted((bucket(str(f["src_ip"])), bucket(str(f["dst_ip"]))))
        if a == b == OTHERS:
            continue  # traffic entirely between merged hosts is summarised in the Others node only
        entry = pairs.setdefault((a, b), [0, 0, 0])
        entry[0] += int(f["byte_count"] or 0)
        entry[1] += 1
        entry[2] += int(bool(f.get("flagged")))
    nodes = [Node(h, host_bytes[h], host_flows[h], host_flagged[h]) for h in ranked if h in keep]
    if merged:
        nodes.append(Node(OTHERS, sum(host_bytes[h] for h in merged), sum(host_flows[h] for h in merged),
                          sum(host_flagged[h] for h in merged), members=len(merged)))
    edges = []
    for (a, b), (size, count, flagged) in sorted(pairs.items(), key=lambda kv: (-kv[1][0], kv[0])):
        throughput = size * 8 / window_seconds if window_seconds > 0 else 0.0
        utilization, risk = edge_risk(throughput, capacity_bps, thresholds)
        edges.append(Edge(a, b, size, count, flagged, throughput, utilization, risk))
    return nodes, edges, len(ranked)


def host_alert_severity(alerts: Iterable[Dict[str, Any]]) -> Dict[str, str]:
    """Most severe unresolved alert per host named in alert evidence (sources and destinations)."""
    worst: Dict[str, str] = {}
    for alert in alerts:
        for host in hosts_in_evidence(alert["evidence"]):
            worst[host] = severity.highest([worst.get(host), alert["severity"]])
    return worst


def hosts_in_evidence(evidence: Dict[str, Any]) -> List[str]:
    hosts = []
    for key in ("top_sources", "top_destinations"):
        for item in evidence.get(key) or []:
            value = str(item.get("value", "")) if isinstance(item, dict) else str(item)
            host = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
            if host:
                hosts.append(host)
    return hosts


def host_risk_score(alert_severities: Sequence[str], flagged_share: Optional[float], in_incident: bool) -> int:
    score = sum(SEVERITY_POINTS.get(severity.normalize(s), 0) for s in alert_severities)
    score += 30 * (flagged_share or 0.0)
    score += 15 if in_incident else 0
    return int(min(100, round(score)))


def spring_layout(node_ids: Sequence[str], edges: Sequence[Tuple[str, str, float]], *, iterations: int = 120,
                  seed: int = 7) -> Dict[str, Tuple[float, float]]:
    """Deterministic force-directed layout (Fruchterman–Reingold) in a unit square."""
    n = len(node_ids)
    if n == 0:
        return {}
    if n == 1:
        return {node_ids[0]: (0.5, 0.5)}
    index = {node: i for i, node in enumerate(node_ids)}
    rng = np.random.default_rng(seed)
    angles = np.linspace(0, 2 * math.pi, n, endpoint=False)
    pos = np.column_stack([0.5 + 0.4 * np.cos(angles), 0.5 + 0.4 * np.sin(angles)]) + rng.normal(0, 0.01, (n, 2))
    k = math.sqrt(1.0 / n)
    weights = [(index[a], index[b], w) for a, b, w in edges if a in index and b in index and a != b]
    temperature = 0.1
    for _ in range(iterations):
        delta = pos[:, None, :] - pos[None, :, :]
        distance = np.maximum(np.linalg.norm(delta, axis=-1), 1e-3)
        np.fill_diagonal(distance, np.inf)
        displacement = (delta / distance[..., None] * (k * k / distance)[..., None]).sum(axis=1)
        for i, j, w in weights:
            d = pos[i] - pos[j]
            dist = max(float(np.linalg.norm(d)), 1e-3)
            pull = d / dist * (dist * dist / k) * (0.5 + w)
            displacement[i] -= pull
            displacement[j] += pull
        length = np.maximum(np.linalg.norm(displacement, axis=1), 1e-9)
        pos += displacement / length[:, None] * np.minimum(length, temperature)[:, None]
        temperature *= 0.97
    pos -= pos.min(axis=0)
    span = np.maximum(pos.max(axis=0), 1e-9)
    pos = 0.05 + 0.9 * pos / span
    return {node: (float(pos[i, 0]), float(pos[i, 1])) for node, i in index.items()}


# ----------------------------------------------------------------- queries

def _session_capacity(conn, session_id: int, configuration: Dict[str, Any]) -> Optional[float]:
    if configuration.get("capacity_bps"):
        return float(configuration["capacity_bps"])
    row = conn.execute("SELECT configured_capacity_bps FROM network_metrics WHERE session_id = ? AND "
                       "configured_capacity_bps IS NOT NULL ORDER BY timestamp DESC LIMIT 1", (session_id,)).fetchone()
    return float(row[0]) if row else None


def flow_sessions(principal: Principal) -> List[Dict[str, Any]]:
    """Sessions that have stored flows (the map needs IP addresses), newest first."""
    require_permission(principal, Permission.VIEW_DASHBOARD, action="network_map.view")
    with database_service.session() as conn:
        rows = conn.execute(
            "SELECT s.id, s.source_type, s.interface_name, s.started_at, s.status, s.configuration_json, "
            "(SELECT COUNT(*) FROM network_flows f WHERE f.session_id = s.id) AS flow_count "
            "FROM monitoring_sessions s WHERE EXISTS (SELECT 1 FROM network_flows f WHERE f.session_id = s.id) "
            "ORDER BY s.started_at DESC, s.id DESC").fetchall()
    return [dict(r) for r in rows]


def _open_alerts(conn) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT a.id, a.severity, a.evidence_json, EXISTS (SELECT 1 FROM incident_alerts ia JOIN incidents i "
        "ON i.id = ia.incident_id WHERE ia.alert_id = a.id AND i.status IN ('open', 'investigating')) AS in_incident "
        "FROM alerts a WHERE a.status IN ('open', 'acknowledged') AND a.suppressed_by_rule IS NULL").fetchall()
    return [{"id": r["id"], "severity": r["severity"], "in_incident": bool(r["in_incident"]),
             "evidence": json.loads(r["evidence_json"]) if r["evidence_json"] else {}} for r in rows]


def _window_flows(conn, filters: MapFilters) -> Tuple[List[Dict[str, Any]], Optional[str], Optional[str]]:
    newest = conn.execute("SELECT MAX(timestamp) FROM network_flows WHERE session_id = ?",
                          (filters.session_id,)).fetchone()[0]
    if newest is None:
        return [], None, None
    start = to_iso(parse_iso(newest) - timedelta(minutes=int(filters.window_minutes)))
    sql = ("SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, byte_count, packet_count, "
           "intrusion_prediction, anomaly_score FROM network_flows WHERE session_id = ? AND timestamp >= ? "
           "AND timestamp <= ? AND src_ip IS NOT NULL AND dst_ip IS NOT NULL")
    params: List[Any] = [filters.session_id, start, newest]
    if filters.protocols:
        sql += f" AND protocol IN ({', '.join('?' for _ in filters.protocols)})"
        params.extend(filters.protocols)
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(MAX_FLOWS)
    rows = [dict(r) for r in conn.execute(sql, params)]
    for r in rows:
        r["flagged"] = bool(r["intrusion_prediction"])
    return rows, start, newest


def build_map(principal: Principal, filters: MapFilters, *, live_running: bool = False,
              live_mode: Optional[str] = None) -> NetworkMap:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="network_map.view")
    if not 1 <= int(filters.window_minutes) <= 7 * 24 * 60:
        raise MapError("The time window must be between 1 minute and 7 days.")
    if not 2 <= int(filters.top_n) <= 200:
        raise MapError("Show between 2 and 200 hosts.")
    thresholds = settings_service.get_predictnet_settings().thresholds()
    with database_service.session() as conn:
        session = conn.execute("SELECT source_type, interface_name, configuration_json FROM monitoring_sessions "
                               "WHERE id = ?", (filters.session_id,)).fetchone()
        if session is None:
            raise MapError("Session not found.")
        configuration = json.loads(session["configuration_json"] or "{}")
        flows, start, end = _window_flows(conn, filters)
        protocols = [r[0] for r in conn.execute("SELECT DISTINCT protocol FROM network_flows WHERE session_id = ? "
                                                "AND protocol IS NOT NULL ORDER BY protocol", (filters.session_id,))]
        capacity = _session_capacity(conn, filters.session_id, configuration)
        alerts = _open_alerts(conn)
    source = data_source.classify(session["source_type"], live_running=live_running and session["source_type"] ==
                                  "live_capture", live_mode=live_mode, detail=session["interface_name"])
    window_seconds = float(filters.window_minutes) * 60
    if flows:  # when the data covers less than the window, average over the span the data actually covers
        span = (parse_iso(end) - min(parse_iso(f["timestamp"]) for f in flows)).total_seconds()
        window_seconds = max(60.0, min(window_seconds, span))  # never average over less than a minute
    nodes, edges, hosts_total = aggregate(flows, top_n=filters.top_n, window_seconds=window_seconds,
                                          capacity_bps=capacity, thresholds=thresholds)
    ring = host_alert_severity(alerts)
    incident_hosts = {h for a in alerts if a["in_incident"] for h in hosts_in_evidence(a["evidence"])}
    for node in nodes:
        node.severity = ring.get(node.id)
        node.in_incident = node.id in incident_hosts
    keep = {n.id for n in nodes if (not filters.only_incident_hosts or n.in_incident)
            and (filters.min_severity is None or (n.severity is not None and
                                                  severity.rank(n.severity) >= severity.rank(filters.min_severity)))}
    if filters.only_incident_hosts or filters.min_severity:
        nodes = [n for n in nodes if n.id in keep]
        edges = [e for e in edges if e.source in keep and e.target in keep]
    positions = spring_layout([n.id for n in nodes], [(e.source, e.target, min(1.0, e.bytes / max(1, edges[0].bytes)))
                                                      for e in edges] if edges else [])
    for node in nodes:
        node.x, node.y = positions.get(node.id, (0.5, 0.5))
    return NetworkMap(nodes, edges, start, end, capacity, source, len(flows), hosts_total,
                      truncated=len(flows) >= MAX_FLOWS, protocols=protocols)


def host_detail(principal: Principal, session_id: int, host: str, window_minutes: int) -> Dict[str, Any]:
    """Flows, alerts, incidents, forecast and risk score for one host in the session window."""
    require_permission(principal, Permission.VIEW_ALERTS, action="network_map.host")
    with database_service.session() as conn:
        flows, start, end = _window_flows(conn, MapFilters(session_id, window_minutes))
        alerts = _open_alerts(conn)
        session = conn.execute("SELECT interface_name FROM monitoring_sessions WHERE id = ?", (session_id,)).fetchone()
        mine = [a for a in alerts if host in hosts_in_evidence(a["evidence"])]
        incident_rows = conn.execute(
            "SELECT DISTINCT i.id, i.title, i.status, i.classification FROM incidents i JOIN incident_alerts ia "
            "ON ia.incident_id = i.id WHERE ia.alert_id IN ({}) ORDER BY i.id DESC".format(
                ", ".join("?" for _ in mine) or "NULL"), [a["id"] for a in mine]).fetchall()
        alert_rows = conn.execute(
            "SELECT id, alert_type, severity, category, status, created_at FROM alerts WHERE id IN ({}) "
            "ORDER BY id DESC".format(", ".join("?" for _ in mine) or "NULL"), [a["id"] for a in mine]).fetchall()
        interface = session["interface_name"] if session else None
        forecast = conn.execute(
            "SELECT timestamp, forecast_horizon_seconds, predicted_utilization_ratio, predicted_throughput_bps, "
            "congestion_risk, model_version FROM congestion_predictions WHERE interface_name IS ? "
            "ORDER BY timestamp DESC, forecast_horizon_seconds LIMIT 1", (interface,)).fetchone()
    host_flows = [f for f in flows if f["src_ip"] == host or f["dst_ip"] == host]
    flagged_share = (sum(f["flagged"] for f in host_flows) / len(host_flows)) if host_flows else None
    in_incident = any(r["status"] in ("open", "investigating") for r in incident_rows)
    return {
        "host": host, "window": [start, end], "flows": host_flows[:200], "flow_count": len(host_flows),
        "bytes": sum(int(f["byte_count"] or 0) for f in host_flows), "flagged_share": flagged_share,
        "alerts": [dict(r) for r in alert_rows], "incidents": [dict(r) for r in incident_rows],
        "forecast": dict(forecast) if forecast else None, "interface": interface,
        "risk_score": host_risk_score([a["severity"] for a in mine], flagged_share, in_incident),
    }


def session_protocols(principal: Principal, session_id: int) -> List[str]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="network_map.view")
    with database_service.session() as conn:
        return [r[0] for r in conn.execute("SELECT DISTINCT protocol FROM network_flows WHERE session_id = ? "
                                           "AND protocol IS NOT NULL ORDER BY protocol", (session_id,))]
