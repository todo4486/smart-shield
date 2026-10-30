"""The live network picture for the NOC view: link totals and per-host bandwidth.

Totals come from interface counters (measured). Per-host rates come from captured packets (measured) and exist only
in packets mode; in counters mode the host list is unavailable and says why. Hosts are identified only from what is
already observed: no reverse DNS or any other lookup is sent, because monitoring is passive.

A host's rate is its mean over the samples in the last HOST_WINDOW_SECONDS. Status is "suspicious" when the models
flagged at least one finished flow from that source in the last FLAG_WINDOW_SECONDS; it is a model verdict, not proof.
Capacity is only ever the value configured for the session: an OS link speed is not available bandwidth, so without
a configured capacity, utilization and available bandwidth are unavailable.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from repositories import telemetry_repository
from services import data_source, database_service
from services.authorization import Permission, Principal, require_permission
from services.host_telemetry import OTHER
from services.timeutil import parse_iso, to_iso

HOST_WINDOW_SECONDS = 15
FLAG_WINDOW_SECONDS = 300
HISTORY_SAMPLES = 300
LIVE_SOURCE_TYPES = ("live_capture",)
# Well-known destination ports only. It describes the port, not the application behind it.
SERVICE_PORTS = {
    20: "File transfer", 21: "File transfer", 22: "Remote access", 23: "Remote access", 25: "Email", 53: "DNS",
    80: "Web", 110: "Email", 123: "Time (NTP)", 143: "Email", 443: "Web", 445: "File sharing", 465: "Email",
    587: "Email", 853: "DNS", 993: "Email", 995: "Email", 3389: "Remote access", 3478: "Video / voice",
    5004: "Video / voice", 5060: "Video / voice", 8080: "Web", 8443: "Web",
}


@dataclass
class HostRow:
    host: str
    kind: str  # "This machine", "Local network", "Internet" or "Other"
    sent_bps: float
    received_bps: float
    sent_pps: float
    received_pps: float
    active_connections: int
    status: str  # "normal" or "suspicious"
    flagged_flows: int
    top_category: Optional[str]
    traffic: Optional[str]  # traffic class from observed destination ports, None until a flow has finished

    @property
    def total_bps(self) -> float:
        return self.sent_bps + self.received_bps


@dataclass
class LiveSnapshot:
    session_id: Optional[int]
    source: data_source.DataSource
    running: bool
    mode: Optional[str]
    interface: Optional[str]
    as_of: Optional[str]
    incoming_bps: Optional[float]
    outgoing_bps: Optional[float]
    incoming_pps: Optional[float]
    outgoing_pps: Optional[float]
    capacity_bps: Optional[float]
    utilization: Optional[float]
    available_bps: Optional[float]
    active_connections: Optional[int]
    hosts: List[HostRow] = field(default_factory=list)
    history: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


# ------------------------------------------------------------------ pure helpers

def host_kind(host: str, local_addresses: Set[str]) -> str:
    if host in local_addresses:
        return "This machine"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "Other"
    return "Local network" if address.is_private or address.is_link_local or address.is_multicast else "Internet"


def traffic_class(ports: Iterable[Optional[int]]) -> Optional[str]:
    """The most common service among destination ports; 'Other traffic' when none is well known; None if no flows."""
    counts: Dict[str, int] = {}
    for port in ports:
        name = SERVICE_PORTS.get(int(port), "Other traffic") if port is not None else "Other traffic"
        counts[name] = counts.get(name, 0) + 1
    if not counts:
        return None
    known = {k: v for k, v in counts.items() if k != "Other traffic"}
    return min(known or counts, key=lambda k: (-(known or counts)[k], k))


def summarize_hosts(samples: Sequence[Dict[str, Any]], flows: Sequence[Dict[str, Any]], local_addresses: Set[str],
                    intervals: int = 0) -> List[HostRow]:
    """Mean rates per host over the window's sampling intervals.

    `intervals` is how many interface samples the window holds. An interval where a host has no row means no packets
    of that host were seen then, so it correctly lowers the mean (this is a measured zero, not a missing value).
    """
    moments = {s["timestamp"] for s in samples}
    if not moments:
        return []
    totals: Dict[str, Dict[str, float]] = {}
    last_connections: Dict[str, tuple] = {}
    for s in samples:
        entry = totals.setdefault(s["host"], {"sent_bps": 0.0, "received_bps": 0.0, "sent_pps": 0.0, "received_pps": 0.0})
        for key in entry:
            entry[key] += float(s[key])
        seen = last_connections.get(s["host"])
        if seen is None or s["timestamp"] >= seen[0]:
            last_connections[s["host"]] = (s["timestamp"], int(s["active_connections"]))
    flagged: Dict[str, int] = {}
    categories: Dict[str, Dict[str, int]] = {}
    ports: Dict[str, List[Optional[int]]] = {}
    for f in flows:
        src = f.get("src_ip")
        if not src:
            continue
        ports.setdefault(src, []).append(f.get("dst_port"))
        verdict = f.get("intrusion_prediction")
        if verdict:
            flagged[src] = flagged.get(src, 0) + 1
            per = categories.setdefault(src, {})
            per[verdict] = per.get(verdict, 0) + 1
    count = max(len(moments), intervals)
    rows = []
    for host, entry in totals.items():
        per = categories.get(host, {})
        rows.append(HostRow(
            host, "Other" if host == OTHER else host_kind(host, local_addresses), entry["sent_bps"] / count,
            entry["received_bps"] / count, entry["sent_pps"] / count, entry["received_pps"] / count,
            last_connections[host][1], "suspicious" if flagged.get(host) else "normal", flagged.get(host, 0),
            min(per, key=lambda k: (-per[k], k)) if per else None, traffic_class(ports.get(host, []))))
    rows.sort(key=lambda r: (r.status != "suspicious", -r.total_bps, r.host))
    return rows


def link_figures(row: Optional[Dict[str, Any]], capacity_bps: Optional[float]) -> Dict[str, Optional[float]]:
    """Link totals from one interface sample. Without a configured capacity, utilization and available are None."""
    if row is None:
        return {"incoming_bps": None, "outgoing_bps": None, "incoming_pps": None, "outgoing_pps": None,
                "utilization": None, "available_bps": None}
    bits = lambda v: None if v is None else 8.0 * float(v)  # noqa: E731
    throughput = row.get("throughput_bps")
    available = None
    if capacity_bps and throughput is not None:
        available = max(0.0, float(capacity_bps) - float(throughput))
    return {"incoming_bps": bits(row.get("incoming_bytes_per_second")),
            "outgoing_bps": bits(row.get("outgoing_bytes_per_second")),
            "incoming_pps": row.get("incoming_packets_per_second"),
            "outgoing_pps": row.get("outgoing_packets_per_second"),
            "utilization": row.get("utilization_ratio"), "available_bps": available}


def _local_addresses() -> Set[str]:
    try:
        import psutil

        return {a.address.split("%")[0] for items in psutil.net_if_addrs().values() for a in items}
    except Exception:  # identification is a convenience: without it hosts are only labelled local or internet
        return set()


# ------------------------------------------------------------------ service API

def snapshot(principal: Principal, *, live_running: bool = False, live_session_id: Optional[int] = None,
             live_active_flows: Optional[int] = None) -> LiveSnapshot:
    """`live_*` describe the in-process capture (from the live monitor), which the database cannot know."""
    require_permission(principal, Permission.VIEW_DASHBOARD, action="live_network.view")
    with database_service.session() as conn:
        session = None
        if live_running and live_session_id is not None:
            session = conn.execute("SELECT * FROM monitoring_sessions WHERE id = ?", (live_session_id,)).fetchone()
        session = session or telemetry_repository.latest_session_with_metrics(conn, LIVE_SOURCE_TYPES)
        if session is None:
            return LiveSnapshot(None, data_source.classify(None), False, None, None, None, None, None, None, None, None,
                                None, None, None,
                                notes=["No live capture has run yet. Start one in Live Monitoring."])
        configuration = json.loads(session["configuration_json"]) if session["configuration_json"] else {}
        running = bool(live_running and session["id"] == live_session_id)
        mode = configuration.get("mode")
        metrics = [dict(r) for r in reversed(telemetry_repository.recent_metrics(conn, session["id"], HISTORY_SAMPLES))]
        newest_host = telemetry_repository.newest_host_metric_time(conn, session["id"])
        samples: List[Dict[str, Any]] = []
        flows: List[Dict[str, Any]] = []
        intervals = 0
        if newest_host:
            end = parse_iso(newest_host)
            window_start = end - timedelta(seconds=HOST_WINDOW_SECONDS)
            samples = [dict(r) for r in telemetry_repository.host_metrics_since(conn, session["id"], to_iso(window_start))]
            intervals = sum(1 for m in metrics if window_start <= parse_iso(m["timestamp"]) <= end)
            flows = [dict(r) for r in telemetry_repository.flows_of_session_since(
                conn, session["id"], to_iso(end - timedelta(seconds=FLAG_WINDOW_SECONDS)))]
    latest = metrics[-1] if metrics else None
    capacity = (latest or {}).get("configured_capacity_bps") or configuration.get("capacity_bps")
    figures = link_figures(latest, capacity)
    hosts = summarize_hosts(samples, flows, _local_addresses(), intervals)
    notes: List[str] = []
    if not running:
        notes.append("No capture is running, so this is the last capture's data, not the network right now.")
    if mode != "packets":
        notes.append("Per-host bandwidth is unavailable: this capture ran in interface-counter mode. Packet capture "
                     "is needed to see individual hosts.")
    if not capacity:
        notes.append("No link capacity was configured for this capture, so utilization and available bandwidth are "
                     "unavailable. Rates are still measured.")
    return LiveSnapshot(
        session["id"], data_source.classify(session["source_type"], live_running=running, live_mode=mode), running, mode,
        session["interface_name"], latest["timestamp"] if latest else None, figures["incoming_bps"],
        figures["outgoing_bps"], figures["incoming_pps"], figures["outgoing_pps"], capacity, figures["utilization"],
        figures["available_bps"], live_active_flows if running else None, hosts,
        [{"timestamp": m["timestamp"], "incoming_bps": link_figures(m, None)["incoming_bps"],
          "outgoing_bps": link_figures(m, None)["outgoing_bps"]} for m in metrics], notes)
