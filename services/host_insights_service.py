"""Host risk and traffic insights for one flow source (a monitoring session with flows).

Everything is computed from stored flows and unresolved, unsuppressed alerts; nothing is sampled or estimated.

* Host risk score: the SAME formula as the Network Map (network_map_service.host_risk_score), so a host has one
  score everywhere:
      40 per open critical alert naming the host, 20 per high, 8 per medium, 3 per low
    + 30 × the share of the host's flows flagged by the classifier OR the anomaly detector
    + 15 if one of those alerts is in an open or investigating incident
  capped at 100.
* Sparkline: flagged flows of the host per time bucket across the source's time span (TREND_BUCKETS buckets).
* Top talkers: busiest hosts (bytes sent + received), destination ports and protocols.
* Heatmap: bytes or flagged flows by hour of day × day of week, in UTC, by flow start time.
* Sankey: source /24 subnet → protocol/port → destination host, for the largest paths by bytes.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from services import database_service
from services.authorization import Permission, Principal, require_permission
from services.network_map_service import _open_alerts, host_risk_score, hosts_in_evidence

MAX_ROWS = 200_000
TREND_BUCKETS = 24
TOP_N = 10
SANKEY_PATHS = 25
DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


class InsightsError(Exception):
    pass


@dataclass
class HostRow:
    host: str
    score: int
    alerts: Dict[str, int]
    flagged_share: Optional[float]
    in_incident: bool
    flows: int
    bytes: int
    trend: List[int]


# ------------------------------------------------------------------ pure helpers

def subnet(ip: Optional[str]) -> str:
    """'10.0.4.17' → '10.0.4.0/24'; IPv6 → /64; anything unparsable → 'unknown' (pure)."""
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return "unknown"
    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def host_frame(flows: pd.DataFrame) -> pd.DataFrame:
    """One row per (flow, endpoint): each flow counts for both its source and its destination (pure)."""
    if flows.empty:
        return pd.DataFrame(columns=["host", "timestamp", "byte_count", "flagged"])
    base = flows.assign(flagged=flows["intrusion_prediction"].notna())
    parts = [base.rename(columns={col: "host"})[["host", "timestamp", "byte_count", "flagged"]]
             for col in ("src_ip", "dst_ip")]
    out = pd.concat(parts, ignore_index=True)
    return out[out["host"].notna()]


def trend(times: pd.Series, flagged: pd.Series, start: pd.Timestamp, end: pd.Timestamp,
          buckets: int = TREND_BUCKETS) -> List[int]:
    """Flagged flows per equal time bucket between start and end (pure)."""
    if times.empty:
        return [0] * buckets
    span = max((end - start).total_seconds(), 1.0)
    index = np.minimum(((times - start).dt.total_seconds() / span * buckets).astype(int), buckets - 1)
    counts = np.bincount(index[flagged.to_numpy()], minlength=buckets)
    return [int(c) for c in counts[:buckets]]


def leaderboard(flows: pd.DataFrame, alerts: List[Dict[str, Any]], *, limit: int = 20) -> List[HostRow]:
    """Hosts ranked by risk score, then bytes (pure)."""
    hosts = host_frame(flows)
    if hosts.empty:
        return []
    times = pd.to_datetime(hosts["timestamp"], utc=True, format="ISO8601")
    start, end = times.min(), times.max()
    hosts = hosts.assign(_t=times)
    per_host: Dict[str, Dict[str, Any]] = {}
    for alert in alerts:
        for host in hosts_in_evidence(alert["evidence"]):
            entry = per_host.setdefault(host, {"severities": [], "in_incident": False})
            entry["severities"].append(alert["severity"])
            entry["in_incident"] |= bool(alert["in_incident"])
    rows = []
    for host, group in hosts.groupby("host"):
        info = per_host.get(host, {"severities": [], "in_incident": False})
        share = float(group["flagged"].mean()) if len(group) else None
        counts: Dict[str, int] = {}
        for s in info["severities"]:
            counts[s] = counts.get(s, 0) + 1
        rows.append(HostRow(str(host), host_risk_score(info["severities"], share, info["in_incident"]), counts, share,
                            info["in_incident"], int(len(group)), int(group["byte_count"].fillna(0).sum()),
                            trend(group["_t"], group["flagged"], start, end)))
    rows.sort(key=lambda r: (-r.score, -r.bytes, r.host))
    return rows[:limit]


def top_talkers(flows: pd.DataFrame, n: int = TOP_N) -> Dict[str, pd.DataFrame]:
    """Busiest hosts (bytes), destination ports and protocols (pure)."""
    hosts = host_frame(flows)
    out = {
        "hosts": (hosts.groupby("host").agg(bytes=("byte_count", "sum"), flows=("flagged", "size"))
                  .sort_values(["bytes", "flows"], ascending=False).head(n).reset_index()) if not hosts.empty
        else pd.DataFrame(columns=["host", "bytes", "flows"]),
    }
    for key, column in (("ports", "dst_port"), ("protocols", "protocol")):
        part = flows[flows[column].notna()] if column in flows else pd.DataFrame()
        out[key] = (part.groupby(column).agg(flows=("byte_count", "size"), bytes=("byte_count", "sum"))
                    .sort_values(["flows", "bytes"], ascending=False).head(n).reset_index()) if not part.empty \
            else pd.DataFrame(columns=[column, "flows", "bytes"])
    return out


def heatmap(flows: pd.DataFrame, value: str = "bytes") -> pd.DataFrame:
    """7 × 24 grid (weekday × UTC hour) of bytes or flagged flows; empty cells are 0 because they had no flows (pure)."""
    grid = pd.DataFrame(0.0, index=list(DAYS), columns=list(range(24)))
    if flows.empty:
        return grid
    times = pd.to_datetime(flows["timestamp"], utc=True, format="ISO8601")
    weights = flows["byte_count"].fillna(0).astype(float) if value == "bytes" else \
        flows["intrusion_prediction"].notna().astype(float)
    table = pd.DataFrame({"day": times.dt.dayofweek, "hour": times.dt.hour, "w": weights.to_numpy()})
    for (day, hour), total in table.groupby(["day", "hour"])["w"].sum().items():
        grid.iat[int(day), int(hour)] = float(total)
    return grid


def sankey(flows: pd.DataFrame, paths: int = SANKEY_PATHS) -> Dict[str, Any]:
    """Nodes and links for subnet → protocol/port → destination, for the largest paths by bytes (pure)."""
    if flows.empty:
        return {"labels": [], "source": [], "target": [], "value": [], "kinds": []}
    frame = pd.DataFrame({
        "subnet": flows["src_ip"].map(subnet),
        "service": flows["protocol"].fillna("?").astype(str) + "/" + flows["dst_port"].map(
            lambda p: "?" if pd.isna(p) else str(int(p))),
        "dest": flows["dst_ip"].fillna("unknown").astype(str),
        "bytes": flows["byte_count"].fillna(0).astype(float),
    })
    top = frame.groupby(["subnet", "service", "dest"])["bytes"].sum().sort_values(ascending=False).head(paths)
    top = top[top > 0]
    labels: List[str] = []
    kinds: List[str] = []
    index: Dict[tuple, int] = {}

    def node(kind: str, label: str) -> int:
        key = (kind, label)
        if key not in index:
            index[key] = len(labels)
            labels.append(label)
            kinds.append(kind)
        return index[key]

    links: Dict[tuple, float] = {}
    for (src, service, dest), value in top.items():
        a, b, c = node("subnet", src), node("service", service), node("dest", dest)
        links[(a, b)] = links.get((a, b), 0.0) + float(value)
        links[(b, c)] = links.get((b, c), 0.0) + float(value)
    return {"labels": labels, "kinds": kinds, "source": [k[0] for k in links], "target": [k[1] for k in links],
            "value": list(links.values())}


# ------------------------------------------------------------------ service API

def load_flows(principal: Principal, session_id: int) -> pd.DataFrame:
    require_permission(principal, Permission.VIEW_ALERTS, action="insights.view", details={"session_id": session_id})
    with database_service.session() as conn:
        rows = conn.execute(
            "SELECT timestamp, src_ip, dst_ip, dst_port, protocol, byte_count, intrusion_prediction FROM network_flows "
            "WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?", (session_id, MAX_ROWS)).fetchall()
    return pd.DataFrame([dict(r) for r in rows], columns=["timestamp", "src_ip", "dst_ip", "dst_port", "protocol",
                                                          "byte_count", "intrusion_prediction"])


def host_leaderboard(principal: Principal, session_id: int, flows: Optional[pd.DataFrame] = None,
                     limit: int = 20) -> List[HostRow]:
    require_permission(principal, Permission.VIEW_ALERTS, action="insights.view", details={"session_id": session_id})
    flows = load_flows(principal, session_id) if flows is None else flows
    with database_service.session() as conn:
        alerts = _open_alerts(conn)
    return leaderboard(flows, alerts, limit=limit)
