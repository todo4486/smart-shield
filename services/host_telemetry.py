"""Per-host live bandwidth: what each IP address sent and received, measured from captured packets.

HostMeter runs inside the capture worker (packets mode). Every captured IP packet adds its wire length to the
sender's "sent" counters and the receiver's "received" counters. At each sampling interval the counters become
rates (bytes and packets per second over the measured interval) and are reset, so a sample describes exactly
one interval. Active connections per host are the open 5-tuple flows that host is part of at that moment.

Everything here is measured from packets seen on the monitored interface. A host that sent nothing in an
interval simply has no row for it (never a 0 stand-in), and hosts beyond MAX_HOSTS per sample are summed into
one "(other hosts)" row so memory and storage stay bounded.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence

MAX_HOSTS = 200
OTHER = "(other hosts)"


def wire_length(packet: Sequence[Any]) -> int:
    """Bytes on the wire for a packet summary: the IP length when known (9th field), else the payload length."""
    if len(packet) > 8 and packet[8] is not None:
        return max(0, int(packet[8]))
    return max(0, int(packet[6]))


class HostMeter:
    def __init__(self, max_hosts: int = MAX_HOSTS):
        self.max_hosts = max_hosts
        self._sent_bytes: Dict[str, int] = defaultdict(int)
        self._recv_bytes: Dict[str, int] = defaultdict(int)
        self._sent_packets: Dict[str, int] = defaultdict(int)
        self._recv_packets: Dict[str, int] = defaultdict(int)

    def add(self, packet: Sequence[Any]) -> None:
        src, dst, length = str(packet[1]), str(packet[2]), wire_length(packet)
        self._sent_bytes[src] += length
        self._sent_packets[src] += 1
        self._recv_bytes[dst] += length
        self._recv_packets[dst] += 1

    def sample(self, seconds: float, connections: Optional[Dict[str, int]] = None) -> List[Dict[str, Any]]:
        """Rates for the interval just ended, busiest hosts first; resets the counters."""
        if seconds <= 0:
            raise ValueError("A sample needs a positive interval.")
        hosts = set(self._sent_bytes) | set(self._recv_bytes)
        connections = connections or {}
        rows = [{
            "host": host,
            "sent_bps": 8 * self._sent_bytes.get(host, 0) / seconds,
            "received_bps": 8 * self._recv_bytes.get(host, 0) / seconds,
            "sent_pps": self._sent_packets.get(host, 0) / seconds,
            "received_pps": self._recv_packets.get(host, 0) / seconds,
            "active_connections": int(connections.get(host, 0)),
        } for host in hosts]
        rows.sort(key=lambda r: (-(r["sent_bps"] + r["received_bps"]), r["host"]))
        if len(rows) > self.max_hosts:
            kept, rest = rows[:self.max_hosts - 1], rows[self.max_hosts - 1:]
            other = {"host": OTHER, "active_connections": sum(r["active_connections"] for r in rest)}
            for key in ("sent_bps", "received_bps", "sent_pps", "received_pps"):
                other[key] = sum(r[key] for r in rest)
            rows = kept + [other]
        self._sent_bytes.clear()
        self._recv_bytes.clear()
        self._sent_packets.clear()
        self._recv_packets.clear()
        return rows


def connections_by_host(flow_keys: Iterable[tuple]) -> Dict[str, int]:
    """Open flows per host from FlowTable keys: (proto, (ip_a, port_a), (ip_b, port_b))."""
    counts: Counter = Counter()
    for key in flow_keys:
        _, (ip_a, _), (ip_b, _) = key
        counts[str(ip_a)] += 1
        if ip_b != ip_a:
            counts[str(ip_b)] += 1
    return dict(counts)
