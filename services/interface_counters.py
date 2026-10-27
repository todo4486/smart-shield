"""Interface counters from psutil, turned into measured rates (pure helpers + a reader).

Rates come from the difference between two counter snapshots divided by the
elapsed time. A counter that goes backwards (interface reset or wrap) gives
no rate for that interval (None), never a negative or invented value.
NIC drop and error counters are reported as-is; they are not network packet
loss, so packet_loss_ratio stays unavailable unless something measures it.
"""
from __future__ import annotations

import re
import socket
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

HOST_RE = re.compile(r"^[A-Za-z0-9.\-:]{1,253}$")
BRACKETED_RE = re.compile(r"^\[([0-9A-Fa-f:.]{2,45})\]$")


@dataclass(frozen=True)
class Snapshot:
    at: float  # monotonic seconds
    bytes_recv: int
    bytes_sent: int
    packets_recv: int
    packets_sent: int
    errin: int = 0
    errout: int = 0
    dropin: int = 0
    dropout: int = 0


def read_snapshot(interface: str) -> Optional[Snapshot]:
    import psutil

    counters = psutil.net_io_counters(pernic=True).get(interface)
    if counters is None:
        return None
    return Snapshot(time.monotonic(), counters.bytes_recv, counters.bytes_sent, counters.packets_recv,
                    counters.packets_sent, counters.errin, counters.errout, counters.dropin, counters.dropout)


def list_interfaces() -> List[Dict[str, object]]:
    import psutil

    stats = psutil.net_if_stats()
    addresses = psutil.net_if_addrs()
    out = []
    for name in sorted(psutil.net_io_counters(pernic=True)):
        st = stats.get(name)
        ips = [a.address for a in addresses.get(name, []) if a.family in (socket.AF_INET, socket.AF_INET6)]
        out.append({"name": name, "is_up": bool(st and st.isup), "speed_mbps": (st.speed if st else 0) or None,
                    "addresses": ips})
    return out


def _delta(new: int, old: int) -> Optional[int]:
    return None if new < old else new - old


def _sum_deltas(*pairs: Tuple[int, int]) -> Optional[int]:
    """Sum of counter deltas, or None if any counter went backwards (never a 0 stand-in)."""
    deltas = [_delta(new, old) for new, old in pairs]
    return None if any(d is None for d in deltas) else sum(deltas)


def rates(previous: Snapshot, current: Snapshot, capacity_bps: Optional[float] = None) -> Optional[Dict[str, object]]:
    elapsed = current.at - previous.at
    if elapsed <= 0:
        return None
    recv = _delta(current.bytes_recv, previous.bytes_recv)
    sent = _delta(current.bytes_sent, previous.bytes_sent)
    precv = _delta(current.packets_recv, previous.packets_recv)
    psent = _delta(current.packets_sent, previous.packets_sent)
    incoming = None if recv is None else recv / elapsed
    outgoing = None if sent is None else sent / elapsed
    throughput = None if incoming is None or outgoing is None else (incoming + outgoing) * 8
    utilization = None
    if throughput is not None and capacity_bps:
        ratio = throughput / capacity_bps
        utilization = ratio if ratio <= 1 else None  # above capacity means the configured value is wrong
    return {
        "incoming_bytes_per_second": incoming,
        "outgoing_bytes_per_second": outgoing,
        "incoming_packets_per_second": None if precv is None else precv / elapsed,
        "outgoing_packets_per_second": None if psent is None else psent / elapsed,
        "throughput_bps": throughput,
        "utilization_ratio": utilization,
        "configured_capacity_bps": capacity_bps,
        "interval_seconds": elapsed,
        "nic_errors": _sum_deltas((current.errin, previous.errin), (current.errout, previous.errout)),
        "nic_drops": _sum_deltas((current.dropin, previous.dropin), (current.dropout, previous.dropout)),
    }


def validate_latency_target(target: Optional[str]) -> Optional[tuple]:
    """'host:port' or '[ipv6]:port' -> (host, port). Used for an explicitly configured TCP connect-time probe."""
    if not target:
        return None
    host, _, port = target.strip().rpartition(":")
    bracketed = BRACKETED_RE.match(host)
    if bracketed:
        host = bracketed.group(1)
    elif "[" in host or "]" in host:
        host = ""
    if not host or not HOST_RE.match(host) or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("Latency target must look like host:port, e.g. 192.168.1.1:443 or [2001:db8::1]:443.")
    return host, int(port)


def probe_latency_ms(host: str, port: int, timeout: float = 2.0) -> Optional[float]:
    """TCP connect time to one configured target (a single handshake, no payload). None on failure."""
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return (time.perf_counter() - started) * 1000
    except OSError:
        return None
