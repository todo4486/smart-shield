"""Bidirectional 5-tuple flow extraction from packet summaries (pure, no I/O).

A packet summary is (timestamp_s, src_ip, dst_ip, src_port, dst_port, protocol, payload_len, tcp_flags).

Flow rules (documented, CICFlowMeter-style)
* Key: the 5-tuple, normalized so both directions map to one flow. "Forward" is
  the direction of the first packet seen.
* Idle timeout (IDLE_TIMEOUT_S = 15 s): a flow with no packets for this long ends.
* Active timeout (ACTIVE_TIMEOUT_S = 120 s): a flow longer than this is cut and
  a new flow starts, so long transfers still produce timely records.
* TCP FIN or RST ends the flow once that packet has been counted.
* Lengths are transport payload bytes (as in CICFlowMeter). Durations and
  inter-arrival times are in microseconds, as in CIC-IDS2017.
* A flow with zero duration has no defined rate: rate features are None
  (later imputed like CIC's Infinity values), never 0.

`features()` produces exactly intrusion_features.LIVE_FLOW_FEATURES, which is
what makes a "live-compatible" model usable on live traffic.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from services.intrusion_features import LIVE_FLOW_FEATURES

IDLE_TIMEOUT_S = 15.0
ACTIVE_TIMEOUT_S = 120.0
MAX_ACTIVE_FLOWS = 50_000  # bounded memory: the oldest flows are flushed early beyond this
TCP_FIN = 0x01
TCP_RST = 0x04
PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

Packet = Tuple[float, str, str, Optional[int], Optional[int], int, int, int]


@dataclass
class _Stats:
    count: int = 0
    total: float = 0.0
    minimum: Optional[float] = None
    maximum: Optional[float] = None

    def add(self, value: float) -> None:
        self.count += 1
        self.total += value
        self.minimum = value if self.minimum is None else min(self.minimum, value)
        self.maximum = value if self.maximum is None else max(self.maximum, value)

    @property
    def mean(self) -> Optional[float]:
        return self.total / self.count if self.count else None


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: int
    start: float
    last: float
    fwd: _Stats = field(default_factory=_Stats)
    bwd: _Stats = field(default_factory=_Stats)
    iat: _Stats = field(default_factory=_Stats)
    end_reason: str = ""

    @property
    def duration_s(self) -> float:
        return max(0.0, self.last - self.start)

    def add(self, ts: float, forward: bool, length: int) -> None:
        if self.fwd.count + self.bwd.count:
            self.iat.add((ts - self.last) * 1e6)
        (self.fwd if forward else self.bwd).add(float(length))
        self.last = max(self.last, ts)

    def features(self) -> Dict[str, Optional[float]]:
        duration_us = self.duration_s * 1e6
        seconds = self.duration_s
        packets = self.fwd.count + self.bwd.count
        total_bytes = self.fwd.total + self.bwd.total
        lengths = [v for v in (self.fwd.minimum, self.bwd.minimum) if v is not None]
        maxima = [v for v in (self.fwd.maximum, self.bwd.maximum) if v is not None]

        def rate(numerator: float) -> Optional[float]:
            return numerator / seconds if seconds > 0 else None

        values = {
            "flow_duration": duration_us,
            "total_fwd_packets": float(self.fwd.count),
            "total_backward_packets": float(self.bwd.count),
            "total_length_of_fwd_packets": self.fwd.total,
            "total_length_of_bwd_packets": self.bwd.total,
            "fwd_packet_length_max": self.fwd.maximum if self.fwd.count else 0.0,
            "fwd_packet_length_min": self.fwd.minimum if self.fwd.count else 0.0,
            "fwd_packet_length_mean": self.fwd.mean or 0.0,
            "bwd_packet_length_max": self.bwd.maximum if self.bwd.count else 0.0,
            "bwd_packet_length_min": self.bwd.minimum if self.bwd.count else 0.0,
            "bwd_packet_length_mean": self.bwd.mean or 0.0,
            "flow_bytes_s": rate(total_bytes),
            "flow_packets_s": rate(packets),
            "flow_iat_mean": self.iat.mean if self.iat.count else 0.0,
            "flow_iat_max": self.iat.maximum if self.iat.count else 0.0,
            "flow_iat_min": self.iat.minimum if self.iat.count else 0.0,
            "fwd_packets_s": rate(self.fwd.count),
            "bwd_packets_s": rate(self.bwd.count),
            "min_packet_length": min(lengths) if lengths else 0.0,
            "max_packet_length": max(maxima) if maxima else 0.0,
            "packet_length_mean": total_bytes / packets if packets else 0.0,
        }
        assert tuple(values) == LIVE_FLOW_FEATURES, "feature order must match LIVE_FLOW_FEATURES"
        return values

    def record(self) -> Dict[str, object]:
        """Everything needed to store the flow and score it."""
        return {
            "start": self.start, "end": self.last, "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "src_port": self.src_port, "dst_port": self.dst_port,
            "protocol": PROTOCOL_NAMES.get(self.protocol, str(self.protocol)),
            "packet_count": self.fwd.count + self.bwd.count, "byte_count": int(self.fwd.total + self.bwd.total),
            "duration_s": self.duration_s, "end_reason": self.end_reason, "features": self.features(),
        }


class FlowTable:
    """Aggregates packets into flows and returns finished flows."""

    def __init__(self, idle_timeout: float = IDLE_TIMEOUT_S, active_timeout: float = ACTIVE_TIMEOUT_S,
                 max_active: int = MAX_ACTIVE_FLOWS):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.max_active = max_active
        self.active: Dict[tuple, Flow] = {}
        self.evicted_for_memory = 0

    @staticmethod
    def _key(src: str, dst: str, sport, dport, proto: int) -> tuple:
        a, b = (src, sport), (dst, dport)
        return (proto,) + ((a, b) if (str(a) <= str(b)) else (b, a))

    def add(self, packet: Packet) -> List[Dict[str, object]]:
        ts, src, dst, sport, dport, proto, length, flags = packet
        finished = self.expire(ts)
        key = self._key(src, dst, sport, dport, proto)
        flow = self.active.get(key)
        if flow is not None and ts - flow.start > self.active_timeout:
            flow.end_reason = "active timeout"
            finished.append(self.active.pop(key).record())
            flow = None
        if flow is None:
            if len(self.active) >= self.max_active:
                oldest = min(self.active, key=lambda k: self.active[k].last)
                victim = self.active.pop(oldest)
                victim.end_reason = "memory limit"
                self.evicted_for_memory += 1
                finished.append(victim.record())
            flow = Flow(src, dst, sport, dport, proto, ts, ts)
            self.active[key] = flow
        forward = (src, sport) == (flow.src_ip, flow.src_port)
        flow.add(ts, forward, max(0, int(length)))
        if proto == 6 and flags & (TCP_FIN | TCP_RST):
            flow.end_reason = "tcp fin/rst"
            finished.append(self.active.pop(key).record())
        return finished

    def expire(self, now: float) -> List[Dict[str, object]]:
        done = [k for k, f in self.active.items() if now - f.last > self.idle_timeout]
        out = []
        for key in done:
            flow = self.active.pop(key)
            flow.end_reason = "idle timeout"
            out.append(flow.record())
        return out

    def flush(self) -> List[Dict[str, object]]:
        out = []
        for flow in self.active.values():
            flow.end_reason = flow.end_reason or "capture stopped"
            out.append(flow.record())
        self.active.clear()
        return out


def extract(packets: Iterable[Packet], **kwargs) -> List[Dict[str, object]]:
    """Convenience for tests and offline use: all flows from a packet sequence."""
    table = FlowTable(**kwargs)
    flows: List[Dict[str, object]] = []
    for packet in packets:
        flows.extend(table.add(packet))
    flows.extend(table.flush())
    return flows
