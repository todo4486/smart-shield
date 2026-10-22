"""Capture worker. Runs in its own process (or a thread in tests) and only observes.

Two modes
* "counters": samples psutil interface counters every interval. Works without
  special privileges.
* "packets":  also sniffs packets passively with Scapy (store=False, never
  sends anything) and turns them into flows with FlowTable. Needs capture
  permission (root/BPF access on macOS, CAP_NET_RAW on Linux, Npcap + admin on
  Windows).

Everything goes back to the app through one bounded queue. If the app falls
behind, messages are dropped and counted, so memory stays bounded, and the
count is reported. Message types: started, metrics, flows, error, stopped.
"""
from __future__ import annotations

import collections
import os
import queue as queue_module
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from services.flow_extractor import FlowTable
from services.interface_counters import probe_latency_ms, rates, read_snapshot, validate_latency_target

FLOW_BATCH = 500
MAX_PENDING_PACKETS = 100_000


def _iso(epoch: Optional[float] = None) -> str:
    moment = datetime.fromtimestamp(epoch, tz=timezone.utc) if epoch is not None else datetime.now(timezone.utc)
    return moment.isoformat(timespec="microseconds")


def summarize_packet(packet) -> Optional[tuple]:
    """Scapy packet -> (ts, src, dst, sport, dport, proto, payload_len, tcp_flags), or None for non-IP."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    if IP in packet:
        ip = packet[IP]
        proto = int(ip.proto)
    elif IPv6 in packet:
        ip = packet[IPv6]
        proto = int(ip.nh)
    else:
        return None
    sport = dport = None
    flags = 0
    if TCP in packet:
        layer = packet[TCP]
        sport, dport, flags = int(layer.sport), int(layer.dport), int(layer.flags)
        length = len(layer.payload)
    elif UDP in packet:
        layer = packet[UDP]
        sport, dport = int(layer.sport), int(layer.dport)
        length = len(layer.payload)
    else:
        length = len(ip.payload)
    return (float(packet.time), str(ip.src), str(ip.dst), sport, dport, proto, int(length), flags)


class _Sender:
    def __init__(self, out):
        self.out = out
        self.dropped = 0

    def put(self, message: Dict[str, Any]) -> None:
        try:
            self.out.put_nowait(message)
        except queue_module.Full:
            self.dropped += 1


def run(config: Dict[str, Any], out, stop_event, sniffer_factory=None) -> None:
    """Worker entry point. `config`: interface, mode, interval_seconds, capacity_bps, latency_target."""
    send = _Sender(out)
    interface = config["interface"]
    sniffer = None
    try:
        previous = read_snapshot(interface)
        if previous is None:
            send.put({"type": "error", "message": f"Interface {interface} was not found on this machine."})
            return
        latency = validate_latency_target(config.get("latency_target") or None)
        pending: collections.deque = collections.deque(maxlen=MAX_PENDING_PACKETS)
        table = FlowTable() if config["mode"] == "packets" else None
        if table is not None:
            sniffer = (sniffer_factory or _scapy_sniffer)(interface, pending)
            sniffer.start()
            time.sleep(0.5)
            error = getattr(sniffer, "exception", None)
            if error is not None or not getattr(sniffer, "running", True):
                raise PermissionError(str(error or "packet capture could not start"))
        send.put({"type": "started", "pid": os.getpid(), "mode": config["mode"], "at": _iso()})
        interval = float(config["interval_seconds"])
        next_sample = time.monotonic() + interval
        flows_seen = 0
        while not stop_event.is_set():
            if table is not None:
                finished = []
                while pending:
                    finished.extend(table.add(pending.popleft()))
                finished.extend(table.expire(time.time()))
                for start in range(0, len(finished), FLOW_BATCH):
                    send.put({"type": "flows", "flows": finished[start:start + FLOW_BATCH]})
                flows_seen += len(finished)
            if time.monotonic() >= next_sample:
                current = read_snapshot(interface)
                if current is None:
                    raise RuntimeError(f"Interface {interface} disappeared.")
                sample = rates(previous, current, config.get("capacity_bps"))
                previous = current
                next_sample += interval
                if sample is not None:
                    sample["latency_ms"] = probe_latency_ms(*latency) if latency else None
                    send.put({"type": "metrics", "at": _iso(), "sample": sample, "dropped_messages": send.dropped,
                              "pending_packets": len(pending), "active_flows": len(table.active) if table else None,
                              "flows_seen": flows_seen})
            stop_event.wait(0.2)
        if table is not None:
            remaining = table.flush()
            for start in range(0, len(remaining), FLOW_BATCH):
                send.put({"type": "flows", "flows": remaining[start:start + FLOW_BATCH]})
        send.put({"type": "stopped", "dropped_messages": send.dropped})
    except PermissionError as exc:
        send.put({"type": "error", "permission": True,
                  "message": f"Packet capture is not permitted on {interface}: {exc}. Interface-counter mode does "
                             "not need special permission."})
    except Exception as exc:  # report anything else to the app instead of dying silently
        send.put({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
    finally:
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass


def _scapy_sniffer(interface: str, pending: collections.deque):
    from scapy.all import AsyncSniffer

    def on_packet(packet) -> None:
        summary = summarize_packet(packet)
        if summary is not None:
            pending.append(summary)  # deque(maxlen) drops the oldest when full: memory stays bounded

    # Passive only: store=False, no send/sr calls anywhere in this project.
    return AsyncSniffer(iface=interface, filter="ip or ip6", store=False, prn=on_packet)
