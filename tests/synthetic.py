"""Synthetic fixtures for tests ONLY. Never used by the application.

Benign and attack rows are drawn from clearly different distributions so the
pipeline can be exercised end to end on a few thousand rows.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from services.intrusion_features import LIVE_FLOW_FEATURES

TYPES = {
    "BENIGN": dict(duration=2e6, packets=12, size=500, rate=5e3),
    "DDoS": dict(duration=5e4, packets=3, size=60, rate=4e5),
    "PortScan": dict(duration=1e3, packets=1, size=0, rate=1e6),
}


def cic_like_frame(n: int = 3000, attack_share: float = 0.4, seed: int = 7, with_timestamp: bool = True,
                   extra_columns: bool = True) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    labels = rng.choice(["BENIGN", "DDoS", "PortScan"], size=n,
                        p=[1 - attack_share, attack_share * 0.7, attack_share * 0.3])
    data = {name: np.zeros(n) for name in LIVE_FLOW_FEATURES}
    for label, params in TYPES.items():
        mask = labels == label
        k = int(mask.sum())
        noise = lambda scale: rng.lognormal(0, 0.4, k) * scale  # noqa: E731
        data["flow_duration"][mask] = noise(params["duration"])
        data["total_fwd_packets"][mask] = np.maximum(1, noise(params["packets"]).round())
        data["total_backward_packets"][mask] = np.maximum(0, noise(params["packets"] * 0.8).round())
        for name in ("total_length_of_fwd_packets", "total_length_of_bwd_packets"):
            data[name][mask] = noise(params["size"] * params["packets"] + 1)
        for name in LIVE_FLOW_FEATURES:
            if name.endswith(("_max", "_min", "_mean")) and "iat" not in name:
                data[name][mask] = noise(params["size"] + 1)
            if "iat" in name:
                data[name][mask] = noise(params["duration"] / max(params["packets"], 1))
        for name in ("flow_bytes_s", "flow_packets_s", "fwd_packets_s", "bwd_packets_s"):
            data[name][mask] = noise(params["rate"])
    frame = pd.DataFrame(data)
    frame.loc[frame.index[:3], "flow_bytes_s"] = np.inf  # CIC quirk: infinite rates
    if extra_columns:
        frame["init_win_bytes_forward"] = np.where(labels == "BENIGN", 29200, 1024) + rng.integers(0, 50, n)
        frame["constant_flag"] = 0
    frame["destination_port"] = np.where(labels == "PortScan", rng.integers(1, 1024, n), 80)
    frame["source_ip"] = [f"10.0.{i % 200}.{i % 250}" for i in range(n)]
    frame["destination_ip"] = np.where(labels == "BENIGN", "192.168.1.10", "192.168.1.50")
    if with_timestamp:
        start = pd.Timestamp("2017-07-03 08:00:00")
        frame["timestamp"] = [(start + pd.Timedelta(seconds=int(i * 3))).strftime("%d/%m/%Y %H:%M:%S") for i in range(n)]
    frame["label"] = labels
    return frame


def to_cic_csv(frame: pd.DataFrame) -> bytes:
    """Write with CIC-style headers: leading spaces and Title Case."""
    renamed = {c: " " + c.replace("_", " ").title() if c != "label" else " Label" for c in frame.columns}
    return frame.rename(columns=renamed).to_csv(index=False).encode()


def telemetry_csv(days: float = 3, interval_seconds: int = 300, seed: int = 11, peak: float = 0.85,
                  capacity_bps: float = None, with_utilization: bool = True, gap: tuple = None) -> bytes:
    """Daily-cycle utilization with noise, ISO-8601 UTC timestamps. Test data only."""
    rng = np.random.default_rng(seed)
    n = int(days * 86400 / interval_seconds)
    times = pd.date_range("2026-10-01T00:00:00Z", periods=n, freq=f"{interval_seconds}s")
    hours = times.hour + times.minute / 60
    utilization = np.clip(0.15 + (peak - 0.15) * (0.5 + 0.5 * np.sin((hours - 8) / 24 * 2 * np.pi))
                          + rng.normal(0, 0.02, n), 0, 1)
    cap = capacity_bps or 100e6
    throughput = utilization * cap
    frame = pd.DataFrame({
        "timestamp": times.strftime("%Y-%m-%dT%H:%M:%SZ"), "interface_name": "eth0",
        "incoming_bytes_per_second": throughput * 0.7 / 8, "outgoing_bytes_per_second": throughput * 0.3 / 8,
        "latency_ms": 10 + 20 * utilization + rng.normal(0, 1, n),
    })
    if with_utilization:
        frame["utilization_ratio"] = utilization.round(4)
    if capacity_bps:
        frame["configured_capacity_bps"] = capacity_bps
    if gap:
        frame = frame.drop(frame.index[gap[0]:gap[1]])
    return frame.to_csv(index=False).encode()
