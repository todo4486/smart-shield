"""Generate clearly labelled SYNTHETIC sample CSVs for trying the app.

    python -m scripts.make_sample_data            # writes samples/*.csv

Nothing here is real traffic. Every file name starts with SAMPLE_ and ends with
_synthetic, and the suggested source/dataset names keep that label inside the
app. The output is deterministic (fixed seeds), so anyone can regenerate the
exact same files.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from config import PROJECT_ROOT

SAMPLES_DIR = PROJECT_ROOT / "samples"

# ------------------------------------------------------------ telemetry


def telemetry_frame(interval_seconds: int = 300, seed: int = 2026) -> pd.DataFrame:
    """Two interfaces with daily and weekly cycles, Friday 00:00 → the next Thursday 15:00 UTC.

    The campus uplink peaks near congestion on weekday afternoons (the file ends
    at such a peak) and has one large evening transfer on Tuesday. The lab link
    has no capacity column, so utilization stays unavailable for it.
    """
    rng = np.random.default_rng(seed)
    n = int((6 * 24 + 15) * 3600 / interval_seconds) + 1
    times = pd.date_range("2026-09-11T00:00:00Z", periods=n, freq=f"{interval_seconds}s")
    hours = times.hour + times.minute / 60
    weekday = times.dayofweek < 5
    frames = []

    # Campus uplink: 1 Gbit/s configured capacity.
    capacity = 1e9
    daily = 0.5 + 0.5 * np.sin((hours - 9) / 24 * 2 * np.pi)
    utilization = 0.12 + np.where(weekday, 0.70, 0.35) * daily + rng.normal(0, 0.012, n)
    transfer = (times >= "2026-09-15T19:00Z") & (times < "2026-09-15T21:30Z")  # Tuesday evening backup
    utilization = np.clip(utilization + np.where(transfer, 0.25, 0), 0.01, 0.99)
    throughput = utilization * capacity
    latency = 4 + 30 * np.maximum(utilization - 0.7, 0) ** 1.5 * 10 + rng.normal(0, 0.4, n)
    loss = np.where(utilization > 0.9, rng.uniform(0.005, 0.03, n), rng.uniform(0, 0.001, n))
    uplink = pd.DataFrame({
        "timestamp": times.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "interface_name": "campus-uplink",
        "incoming_bytes_per_second": (throughput * 0.68 / 8).round(0),
        "outgoing_bytes_per_second": (throughput * 0.32 / 8).round(0),
        "incoming_packets_per_second": (throughput * 0.68 / 8 / 900).round(1),
        "outgoing_packets_per_second": (throughput * 0.32 / 8 / 400).round(1),
        "throughput_bps": throughput.round(0),
        "utilization_ratio": utilization.round(4),
        "latency_ms": np.maximum(latency, 0.5).round(2),
        "packet_loss_ratio": loss.round(5),
        "configured_capacity_bps": capacity,
    })
    # A few unmeasured cells: realistic gaps, left empty (never 0).
    for column in ("latency_ms", "packet_loss_ratio"):
        uplink.loc[rng.choice(n, size=25, replace=False), column] = np.nan
    frames.append(uplink)

    # Lab link: rates only, no capacity, so utilization must stay unavailable.
    lab_rate = 2e6 + 1.5e6 * np.sin((hours - 13) / 24 * 2 * np.pi) + rng.normal(0, 1.5e5, n)
    lab = pd.DataFrame({
        "timestamp": times.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "interface_name": "lab-link",
        "incoming_bytes_per_second": np.maximum(lab_rate * 0.6, 0).round(0),
        "outgoing_bytes_per_second": np.maximum(lab_rate * 0.4, 0).round(0),
        "latency_ms": (2 + rng.normal(0, 0.2, n)).round(2),
    })
    frames.append(lab)
    return pd.concat(frames, ignore_index=True)


def telemetry_with_errors_frame() -> pd.DataFrame:
    """A small file with deliberate mistakes, to show the import validation report."""
    rows = [
        ("2026-09-20T00:00:00Z", "edge-1", "1200000", "400000", "0.42", "12.1"),
        ("2026-09-20T00:05:00Z", "edge-1", "1250000", "410000", "0.44", ""),           # missing latency: kept, partial
        ("20/09/2026 00:10", "edge-1", "1300000", "420000", "0.45", "12.4"),            # not ISO-8601
        ("2026-09-20T00:15:00", "edge-1", "1310000", "425000", "0.45", "12.0"),          # no timezone
        ("2026-09-20T00:20:00Z", "edge-1", "-5", "430000", "0.46", "12.2"),              # negative rate
        ("2026-09-20T00:25:00Z", "edge-1", "1330000", "440000", "1.7", "12.6"),          # ratio above 1
        ("2026-09-20T00:30:00Z", "edge-1", "n/a", "445000", "0.47", "12.9"),             # not a number
        ("2026-09-20T00:35:00Z", "edge-1", "1350000", "450000", "0.48", "13.0"),
        ("2026-09-20T00:35:00Z", "edge-1", "1351000", "451000", "0.48", "13.0"),         # duplicate timestamp: first kept
        ("2026-09-20T00:40:00Z", "edge-1", "", "", "", ""),                              # no measurements
        ("2026-09-20T00:45:00Z", "edge-1", "1370000", "460000", "0.49", "13.1"),
    ]
    return pd.DataFrame(rows, columns=["timestamp", "interface_name", "incoming_bytes_per_second",
                                       "outgoing_bytes_per_second", "utilization_ratio", "latency_ms"])


# ------------------------------------------------------------ intrusion

PROFILES = {
    #               duration µs, fwd pkts, bwd pkts, pkt size, rate scale
    "BENIGN":      (1.5e6, 14, 12, 520, 4e3),
    "DDoS":        (4e4, 4, 2, 70, 3e5),
    "DoS Hulk":    (2e5, 7, 6, 300, 6e4),
    "PortScan":    (2e3, 1, 1, 2, 8e5),
    "FTP-Patator": (4e6, 10, 14, 90, 6e2),
}


def intrusion_frame(n: int, start: str, seed: int, mix: dict, span_hours: float = 8) -> pd.DataFrame:
    """CIC-IDS2017-shaped flows with overlapping class distributions and 1% label noise,
    so models score well but not perfectly."""
    rng = np.random.default_rng(seed)
    labels = rng.choice(list(mix), size=n, p=np.array(list(mix.values())) / sum(mix.values()))
    rows = {k: np.zeros(n) for k in (
        "flow_duration", "fwd", "bwd", "fwd_len", "bwd_len", "size_fwd", "size_bwd", "rate")}
    for label, (duration, fwd, bwd, size, rate) in PROFILES.items():
        mask = labels == label
        k = int(mask.sum())
        if not k:
            continue
        # 15% of attack flows imitate benign behaviour, which makes them hard to detect.
        stealth = (rng.random(k) < 0.15) & (label != "BENIGN")
        d, f, b, s, r = (np.where(stealth, benign, own) for benign, own in
                         zip(PROFILES["BENIGN"], (duration, fwd, bwd, size, rate)))
        spread = lambda scale: rng.lognormal(0, 0.55, k) * scale  # noqa: E731
        rows["flow_duration"][mask] = spread(d)
        rows["fwd"][mask] = np.maximum(1, spread(f).round())
        rows["bwd"][mask] = np.maximum(0, spread(b).round())
        rows["size_fwd"][mask] = spread(s)
        rows["size_bwd"][mask] = spread(s * 0.9)
        rows["rate"][mask] = spread(r)
    fwd_len = rows["fwd"] * rows["size_fwd"]
    bwd_len = rows["bwd"] * rows["size_bwd"]
    duration_s = np.maximum(rows["flow_duration"], 1) / 1e6
    total_packets = rows["fwd"] + rows["bwd"]
    sources = np.where(np.isin(labels, ["DDoS"]), [f"172.16.{i % 40}.{i % 200 + 1}" for i in range(n)],
                       [f"192.168.10.{i % 30 + 2}" for i in range(n)])
    destinations = np.where(labels == "BENIGN", rng.choice(["192.168.10.50", "192.168.10.51", "8.8.8.8"], n),
                            "192.168.10.50")
    ports = np.where(labels == "PortScan", rng.integers(1, 1024, n),
                     np.where(labels == "FTP-Patator", 21, rng.choice([80, 443, 53], n)))
    stamps = pd.Timestamp(start) + pd.to_timedelta(np.sort(rng.uniform(0, span_hours * 3600, n)), unit="s")
    observed = labels.copy()
    noise = rng.random(n) < 0.01
    observed[noise] = np.where(observed[noise] == "BENIGN", "DDoS", "BENIGN")
    frame = pd.DataFrame({
        "Flow ID": [f"{s}-{d}-{p}-{i}" for i, (s, d, p) in enumerate(zip(sources, destinations, ports))],
        "Source IP": sources, "Source Port": rng.integers(1024, 65535, n), "Destination IP": destinations,
        "Destination Port": ports, "Protocol": np.where(labels == "PortScan", 6, rng.choice([6, 17], n, p=[0.8, 0.2])),
        "Timestamp": stamps.strftime("%d/%m/%Y %H:%M:%S"),
        "Flow Duration": rows["flow_duration"].round(0),
        "Total Fwd Packets": rows["fwd"], "Total Backward Packets": rows["bwd"],
        "Total Length of Fwd Packets": fwd_len.round(0), "Total Length of Bwd Packets": bwd_len.round(0),
        "Fwd Packet Length Max": (rows["size_fwd"] * 1.6).round(0), "Fwd Packet Length Min": (rows["size_fwd"] * 0.3).round(0),
        "Fwd Packet Length Mean": rows["size_fwd"].round(2),
        "Bwd Packet Length Max": (rows["size_bwd"] * 1.6).round(0), "Bwd Packet Length Min": (rows["size_bwd"] * 0.3).round(0),
        "Bwd Packet Length Mean": rows["size_bwd"].round(2),
        "Flow Bytes/s": ((fwd_len + bwd_len) / duration_s).round(2),
        "Flow Packets/s": (total_packets / duration_s).round(3),
        "Flow IAT Mean": (rows["flow_duration"] / np.maximum(total_packets - 1, 1)).round(1),
        "Flow IAT Max": (rows["flow_duration"] / np.maximum(total_packets - 1, 1) * 2.5).round(1),
        "Flow IAT Min": (rows["flow_duration"] / np.maximum(total_packets - 1, 1) * 0.1).round(1),
        "Fwd Packets/s": (rows["fwd"] / duration_s).round(3), "Bwd Packets/s": (rows["bwd"] / duration_s).round(3),
        "Min Packet Length": (np.minimum(rows["size_fwd"], rows["size_bwd"]) * 0.3).round(0),
        "Max Packet Length": (np.maximum(rows["size_fwd"], rows["size_bwd"]) * 1.6).round(0),
        "Packet Length Mean": ((fwd_len + bwd_len) / np.maximum(total_packets, 1)).round(2),
        "Init_Win_bytes_forward": np.where(labels == "BENIGN", 29200, rng.choice([256, 1024, 29200], n)),
        "Label": observed,
    })
    # CIC quirk: zero-duration flows have infinite rates.
    zero = rng.choice(n, size=max(1, n // 500), replace=False)
    frame.loc[zero, ["Flow Bytes/s", "Flow Packets/s"]] = np.inf
    frame.columns = [" " + c if c not in ("Flow ID", "Label") else c for c in frame.columns]  # CIC leading spaces
    frame = frame.rename(columns={"Label": " Label"})
    return frame


# ---------------------------------------------------------------- main

FILES = {
    "SAMPLE_telemetry_7days_synthetic.csv": telemetry_frame,
    "SAMPLE_telemetry_with_errors_synthetic.csv": telemetry_with_errors_frame,
    "SAMPLE_intrusion_train_day_synthetic.csv": lambda: intrusion_frame(
        12_000, "2017-07-03 08:00:00", 101,
        {"BENIGN": 0.62, "DDoS": 0.14, "DoS Hulk": 0.10, "PortScan": 0.10, "FTP-Patator": 0.04}),
    "SAMPLE_intrusion_test_day_synthetic.csv": lambda: intrusion_frame(
        6_000, "2017-07-05 08:00:00", 202,
        {"BENIGN": 0.70, "DDoS": 0.10, "DoS Hulk": 0.08, "PortScan": 0.09, "FTP-Patator": 0.03}),
    # A DDoS burst during the telemetry file's congested peak (17 Sep 2026, 13:30-15:00 UTC), so detection plus a
    # PredictNet forecast produce a "Security + congestion" incident. Timestamps are already UTC (offset 0).
    "SAMPLE_intrusion_attack_during_peak_synthetic.csv": lambda: intrusion_frame(
        6_000, "2026-09-17 13:30:00", 303, {"BENIGN": 0.45, "DDoS": 0.45, "PortScan": 0.10}, span_hours=1.5),
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=SAMPLES_DIR)
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, build in FILES.items():
        frame = build()
        path = args.out / name
        frame.to_csv(path, index=False)
        print(f"Wrote {path} ({len(frame):,} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
