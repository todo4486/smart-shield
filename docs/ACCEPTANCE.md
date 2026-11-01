# Acceptance results

Run them yourself at any time. It works on a throwaway copy of your database, sends no packets, and takes about 10 seconds:

```
python -m scripts.acceptance --interface en0
```

Last run: 2026-10-31, on macOS, using the registered live-compatible models (`20261030-224908-253`) trained on the bundled
synthetic sample. Simulated tests step the real engine one second at a time, so they do not depend on the machine staying awake.
The same flow was also run in real time and clicked through in a browser during M5.

| # | Test | Result | What was seen | Where it was checked |
| --- | --- | --- | --- | --- |
| 1 | Actual incoming and outgoing traffic | **Pass** | Rates from `en0`, stored as `measured` | Real interface, passive counters |
| 2 | Individual hosts and their bandwidth | **Limited** | 12 hosts with rates | Simulation only. Real per-host capture needs packet permission, which this Mac does not have |
| 3 | The Random Forest model runs | **Pass** | Flows scored by the registered, hash-verified model | Simulated flows through the real extractor and model |
| 4 | Controlled suspicious scenario | **Pass** | Bandwidth hog: records in memory, no packets | Simulation |
| 5 | Suspicious traffic identified | **Pass** | `10.20.1.99`, Anomalous flows, severity high | Simulation |
| 6 | A rate limit or policy is applied | **Pass** | Limit to 5.00 Mbit/s, approved by an administrator | Simulated link |
| 7 | Allocation changes dynamically | **Pass** | Restricted 0 → 5 Mbit/s, suspicious 10 → 0, available 50 → 55 | Simulation |
| 8 | Before and after | **Pass** | Target 65.2 → 5.0 Mbit/s, legitimate 34.8 → 40.0, utilization 100% → 45%, loss 13% → 0%, recovered | Simulation. Latency is unavailable |
| 9 | Recorded in the Incident Center | **Pass** | Incident with status Mitigation active, labelled simulation | Simulation |
| 10 | Reversed, policy restored | **Pass** | Nothing enforced, loss back to 13%, incident back to Detected | Simulation |
| 11 | Legitimate traffic gets its priority | **Limited** | Critical application 7.0 → 8.0 of its 8.0 Mbit/s once prioritized | Simulated link only |
| 12 | Live values collected, simulated labelled | **Pass** | Live stored as `measured`, simulated as `derived`, simulated incidents labelled | Both |

## What the project does not do yet

Be ready to say these plainly in the viva.

- **Real enforcement has not run in a real kernel.** The generated `pf` rules and `dnctl` commands pass the real parsers (`pfctl -n`,
  `dnctl -n`) and everything else is tested with a fake runner, because loading rules needs root. `tc` has never run, as this Mac has
  none. To prove `pf` on your Mac: `sudo .venv/bin/python -m scripts.manage enforcement-check --backend pf --interface en0 --install`,
  then `sudo chown -R "$USER" data artifacts`.
- **Real per-host capture has not run on this Mac.** It needs packet permission (Wireshark's ChmodBPF, or sudo). The path is tested
  with a fake sniffer and a real packet parsed in memory.
- **On a real link, class shares are a plan.** Approved limits, blocks and isolation are enforced per host, and class policies through
  `tc`. The spec asks for every control to reach the adapter, and this part does not.
- **Model figures say nothing about real networks.** The models were trained on bundled synthetic samples, whose patterns were also
  used to shape the simulated traffic. Confidence and false-positive risk are heuristics, not probabilities.
- **Flood recovery is partial by design.** A controller on your side cannot free capacity a flood has already filled upstream.
- **Forecasts need history.** A forecaster sampling every 5 minutes needs about an hour of data, longer than the longest simulation,
  so preventive recommendations are shown on imported telemetry or a replay.
