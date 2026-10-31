# Adaptive Bandwidth Allocation & Automated Threat Mitigation: review and plan

Status: **approved 2026-10-30; M1, M2, M3 and M4 done, M5 next.** Decisions are recorded in section 6.

## 1. The project today

```
app.py (st.navigation router; signed out = login page only)
  └─ views/ (17 pages) ─ components/ (theme, charts, header strip, map, waterfill, …)
       └─ services/ (all logic + require_permission + audit)
            └─ repositories/ (parameterized SQL) ─ SQLite (WAL, migrations 001–009)
```

- **Frontend/backend:** one Python process, Streamlit 1.66. The browser already talks to the server over a WebSocket;
  live panels use `@st.fragment(run_every=…)`, so only those panels refresh (no page reloads).
- **Network data today:**
  - `services/capture_worker.py` runs in a separate process: *counters* mode (psutil, works without privileges) and
    *packets* mode (Scapy sniff, `store=False`, needs capture permission).
  - `services/flow_extractor.py` builds 5-tuple flows (15 s idle, 120 s active timeout) with CIC-style features.
  - `services/live_monitor_service.py` (singleton) drains a bounded queue, writes metrics and flows in batches, and
    scores finished flows with the active Random Forest when every feature it needs is computable live.
- **Random Forest:** `services/intrusion_training_service.py` trains the binary RF, the attack-type RF and the
  Isolation Forest; `intrusion_inference_service.score_frame` is the shared scoring path (dataset detection, replay).
  Artifacts load only through the hash-verified registry.
- **PredictNet:** `forecasting.py` / `congestion_*_service.py`: per-horizon forecasters checked against baselines,
  threshold-based risk, a minimum-history rule, residual error bands.
- **Bandwidth Management:** `bandwidth_allocation.allocate()` is a deterministic weighted water-filling allocator per
  *traffic class* (500 randomized invariant tests). Policies and recommendations are stored. Enforcement
  (`traffic_shaping_service.py`) builds Linux `tc` HTB classes with DSCP filters, list-argv only, admin-only, typed
  confirmation, audited, with rollback and emergency disable. It is **off by default**.
- **Incident Center:** correlation of alerts into incidents (`open → investigating → resolved → closed`), assignment,
  notes, history, permalinks, swimlanes, reports.

### Working vs. limited on this Mac (checked 2026-10-29/30)

| Piece | State |
| --- | --- |
| Live counters (psutil) on `en0` | **Works** (10 s test capture stored 4 measured samples) |
| Live packets → flows → per-host data → RF scoring | Code works (tests use a real spawned process), but **needs capture permission** on macOS (Wireshark's ChmodBPF or sudo) |
| Linux `tc` enforcement | Implemented and tested with a mocked `tc`; **not available on macOS** (no `tc`) |
| macOS `pfctl` / `dnctl` (dummynet) | Present on this Mac, **need root**; not integrated |
| NFQUEUE, eBPF, NetFlow/IPFIX, Open vSwitch/SDN | Not present / not integrated |

## 2. What the request needs that does not exist yet

1. **Per-host live bandwidth:** today flows are scored, but there is no rolling per-host in/out rate, no
   active-connection count per host, no host table.
2. **Host-level allocation:** the allocator works per traffic class; there is no per-host cap, no "suspicious" or
   "restricted" classes, no adaptive loop.
3. **A mitigation engine:** decisions (rate limit, prioritize, block, isolate), approvals, expiry, rollback,
   verification of recovery. None exists.
4. **Enforcement beyond class shaping:** per-host rate limits and blocks need tc `u32 match ip src` filters (Linux)
   or pf rules + dummynet pipes (macOS). Neither exists.
5. **Incident statuses** Detected / Mitigation pending / Mitigation active / False positive / Failed mitigation.
6. **Simulation mode:** synthetic traffic in-process (different from Replay, which plays recorded datasets).
7. **Before/after measurement** of a mitigation, from real samples in live mode.

## 3. Conflicts with the project rules (CLAUDE.md), and what I propose

| Request | Project rule | Proposal |
| --- | --- | --- |
| "Automatically initiate mitigation policies" | Rule 5: *passive only … no automatic blocking*. Rule 6: shaping is *off by default, admin-only, requires explicit confirmation* | Three policy levels an admin chooses: **Recommend** (default: engine proposes, admin approves each), **Auto rate-limit** (engine may apply *reversible, expiring rate limits only* when confidence, severity and repetition thresholds are all met), **Off**. Blocking and host isolation **always** need admin approval. Needs CLAUDE.md rules 5 and 6 amended by you |
| Temporary IP blocking, host isolation | Rule 5 (no blocking) | Admin-approved only, with reason, expiry and one-click rollback; isolation only for interfaces marked as a lab/test network |
| WebSockets or Server-Sent Events | Streamlit already uses a WebSocket per browser tab | Keep Streamlit fragments (0.5–2 s refresh, no page reload). A separate SSE server would need a second web server, its own auth and CORS, and would bypass the login gate |
| Simulation "generate synthetic network traffic" | Rule 1: demo data must be clearly labelled | Simulation generates traffic **records in memory only** (never packets), stored under a new `simulation` source type, with SIMULATION badges and a banner. Never mixed with live data |
| Enforcement "must affect the actual adapter in live mode" | Rule 6 (allow-listed backend, fixed operations) | New adapters behind the same allow-listed, list-argv, audited pattern: Linux `tc` (extended with per-host filters), macOS `pf` + `dnctl` (needs root), and a **dry-run adapter** that shows exactly what would run when no backend is usable |

## 4. Environment limits to be honest about

- **On this Mac, live enforcement needs root.** Without it, live mode can monitor (counters; per-host needs capture
  permission) and *recommend* mitigations, and the dry-run adapter shows the exact commands, but nothing is shaped.
- **A local controller cannot stop a flood that has already filled the internet link.** DDoS mitigation will say when
  mitigation must happen upstream (ISP/scrubbing service).
- **Latency/packet drop before and after** are shown only when measured (latency probe configured; drop counters from
  the enforcement backend where it reports them). Otherwise "unavailable".

## 5. Phases (each ends with tests passing, the app running, and a summary to you)

| Phase | Builds | Acceptance tests covered |
| --- | --- | --- |
| **M1 Host telemetry** | Rolling per-host rates (in/out bps, pps, active connections) from live flows; host table; interface capacity where the OS reports it (`psutil` speed), otherwise configured or unavailable; live overview tiles; fragment refresh | 1, 2, 12 |
| **M2 Simulation mode** | In-process synthetic traffic generator (normal mix, DDoS-like, port scan, bandwidth hog) feeding the same host/flow pipeline and the real RF; `simulation` source type (migration), banner and badges | 3, 4, 5, 12 |
| **M3 Allocation + mitigation engine** | Host-aware allocator built on `allocate()` (critical / normal / suspicious / restricted); severity scoring (confidence, severity, repetition, false-positive risk); policy levels; mitigation records with expiry, approval, rollback; before/after snapshots and recovery verification | 6, 7, 10, 11 |
| **M4 Enforcement adapters** | Adapter interface; Linux `tc` per-host rate limits and drops; macOS `pf` + `dnctl`; dry-run adapter; capability detection; emergency disable covers all | 6, 10 (live, where supported) |
| **M5 Dashboard + Incident Center** | Upgraded Bandwidth Management (overview, live allocation graph, host table with actions, controls), attack-mitigation before/after view with animated map, incident integration and new mitigation statuses, reversal from the incident | 7, 8, 9, 10 |
| **M6 PredictNet link** | 5/10-minute forecasts feeding preventive recommendations (automatic only if a validated model exists and policy allows); "unavailable" otherwise | — |
| **M7 Final pass** | Run all 12 acceptance tests, docs, demo script for the examiner | all |

## 6. Decisions (approved 2026-10-30)

1. **Automation:** three policy levels: Off, Recommend (default), Auto rate-limit (reversible, expiring rate limits
   only, when confidence, severity and repetition thresholds are all met). Blocking and isolation always need admin
   approval. CLAUDE.md rules 5 and 6 were amended to say this.
2. **Live enforcement:** macOS `pf` + `dnctl` adapter (works only when the app runs with sudo), Linux `tc`, and a
   dry-run adapter that shows the exact commands when neither is usable.
3. **Real-time:** Streamlit fragments over Streamlit's existing WebSocket.
4. **Demo:** a new in-memory simulation mode (labelled SIMULATION); Replay stays as it is.

## 7. Progress notes

- **M1 (host telemetry), done.** `services/host_telemetry.py` meters each captured packet per IP inside the capture
  worker. Migration `010` stores samples in `host_metrics`; `services/live_network_service.py` builds the snapshot;
  `components/live_network.py` is the new **Live network** tab in Bandwidth Management (2 s fragment).
  - Verified for real on `en0`: counter-mode rates through to the panel.
  - Not verified with real packets: this Mac has no capture permission. The worker path is tested with a fake sniffer
    and a real Scapy packet parsed in memory.
  - Capacity stays configured-or-unavailable: macOS reports link speed 0, and link speed is not available bandwidth.
- **M2 (simulation mode), done.** `services/simulation_service.py`, `views/simulation.py`, migration `011` (`simulation`
  source type, `incidents.is_simulation`).
  - Packet records are created in memory and go through the real `FlowTable` and the registered models; no verdict is
    scripted. Only a live-compatible classifier can be used (features are never zero-filled).
  - Bandwidth comes from a simple link model (equal cut when offered exceeds capacity), stored as `derived` and shown as
    *Simulated*. Stored flows are a representative sample. Latency is not modelled, so it stays unavailable.
  - Verified with models trained on the bundled synthetic sample: normal traffic 0 flagged, flood named DDoS, scan named
    PortScan, hog flagged by the anomaly detector. Those verdicts depend on the model and were shaped against that
    sample's benign range (the file-transfer pattern was adjusted once), so they say nothing about real-network accuracy.
  - Correlation now takes an `origin`, so a replay or simulation only ever groups its own alerts (this also fixed replay
    linking real alerts as a side effect).
- **M3 (allocation + mitigation engine), done.** `services/host_allocation.py`, `services/mitigation_scoring.py`,
  `services/mitigation_service.py`, `repositories/mitigation_repository.py`, `components/mitigation_panel.py`, migration
  `012` (`mitigation_actions`, `allocation_snapshots`), `MitigationSettings`.
  - Allocation is two levels of the existing `allocate()`: classes (critical, normal, suspicious, restricted), then hosts
    within a class. An unused guarantee is lent to other classes, unlike a stored policy plan.
  - Only flows flagged by the models start an assessment; a congested link alone never does (tested). Confidence, severity,
    repetition and false-positive risk are kept separately, and the risk figure is a documented heuristic, not a probability.
  - Auto rate-limit applies rate limits only. Blocking and isolation always need an administrator, a reason, an expiry and
    the target typed out (tested, including the engine trying to apply a block).
  - The simulated link is direction-aware: limiting outgoing traffic frees the link; limiting a flood from outside only
    stops it reaching the host. So the flood scenario ends in `partial` recovery with an upstream note, which is the honest
    result. `Recovered` is only reported from stored samples after the action.
  - Enforcement in this phase is the simulated link only. A real session's action is recorded as failed with the reason,
    and nothing evaluates live capture yet: both are M4. New incident statuses (Mitigation pending, etc.) are M5; for now
    actions link to the incident and add notes to it.
  - Verified in real time on a copy of the real database with the live-compatible model (see the M3 report); that says
    nothing about accuracy on a real network, since the model was trained on the synthetic sample.
- **M4 (enforcement adapters), done.** `services/enforcement_adapters.py` (fixed command plans), `services/enforcement_service.py`
  (capability detection, running commands, self-check), `components/enforcement_panel.py`, migration `013`
  (`interface_name`, `commands_json`), `mitigation_service.run_live_interval` and `emergency_disable`,
  `python -m scripts.manage enforcement-check`.
  - The backend is set only in the server's environment and defaults to `dry_run`. A backend that cannot work here stays
    in dry run and says why. A dry-run action is labelled everywhere, never counts as a limit in the allocation, and is
    never checked for recovery.
  - `tc` uses a clsact qdisc with flower filters, so it sits beside a class policy on the root qdisc. It polices (drops)
    rather than queues.
  - `pf` uses the anchor `com.apple/smart_shield`, which the default `/etc/pf.conf` already evaluates, plus a dummynet pipe
    per limit. It reloads the anchor to change it and never flushes, so the main ruleset is never touched.
  - Live capture now feeds the engine when it runs in packets mode with a live-compatible active model. With no configured
    capacity there is no allocation, and a limit is proposed from the measured rate alone.
  - Refused for every backend: loopback, multicast and unspecified addresses, protected hosts, and blocking or isolating this
    machine. Isolation needs a lab interface. Prioritizing by class is not available on a real link: it would rewrite per-host
    limits every interval, so class policies remain the way to do that.
  - Capture sees incoming packets before pf or tc acts on them. So recovery on a real link is only judged for traffic leaving
    this machine; for incoming traffic it reports `unavailable` instead of a false "not recovered".
  - Verified: the generated rules and dnctl command pass the real `pfctl -n` and `dnctl -n` parsers on this Mac (tests). That
    found one real error: pf refuses a dummynet rule with no direction.
  - **Not verified:** no rule has been loaded into a real kernel on either OS, because that needs root. `tc` commands have only
    run against a fake, since this Mac has no `tc`. `enforcement-check --install` is the way to prove pf or tc on a real machine.
  - Limits live in the kernel, so if the app is killed they stay until the next start, a rollback or a reboot; expiry only runs
    while the app runs. Live alerts are not correlated into incidents automatically, so live actions link to an incident only
    after correlation has been run: M5.
