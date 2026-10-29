# UI, animation & feature upgrade: plan

Source: `SMART_SHIELD_UI_UPGRADE.md`. **Baseline: 285 tests passing** (commit `c86dd7b`, Streamlit 1.66.1, Plotly 7.1.0).

## What already exists (reused, not rebuilt)

| Need in the spec | Already in the repo |
| --- | --- |
| Dark theme colours | `.streamlit/config.toml`, `assets/styles.css`, `components/theme.py` (same palette) |
| Provenance labels | `measured / derived / predicted / configured / unavailable` chips (`components/ui.py`) |
| `st.fragment` live refresh, `st.dialog`, `st.toast`, plot click events | Streamlit 1.66 has all of them; no upgrade needed |
| Water-filling allocator + 500 randomized property tests | `services/bandwidth_allocation.py`, `tests/test_bandwidth_allocation.py` |
| Correlation into incidents, "congestion is not an attack" | `services/incident_correlation_service.py` |
| Alert triage + notes + audit | `services/alert_service.py` (alerts only; incidents have status only) |
| Model verification ✓ | SHA-256 check in `services/model_registry_service.py` |
| HTML report | `services/reporting_service.py` |
| `tc` enforcement (admin, confirmed, audited, reversible) | `services/traffic_shaping_service.py`, `views/bandwidth.py` |

## New dependencies

**None planned.** Everything is built with Plotly + Streamlit + a small offline HTML/JS component (`st.components.v1.html`, inline JS, no CDN) for the animated map particles and the pipeline walk-through. `streamlit-agraph`/`pyvis` are not installed and are not needed.
No PDF library is installed, so reports stay **HTML (print to PDF from the browser)**.

## Phase map

### Phase 1: foundation
| Item | Files |
| --- | --- |
| Theme tokens, light/dark toggle, fonts | `assets/styles.css`, `components/theme.py`, `.streamlit/config.toml`; fonts in `static/fonts/` (Streamlit serves local files only from `static/`). Light/dark is Streamlit's own theme switch (⋮ → Settings), which also restyles every widget |
| One severity system (Info…Critical) with icon + label | new `components/severity.py`; used by every alert/incident view |
| Source badges `LIVE / COUNTERS / DATASET / DATASET REPLAY` | new `services/data_source.py` (pure: session source type + mode → badge), `components/ui.py` |
| Header strip (health ring, flows/s, active incidents, top link risk, models ✓, source) | new `services/header_service.py` + `components/header.py`, called from `app.py` on every page |
| Toasts for new High/Critical incidents | `components/header.py` (remembers last seen incident id per session) |
| Reduce-motion preference | migration `006_ui_preferences` adds `user_preferences`; `services/preferences_service.py`; Settings page |
| Live panels via `@st.fragment(run_every=…)`, cached heavy loads | `components/live_capture.py`, overview tiles |

### Phase 2: core visuals
| Item | Files |
| --- | --- |
| 3.1 Live network map | new `services/network_map_service.py` (pure graph builder: top-N nodes + "others", edge throughput, risk, severity rings); `components/network_map.py` (Plotly graph + offline particle overlay); new page `views/network_map.py` |
| 3.2 Incident timeline, triage, notes, permalinks | `services/incident_correlation_service.py` (timeline data), migration `007` (incident `acknowledged` status, `assigned_to`, `incident_events` notes/history); `views/incident_center.py` with `st.query_params["incident"]` |
| 3.3 Forecast band + "now" + countdown, baseline table, gauges, animated water-filling | `services/forecasting.py` (residual intervals from stored test residuals, labelled), `views/predictnet.py`, new `components/waterfill.py` (Plotly frames from the existing `allocate()` rounds) |

### Phase 3: demo power
| Item | Files |
| --- | --- |
| 3.8 Replay mode | new `services/replay_service.py` (feeds a registered labelled dataset through the existing inference path at 1×–30×, `source_type='replay'` via migration `008`); `views/replay.py`; banner in `components/header.py`; one-click admin clear (audited) |
| 3.9 How it works | new `views/how_it_works.py` + `components/pipeline.py` (step-through, real flow from current/replay data) |
| 3.5 Why was this flagged? | new `services/explainability_service.py` (global RF importances + per-flow deviation from the benign median + template sentence) |
| 3.6 MITRE ATT&CK | new `services/mitre.py` (static table), badges on alerts/incidents |

### Phase 4: analyst tools
| Item | Files |
| --- | --- |
| 3.4 What-if simulator | new `views/what_if.py`; calls the same `bandwidth_allocation.allocate()`; "Apply as shaping policy…" hands off to the existing enforcement flow |
| 3.7 Host risk, top talkers, heatmap, Sankey | new `services/host_insights_service.py` (documented score formula), `views/insights.py` |
| 3.10 Suppression rules | migration `009` (`suppression_rules`, `alerts.suppressed_by_rule`), `services/suppression_service.py`, applied inside `alert_service.create_alert` (alert still stored, flagged suppressed) |
| 3.13 Safer enforcement UX | `views/bandwidth.py` (`st.dialog` with before/after chart, exact `tc` argv, typed confirm, active policies + revert) |

### Phase 5: trust & output
| Item | Files |
| --- | --- |
| 3.11 Model health + PSI drift | `services/model_health_service.py`, `views/model_health.py`; training stores per-feature bin edges/proportions in metadata (see decision 4) |
| 3.12 Incident report + weekly summary | `services/reporting_service.py`, `views/reports.py` |

### Phase 6: final pass
Full tests, lint, click-through as admin and analyst, load test with the 12k-flow sample, README screenshots, replay demo guide, viva demo script.

## Conflicts with the current architecture (and what I propose)

1. **Fonts offline.** The spec wants Space Grotesk + JetBrains Mono bundled. They aren't in the repo; bundling means downloading the OFL font files (≈ 300 KB) once into `assets/fonts/`. Otherwise system fonts are used.
2. **Severity "Info".** The DB only allows `low…critical` for alerts. I'd use **Info only in the UI** (system notices, unavailable data), not as an alert severity, so no alert table change is needed.
3. **Incident triage.** Incidents today go `open → investigating → resolved → closed` with no assignee. I'd map **Acknowledge = investigating**, add an `assigned_to` column and an `incident_events` history/notes table (migration), all audited.
4. **Drift (PSI) needs training distributions.** Current models don't store them. Training would start saving per-feature histogram bins in the model metadata (no change to splits or model logic). **Existing models show "drift unavailable" until retrained** — no automatic retraining.
5. **Replay data.** The repo has no real CIC-IDS2017 files, only the **SAMPLE (synthetic)** CSVs (BENIGN, DDoS, DoS Hulk, PortScan, FTP-Patator; no SSH-Patator). Scenarios are built from whatever labelled datasets are registered and stay labelled "synthetic" when they are. Replay shows the dataset's own timestamps on a replay clock with the `DATASET REPLAY` banner, rather than rewriting them to "now".
6. **Source badge "COUNTERS".** Maps to live capture in counter-only mode; imported telemetry/datasets get `DATASET`; replay gets `DATASET REPLAY`. Existing provenance chips stay alongside.
7. **Toast with Undo.** `st.toast` cannot hold buttons, so Undo lives in the Active policies panel the toast points to.
8. **Network map needs IPs.** Live flows and the sample datasets have IPs; datasets without IP columns show "map unavailable for this source", never invented hosts.

## Phase 3 notes (as built)

- **Migration 008** rebuilds `monitoring_sessions` to allow `source_type = 'replay'` (SQLite cannot alter a CHECK in place).
  The runner supports a `-- requires: foreign_keys_off` first line: foreign keys are off for that one migration, so
  `DROP TABLE` cannot cascade to flows/metrics, and `PRAGMA foreign_key_check` must be clean before it commits.
  It also adds `incidents.is_replay`.
- **Replay keeps dataset timestamps** (decision 5). The header shows the replay clock and replayed rows/second.
- **Correlation never mixes replay and real alerts**: they are clustered separately, and measured changes and
  forecasts in an incident come from the same side only.
- **Dev-only limitation**: editing a source file while the server runs makes Streamlit re-import the services, which
  creates a new replay engine and closes a running replay (the old thread notices and stops). Restart the replay.
  This does not happen in normal use.

## Phase 4 notes (as built)

- **Migration 009** adds `suppression_rules` (author, reason, expiry ≤ 90 days, status requested/active/rejected/revoked)
  and `alerts.suppressed_by_rule`. Rules apply to alerts raised while they are active. Suppressed alerts keep their
  status and history and are listed under *Show → Suppressed*; they are left out of the unresolved counts, header,
  correlation, swimlanes and network map. A host rule only matches when every flow of the alert is from/to that host.
- **What-if** calls `bandwidth_allocation.allocate()` directly (a test checks it against the allocator on 200 random
  inputs). "Propose as shaping policy…" (admin) saves a policy and a *proposed* recommendation; enforcing it still
  goes through accept → apply with typed confirmation.
- **Host insights** reuse the Network Map's host risk formula, so a host has one score everywhere.
- **Enforcement**: apply happens in an `st.dialog` with the before/after split, exact argv and typed confirmation.
  "Before" is the last policy Smart Shield applied (the live `tc` output is shown separately). Undo is the Revert
  button in *Active policies* (a toast cannot hold buttons, decision 7). The dialog needs Linux `tc`, so it is
  covered by tests with a mocked `tc` rather than in a browser on macOS.

## Phase 5 notes (as built)

- **No migration.** Training now stores `feature_distributions` (decile bins and shares of the TRAINING split, per
  feature) in the model's metadata; splits and model logic are unchanged. Older models show "drift unavailable"
  until retrained.
- **Model health** (`views/model_health.py`): cards with data, split, held-out metrics, confusion matrix and the
  SHA-256 check; a read-only PSI check per top feature against a replay/live session (stored flow features) or a
  registered dataset. The warning threshold and feature count are admin settings (`model_health.drift`, audited).
- **Reports**: one-click incident report and a weekly summary, as script-free HTML with an inline SVG timeline
  (no PDF library is installed; print to PDF from the browser). The weekly summary leaves out DATASET REPLAY data
  and suppressed alerts (and says how many). Forecast accuracy matches each stored forecast to the closest
  measurement of the same link and quantity within 150 s; utilization and throughput are scored separately.
