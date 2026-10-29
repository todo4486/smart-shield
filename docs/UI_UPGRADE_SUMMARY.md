# UI, animation and feature upgrade: summary

What was built for `SMART_SHIELD_UI_UPGRADE.md`, in six phases (commits `9ceec56` → final pass). The plan, the
conflicts found up front and the per-phase notes are in [`UI_UPGRADE_PLAN.md`](UI_UPGRADE_PLAN.md). The viva demo is
in [`VIVA_DEMO_SCRIPT.md`](VIVA_DEMO_SCRIPT.md).

## At a glance

| | Before | After |
| --- | --- | --- |
| Tests | 285 passing | **399 passing** (`pytest -q`, about 90 s) |
| Migrations | 001–005 | **006–009** added |
| Runtime dependencies | — | **none added** |
| Pages | 11 | **17** (Network Map, Host insights, Replay / demo, What-if simulator, Model health, How it works) |

## Features and files

### Look and feel (Phase 1)
- **SOC theme, light/dark, fonts.** `.streamlit/config.toml`, `assets/styles.css`, `components/theme.py`. Space Grotesk and
  JetBrains Mono are bundled in `static/fonts/` (OFL licences included), so nothing loads from a CDN.
- **One severity system** (Info < Low < Medium < High < Critical, icon + label, never colour alone).
  `services/severity.py`, `components/severity.py`.
- **Source badges** LIVE / COUNTERS / DATASET / DATASET REPLAY. `services/data_source.py`, `components/ui.py`.
- **Header strip on every page** (health ring, flows/s, active incidents, highest link risk, models ✓, source) and
  **toasts** for new high/critical incidents. `services/header_service.py`, `components/header.py` (an
  `@st.fragment(run_every=10)`, so only the strip refreshes).
- **Reduce motion** per user. Migration `006`, `services/preferences_service.py`, `views/settings.py`.

### Core visuals (Phase 2)
- **3.1 Network map.** `services/network_map_service.py` (top-N hosts + "Others", throughput, link risk, severity
  rings, deterministic spring layout, documented host risk score), `components/network_map.py`, `views/network_map.py`.
- **3.2 Incident timeline, triage, notes, permalinks.** Migration `007` (assignee, `incident_events`),
  `services/incident_correlation_service.py`, `repositories/incident_repository.py`, `views/incident_center.py`.
- **3.3 PredictNet visuals.** Risk gauges, forecast band (validation-residual q90, labelled), "now" marker, countdown
  card, baselines chart: `views/predictnet.py`, `services/congestion_prediction_service.py`. Animated water-filling from
  the allocator's own steps: `services/bandwidth_allocation.py` (records steps; results unchanged),
  `components/waterfill.py`.

### Demo power (Phase 3)
- **3.8 Replay / demo mode.** `services/replay_service.py` (engine, scenarios, clock, clear), `views/replay.py`,
  migration `008` (`source_type = 'replay'`, `incidents.is_replay`). Scoring is shared with dataset detection
  (`intrusion_inference_service.score_frame`), and correlation keeps replay and real alerts apart.
- **3.9 How it works.** `services/how_it_works_service.py`, `components/pipeline.py`, `views/how_it_works.py`.
- **3.5 Why was this flagged?** `services/explainability_service.py`, `components/explain.py`.
- **3.6 MITRE ATT&CK.** `services/mitre.py` (static table), `components/mitre.py`.

### Analyst tools (Phase 4)
- **3.4 What-if simulator.** `services/what_if_service.py`, `views/what_if.py`.
- **3.7 Host risk and insights.** `services/host_insights_service.py`, `views/insights.py`.
- **3.10 Alert noise control.** Migration `009`, `services/suppression_service.py`, applied in
  `alert_service.create_alert`; UI in `views/security_center.py` (Noise control tab, Suppressed filter).
- **3.13 Safer enforcement UX.** `traffic_shaping_service.plan_preview` / `active_policies`, `views/bandwidth.py`.

### Trust and output (Phase 5)
- **3.11 Model health and drift.** `services/drift.py` (PSI), `services/model_health_service.py`,
  `views/model_health.py`; training stores per-feature distributions (`intrusion_training_service.py`); drift settings
  in `settings_service.py`.
- **3.12 Reports.** `services/incident_report_service.py` (incident report, weekly summary, forecast accuracy),
  `views/reports.py`.

## Migrations

| Migration | Change |
| --- | --- |
| `006_ui_preferences` | `user_preferences` (reduce motion); an index for latest utilization per interface |
| `007_incident_triage` | `incidents.assigned_to`; `incident_events` (status changes, assignments, notes) |
| `008_replay_source` | Rebuilds `monitoring_sessions` to allow `source_type = 'replay'` (every row copied; foreign keys off for this migration only, `foreign_key_check` before commit); adds `incidents.is_replay` |
| `009_suppression_rules` | `suppression_rules` (author, reason, expiry, request/approve/revoke) and `alerts.suppressed_by_rule` |

No migration drops data. `database/schema.sql` is regenerated and its drift test passes.

## Dependencies

No runtime packages were added. Everything is built with Streamlit 1.66 and Plotly 7.1, which were already installed.
`pyflakes` was installed into the local virtual environment only to lint the code; it is not needed to run the app
and is not in `requirements.txt`.

## Rules kept

- **No fake data.** Every chart is built from stored rows. Empty states explain what to do. Unknown capacity means no
  utilization; unmatched forecasts are counted, not scored.
- **Passive only.** Nothing new sends traffic. Replay reads files; the what-if simulator never runs `tc`.
- **Roles enforced in services**, with denials audited; buttons are disabled with "Admin only" as a courtesy.
- **Every state-changing action is audited:** triage, assignment, notes, preferences, replay start/pause/speed/stop/
  clear, suppression create/request/approve/reject/revoke/unsuppress, what-if proposals, enforcement, settings,
  report generation.
- **Leakage-safe ML.** No split or model logic changed. Training only additionally stores training-split distributions.

## Done differently from the spec, and why

| Spec | What was built | Why |
| --- | --- | --- |
| Map with `streamlit-agraph`/`pyvis` | Plotly network graph with CSS-animated particles and halos | No new dependency; works offline; Reduce motion removes all motion |
| Water-filling with Plotly animation frames | CSS keyframes driven by the allocator's recorded steps | Plotly frames in Streamlit need a play button; CSS plays on its own and respects Reduce motion |
| Replay "as if arriving now" | Rows keep their dataset timestamps; a replay clock is shown | Rewriting timestamps would present recorded data as current. The UI still reacts live (map, timeline, toasts, flows/s) |
| "SSH brute force" scenario | Offered only when the dataset has Patator/brute-force rows | The bundled samples have FTP-Patator but no SSH-Patator; the page says so |
| Class probabilities | Share of trees voting, labelled as not a probability | Project rule: confidence is never presented as a calibrated probability |
| Toast with Undo | Toast points to Revert in Active policies | `st.toast` cannot hold buttons |
| Suppression applies to alerts | Applies to alerts raised while the rule is active | Changing old alerts silently would rewrite history; one-off alerts can be unsuppressed |
| Drift on recent live data | Live, replay or registered datasets | Dataset-detection flows do not store feature values |
| Incident report as PDF | Printable HTML (Print → Save as PDF) | No PDF library is installed |
| "Severity Info" for alerts | Info is a UI level only | The alerts table allows low…critical; no schema change was needed |

## Not verified, or limited by the OS

- **Map host click:** Streamlit did not receive Plotly selection events from the automated browser used for testing,
  so a real-browser click is unconfirmed. The "Or pick a host" list under the map always works.
- **Enforcement dialog:** needs Linux `tc`; covered by tests with a mocked `tc`. On macOS the controls show disabled
  with the reason.
- **Code edits during a replay:** Streamlit reloads the services and the running replay stops (the old thread notices
  and exits cleanly). Restart the replay. Not an issue in normal use.
- **Screenshots:** not included yet. The browser pane used for testing was too small to capture usable images.

## Final checks (Phase 6)

- `pytest -q`: **399 passed**. `pyflakes`: clean apart from intentional re-exports, import probes and a shared fixture.
- Every page rendered as **admin and as analyst** (Streamlit AppTest against a copy of the test database): 34 renders,
  0 exceptions.
- **Load check** with the 12,000-flow sample replayed at 30×: at most 0.12 s of work per one-second replay tick
  (mean 0.04 s); Network Map, Host insights and Incident Center render in under 0.2 s; one explanation takes 0.16 s.
