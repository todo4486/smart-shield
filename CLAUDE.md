# Smart Shield + PredictNet — Project Rules for Claude Code

Final-year CS project: a unified network-intelligence platform (Python + Streamlit).
- **Smart Shield**: ML intrusion detection, anomaly/DDoS detection, security alerts.
- **PredictNet**: congestion forecasting, congestion risk, bandwidth recommendations.

**The full requirements are in `docs/SPEC.md`. It is the source of truth.**
Re-read the relevant SPEC sections at the start of every phase.

## Golden rules (never break these)
1. No fake data. No fabricated traffic, predictions, metrics, accuracy, or monitoring states.
   Empty states explain what the user should do next. Demo or sample data must be clearly labelled as sample data.
2. Label every value's provenance in the UI and the DB: `measured`, `derived`, `predicted`,
   `configured`, or `unavailable`. Never present a prediction as a measurement.
   Never substitute 0 for a missing measurement.
3. If link capacity is unknown, show absolute rates and say utilization is unavailable. Never invent a percentage.
4. Congestion does not mean attack. The correlation engine must never conclude that on its own.
5. Monitoring is passive only. No packet injection, scanning, attack generation, or automatic blocking.
6. Never use `shell=True`. Never let the dashboard run arbitrary commands. Traffic shaping goes through an
   allow-listed backend (fixed operations, validated arguments, `subprocess.run([...])` with list args).
   It is off by default, admin-only, requires explicit confirmation, is audited, and is reversible.
7. Work in phases. Each phase must leave the app runnable with all tests passing. Stop and report at the end of a phase.

## Architecture
```
app.py (router) → views/ (pages) → components/ (UI) → services/ (logic) → repositories/ (SQL) → SQLite
```
- **Routing**: use `st.navigation` + `st.Page` with page files in `views/`. Do NOT create a `pages/` folder,
  because Streamlit auto-discovery would bypass the login gate. Before login, only the login page is registered.
  Every view also calls `require_principal()`, which `st.stop()`s if there is no session.
- **Business logic is never in view files.** Views call services only.
- **Authorization lives in services.** Every service function takes the acting `Principal` and calls
  `require_permission()`. Denials are written to the audit log. Hiding buttons is cosmetic only.

## Database
- Use raw `sqlite3` with a repository layer. WAL mode, `PRAGMA foreign_keys=ON`, busy timeout.
- Connections are autocommit. Write through a `session(write=bool)` context manager (BEGIN / BEGIN IMMEDIATE → COMMIT or ROLLBACK).
- All SQL is parameterized. Use CHECK constraints for roles, statuses, severities, risk levels, ports, and ratios (0–1).
- Migrations are `database/migrations/NNN_name.sql`, applied in order and tracked in `schema_migrations`.
  Never drop data to change the schema. `database/schema.sql` is GENERATED; a test fails if it drifts.
- Store timestamps as ISO-8601 UTC strings.
- Tables: everything in SPEC §11, plus `login_attempts`, `alert_events` (status history/notes),
  `incidents` + `incident_alerts` (correlation), and `app_settings` (validated key/value).
  `model_registry` also has `artifact_sha256` and a partial unique index giving one active model **per `model_family`**
  (intrusion_classifier, anomaly_detector, congestion_forecaster, congestion_classifier).

## Auth & sessions
- Hash with argon2-cffi; rehash on login when parameters change.
- Password policy: 10–128 chars, with uppercase, lowercase, and a digit.
- Lockout: N failures per normalized email key, tracked even for non-existent emails, with a dummy-hash verify
  so timing doesn't reveal accounts. Use generic login errors.
- No default admin. The FIRST registered user becomes admin (inside BEGIN IMMEDIATE); later users are analysts.
  CLI: `python -m scripts.manage init-db | create-admin | dump-schema`.
- Session is server-side `st.session_state` holding `user_id` + `last_activity`, with an idle timeout from `.env`.
  Reload the user from the DB on every rerun. Document the limitation: a browser refresh means signing in again.
- Admins cannot demote or deactivate the last admin.

## ML rules
- **Smart Shield**: CIC-IDS2017. Normalize column names, handle inf/NaN, use an explicit inspectable label map,
  and drop identifiers and leakage columns. Fit preprocessing on train only. Use train/val/test (time or capture-group
  split where possible). Use Random Forest, plus Isolation Forest fit on benign training data, plus an optional multiclass model.
  Report precision, recall, F1, confusion matrix, per-class metrics, and FPR. Never present confidence as a calibrated probability.
- **PredictNet**: chronological splits only (never shuffle). Lag and rolling features use past data only.
  Run baselines first (last value, moving average), then RandomForestRegressor or HistGradientBoostingRegressor.
  Report MAE, RMSE, R², and per-horizon error. Enforce a documented minimum history; refuse to train below it.
  Horizons are configurable and must be consistent with the sampling interval (default 5 min).
- **Artifacts**: save preprocessing + model together with joblib. Only load an artifact that is registered AND whose
  SHA-256 matches. A failed training run must never replace the active model. Every prediction stores the model id and version.
- **Live compatibility**: build a feature-compatibility report against the model's saved schema.
  Missing features mean the model is REJECTED for live use (never zero-fill). The ML Lab offers a
  "live-compatible feature set" option so live mode has a model it can genuinely run.

## Bandwidth allocation (deterministic, documented)
Weighted water-filling: grant every class its minimum (fail clearly if the sum of minimums exceeds usable capacity),
then share the remaining usable capacity (capacity × (1 − safety margin)) by priority weight, capped at
min(max, demand), and redistribute leftovers until nothing can change.
Invariants, all unit-tested:
- every allocation ≥ 0
- every allocation ≤ max
- total ≤ capacity
- unmet demand is reported
- identical inputs give identical output

## Live monitoring
- Scapy capture runs in a separate process managed by a singleton (`st.cache_resource`), so reruns never duplicate workers.
- Use bounded queues and batched DB writes.
- States are STOPPED / STARTING / RUNNING / STOPPING / ERROR, persisted in the database.
- Interface counters come from `psutil` (measured). Flows are 5-tuple keyed with documented idle/active timeouts.
- Latency is measured only if explicitly configured; otherwise it is `unavailable`.
- If capture is unsupported or permission is missing, explain why and keep dataset mode fully working.

## UI design system
- Colors: background #0B1220, cards #111A2E, borders #1E2A44, text #E6EBF5, muted #8B97AD, accent #3B82F6,
  ok #22C55E, warn #F59E0B, critical #EF4444.
- One shared CSS file and one shared Plotly layout. Pass every dynamic value through `html.escape()` before it goes into `st.markdown` HTML.
- Sidebar: `st.logo` shield at the top, then navigation, then user name and role badge, system/monitoring status, and logout.
- Keep the layout clean: few cards per row, readable charts, plain-language explanations of metrics.

## How to work
- Use the project venv (`.venv`) and keep `requirements.txt` current.
- Write tests alongside the code: pytest, small synthetic fixtures, a temporary DB per test (`SMART_SHIELD_DB_PATH` via monkeypatch),
  and mocks for OS capture and `tc`. Use `streamlit.testing.v1.AppTest` to prove that anonymous users only see the login page.
- Before reporting a phase as done:
  1. Run `pytest -q` and fix every failure.
  2. Boot `streamlit run app.py --server.headless true`, check it starts without errors, then stop it.
- End-of-phase report:
  - what was built
  - files changed
  - how they connect
  - exact run and test commands (Windows + macOS/Linux)
  - test results
  - what is unverified or OS-limited
- Commit at the end of each phase with a clear message.

## Commands
```
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS/Linux
pip install -r requirements.txt
python -m scripts.manage init-db
streamlit run app.py
pytest -q
```
