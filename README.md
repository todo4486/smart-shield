# Smart Shield — Powered by PredictNet

An AI-powered network intelligence platform for intrusion detection, congestion prediction and
intelligent bandwidth management (final-year CS project). Requirements: `docs/SPEC.md`. Project rules: `CLAUDE.md`.

**Status: Phase 7 (Live Monitoring).** Working now:

- Phase 1: authentication, database, shared UI, the Overview dashboard and Administration.
- Historical telemetry import and labelled intrusion-dataset registration, in **ML Laboratory → Data sources**.
- Monitoring sessions, with telemetry and flow charts, in **Live Monitoring**.
- Smart Shield training and evaluation, in **ML Laboratory → Smart Shield models**. It trains a Random Forest, an
  Isolation Forest and an attack-type model, and keeps them in a SHA-256-verified registry.
- Detection runs, grouped and deduplicated alerts, and alert triage, in the **Smart Shield Security Center**.
- PredictNet forecasting, in **ML Laboratory → PredictNet models**. It uses a chronological split, past-only
  features and last-value / moving-average baselines, then Random Forest and HistGradientBoosting, with one
  model per horizon.
- Forecast-vs-actual charts, congestion risk, congestion alerts with cooldowns, and forecast history, in the
  **PredictNet Congestion Center**.
- Validated, admin-only PredictNet settings (thresholds, horizons, alert rules), in **Settings**.
- **Bandwidth Management**:
  - Traffic-class policies and recommendations from deterministic weighted water-filling. Totals never exceed
    capacity, unmet demand is reported, and demand provenance is labelled.
  - Recommendation history with admin review.
  - Optional Linux `tc` enforcement: off by default, allow-listed, admin-only, confirmed, audited and
    reversible with rollback and emergency disable.
- **Incident Center**:
  - Correlates security and congestion alerts on the network timeline into incidents (combined / performance /
    security) with measured traffic changes, model outputs, rationale and investigation steps.
  - Congestion alone is never treated as an attack.
  - Incident triage with notes, and a unified view of all alerts.
- **Live Monitoring**:
  - Passive capture on interfaces an admin authorises in Settings. There are two modes: psutil interface counters
    (no special permission needed), and Scapy packet capture with flow extraction.
  - Flows are 5-tuple keyed, with a 15 s idle timeout and a 120 s active timeout.
  - Capture runs in a separate worker process with a bounded queue and batched writes. A singleton manager
    prevents duplicate workers. States are persisted, and live sessions orphaned by a restart are closed.
  - Live detection runs only with a live-compatible model; any other model is rejected and features are never
    zero-filled.
  - Latency is measured only if a target is configured.
- **Overview**: a network health summary built from persisted data, the most severe unresolved alerts from both
  engines, and a chart of the newest 24 hours of stored measurements.

Pages for later phases show a "Planned for Phase X" notice. Nothing is simulated.
File formats are described in `docs/TELEMETRY_SCHEMA.md`.

## Setup

Python 3.9+ (3.11+ recommended).

macOS / Linux:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m scripts.manage init-db
streamlit run app.py
```

Windows (PowerShell):
```
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python -m scripts.manage init-db
streamlit run app.py
```

The first account registered in the app becomes the administrator; later accounts are analysts.

**Want something to try it with?** `samples/` contains clearly labelled synthetic CSVs: 7 days of telemetry, a
file with deliberate errors, and CIC-IDS2017-style train and test days. Its README says what each file
demonstrates. Regenerate them with `python -m scripts.make_sample_data`.
Alternatively create an admin from the terminal: `python -m scripts.manage create-admin`.

## Commands

| Command | Purpose |
| --- | --- |
| `python -m scripts.manage init-db` | Create the database / apply pending migrations |
| `python -m scripts.manage create-admin` | Create an admin account (password prompted, never passed as an argument) |
| `python -m scripts.manage dump-schema` | Regenerate `database/schema.sql` after adding a migration |
| `python -m scripts.manage dump-schema --check` | Fail if `schema.sql` is out of date |
| `python -m scripts.make_sample_data` | Regenerate the labelled synthetic sample CSVs in `samples/` |
| `pytest -q` | Run the test suite (each test uses its own temporary database) |

## Architecture

```
app.py (router) → views/ (pages) → components/ (UI) → services/ (logic + authorization) → repositories/ (SQL) → SQLite
```

* Pages live in `views/` and are registered with `st.navigation`. Signed out, only the login page is registered.
* Every service call takes the acting `Principal` and checks a `Permission`; denials are audited.
* Migrations: `database/migrations/NNN_name.sql`, tracked in `schema_migrations`. `database/schema.sql` is generated.

## Known limitations

* Sessions live in Streamlit server memory: refreshing the browser or opening a new tab requires signing in again.
* Sessions end after `SMART_SHIELD_SESSION_IDLE_MINUTES` of inactivity (default 30).
* Lockout is per email address (no client IP is available to Streamlit apps).
* Live packet capture is not implemented yet (Phase 7). Monitoring sessions come from imports and datasets.
* Models are trained in the Streamlit process. A 200k-row Smart Shield run takes about a minute on a laptop.
  Training and scoring row limits keep memory bounded.
* Packet capture needs privileges: root or ChmodBPF on macOS, root or CAP_NET_RAW on Linux, and Npcap plus
  administrator rights on Windows. Without them only counter mode is offered, with the reason shown, and imported
  data keeps working.
* The live flow features approximate CICFlowMeter's definitions from packet headers. Live detection accuracy can
  differ from dataset accuracy.
* NIC drop counters are not network packet loss, so packet loss stays unavailable in live mode.
* Correlation of dataset-based Smart Shield alerts with congestion is by time only, because those alerts do not
  identify a network interface.
* Per-class bandwidth demand is entered or scaled from total throughput, because no data source measures it per class yet.
* Traffic shaping needs Linux with `tc` and CAP_NET_ADMIN. It is unavailable on macOS and Windows, where
  recommendation mode still works fully.
* Uploads are read into memory. Large CIC-IDS2017 days (≈ 200–300 MB) work, but need a few GB of free RAM.
