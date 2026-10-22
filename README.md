# Smart Shield: Powered by PredictNet

**Smart Shield: An AI-Powered Network Intelligence Platform for Intrusion Detection, Congestion Prediction, and
Intelligent Bandwidth Management.** This is a final-year Computer Science project built with Python and Streamlit.

- Requirements: [`docs/SPEC.md`](docs/SPEC.md)
- Engineering rules: [`CLAUDE.md`](CLAUDE.md)
- Acceptance criteria mapped to evidence: [`docs/EVALUATION.md`](docs/EVALUATION.md)
- Security review: [`docs/SECURITY_REVIEW.md`](docs/SECURITY_REVIEW.md)
- File formats: [`docs/TELEMETRY_SCHEMA.md`](docs/TELEMETRY_SCHEMA.md)

## What it does

| Engine | Question it answers | How |
| --- | --- | --- |
| **Smart Shield** | Is this traffic malicious? | Random Forest intrusion classifier, attack-type classifier, and an Isolation Forest anomaly detector trained on benign traffic (CIC-IDS2017 format) |
| **PredictNet** | Will the link congest, and how should capacity be shared? | Utilization forecasting compared against baselines, risk from configured thresholds, and weighted water-filling bandwidth recommendations |
| **Correlation** | Are these problems related? | Groups security and congestion alerts on the network timeline into incidents. **Congestion is never treated as an attack by itself** |

Principles that apply everywhere:

- **No fake data:** nothing is simulated or fabricated.
- **Labelled values:** every value is labelled *measured*, *derived*, *predicted*, *configured* or *unavailable*.
- **No invented percentages:** if link capacity is unknown, there is no utilization percentage.
- **Passive monitoring only:** no scanning, packet injection or automatic blocking.
- **Optional enforcement:** bandwidth enforcement is opt-in, admin-only, audited and reversible.

## Pages

| Page | Highlights |
| --- | --- |
| **Overview** | Health summary built from stored data, key traffic figures with provenance, and the worst open alerts from both engines |
| **Live Monitoring** | Passive capture on admin-authorised interfaces (counters, or packets and flows), live detection with a compatible model, and session history with charts |
| **Incident Center** | Correlated incidents with timeline, measured traffic change, model outputs, rationale and investigation steps, plus triage |
| **Smart Shield Security** | Run detection on datasets; alerts grouped per attack type and deduplicated; triage with history; severity rules |
| **PredictNet Congestion** | Forecasts per horizon with typical error, forecast-vs-actual charts, risk assessment, congestion history and model evaluation |
| **Bandwidth Management** | Traffic-class policies, recommendations with rationale and constraint checks, review, and optional Linux `tc` enforcement with rollback |
| **ML Laboratory** | Data import and validation, Smart Shield and PredictNet training and evaluation, and a SHA-256-verified model registry |
| **Reports** | Period reports from stored data, with CSV export (formula-safe) and a printable HTML report |
| **Settings** | PredictNet thresholds, horizons and alert rules; monitoring interfaces and latency target (admin) |
| **Administration** | Users and roles (the last admin is protected), the audit log, and data retention |
| **My account** | Change password |

## Quick start

Python 3.9+ works. **Python 3.11 or newer is strongly recommended:** several dependency security fixes need ≥ 3.10.
See [`docs/SECURITY_REVIEW.md`](docs/SECURITY_REVIEW.md).

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m scripts.manage init-db
streamlit run app.py
```

Windows (PowerShell):

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python -m scripts.manage init-db
streamlit run app.py
```

Open http://localhost:8501. The **first account you register becomes the administrator**; later accounts are analysts.

### Try it with sample data

[`samples/`](samples/README.md) contains clearly labelled synthetic CSVs and a 7-step walkthrough: import telemetry,
train and detect, forecast, correlate into a "Security + congestion" incident, then generate a report.

## Operator commands

| Command | Purpose |
| --- | --- |
| `python -m scripts.manage init-db` | Create the database or apply pending migrations |
| `python -m scripts.manage create-admin` | Create an admin account (the password is prompted, never passed as an argument) |
| `python -m scripts.manage reset-password --email EMAIL` | Reset a user's password and clear their lockout |
| `python -m scripts.manage apply-retention [--dry-run]` | Delete data older than the retention settings (preview with `--dry-run`) |
| `python -m scripts.manage dump-schema [--check]` | Regenerate `database/schema.sql`, or check it is current |
| `python -m scripts.make_sample_data` | Regenerate the labelled synthetic sample CSVs |
| `pytest -q` | Run all tests (each test uses its own temporary database) |

## Architecture

```
app.py (router: st.navigation; signed out, only the login page is registered)
  └─ views/        pages; every page calls require_principal()
      └─ components/   shared UI: theme, charts, cards, sidebar
          └─ services/     all logic + authorization (require_permission) + audit
              └─ repositories/   all SQL, parameterized only
                  └─ SQLite (WAL, foreign keys, CHECK constraints, versioned migrations)
```

- **Authentication:**
  - argon2id password hashes, a password policy, and a lockout that also covers unknown emails.
  - Sessions are server-side and end after an idle timeout.
  - Roles are admin and analyst, enforced in services with audit logging of denials.
- **Machine learning:**
  - Preprocessing is fit on the training split only.
  - Splits are chronological where timestamps exist; time-series splits are never shuffled.
  - Baselines come first; there are minimum-history checks and feature-compatibility checks.
  - Models load only when registered and their hash matches.
- **Live monitoring:**
  - The capture worker runs as a separate process with a bounded queue and batched writes.
  - A singleton manager keeps one worker at a time, and its states are persisted.
  - Flows are 5-tuple keyed, with a 15 s idle and 120 s active timeout.
- **Database:** `database/migrations/NNN_*.sql`, tracked in `schema_migrations`. `database/schema.sql` is generated, and a
  test fails if it drifts.

## Configuration (`.env`)

| Variable | Default | Meaning |
| --- | --- | --- |
| `SMART_SHIELD_DB_PATH` | `data/smart_shield.db` | SQLite database |
| `SMART_SHIELD_DATASET_DIR` | `data/datasets` | Stored intrusion datasets |
| `SMART_SHIELD_ARTIFACT_DIR` | `artifacts` | Model artifacts |
| `SMART_SHIELD_SESSION_IDLE_MINUTES` | `30` | Idle sign-out |
| `SMART_SHIELD_LOCKOUT_MAX_ATTEMPTS` / `_MINUTES` | `5` / `15` | Sign-in lockout |
| `SMART_SHIELD_ALLOW_SELF_REGISTRATION` | `true` | Allow sign-up after the first admin |
| `SMART_SHIELD_TC_ENABLED` / `_INTERFACES` / `_BINARY` | `false` / empty / `/sbin/tc` | Optional Linux traffic shaping |

Interfaces for live monitoring, the latency target and retention are configured in the app by an admin.

## Testing

`pytest -q` runs about 260 tests in about 75 seconds. They cover:

- authentication, roles and permissions;
- database constraints and schema drift;
- telemetry and dataset validation;
- leakage-safe training and evaluation;
- registry integrity, detection, alert deduplication and triage;
- forecasting rules, risk and cooldowns;
- bandwidth allocation invariants (500 randomized cases) and shaping guards;
- correlation scenarios A–D;
- flow extraction and the live-monitor lifecycle (including a real spawned process);
- reports, retention, page rendering, and an end-to-end run on the sample files.

## Known limitations

- **Sessions:** they live in server memory, so refreshing the browser or opening a new tab means signing in again.
- **Lockout:** it is per email address (Streamlit apps cannot see client IPs). It can be used to lock someone out
  for 15 minutes, which is an accepted trade-off.
- **Packet capture permissions:** capture needs root or ChmodBPF on macOS, root or CAP_NET_RAW on Linux, and Npcap plus
  administrator rights on Windows. Without them only counter mode is offered, and imported data keeps working.
- **Live features:** they approximate CICFlowMeter's definitions, so live accuracy can differ from dataset accuracy.
  Train with the *live-compatible* feature set for live use.
- **Packet loss:** it stays unavailable in live mode, because NIC drop counters are not network loss. Latency needs a
  configured target.
- **Per-class demand:** bandwidth demand per class is entered or scaled from totals, because nothing measures it per class.
- **Correlation:** dataset-based Smart Shield alerts carry no interface, so they are correlated with congestion by time only.
- **Training speed:** models train inside the app process; a 200k-row run takes about a minute.
- **Untested platforms:** Windows and Linux have not been run end to end. Development and verification were done on macOS.
