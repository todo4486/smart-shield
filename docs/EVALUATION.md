# Acceptance criteria (SPEC §17): evidence map

Each criterion from SPEC §17 is listed with where it is implemented, how to see it in the app, and which automated tests
prove it. Run `pytest -q` to re-check everything. The [sample walkthrough](../samples/README.md) demonstrates the
criteria end to end in the UI.

| # | Criterion | Where it is implemented | See it in the app | Test evidence |
| --- | --- | --- | --- | --- |
| 1 | Register, log in, log out | `services/auth_service.py`, `services/session_service.py`, `views/login.py` | Login page → sidebar "Sign out" | `test_auth.py` (registration, duplicates, weak passwords, lockout, logout), `test_app.py::test_login_through_the_form` |
| 2 | Unauthorized users cannot access protected pages | `app.py` (only the login page is registered when signed out), `components/guard.py`, `services/authorization.py` | Open any page URL while signed out | `test_app.py::test_anonymous_user_*`, `test_authorization.py` (analyst blocked from admin services, denials audited) |
| 3 | Smart Shield trains and evaluates an intrusion model | `services/intrusion_training_service.py`, `services/intrusion_features.py` | ML Laboratory → Smart Shield models | `test_intrusion_detection.py::test_training_*`, `test_end_to_end.py` |
| 4 | Persistent alerts from real inference | `services/intrusion_inference_service.py`, `services/alert_service.py` | Security Center → Run detection → Alerts | `test_detection_groups_alerts_and_records_model_version`, `test_rerun_does_not_duplicate_unresolved_alerts` |
| 5 | PredictNet ingests historical telemetry | `services/telemetry_service.py`, `services/telemetry_schema.py` | ML Laboratory → Data sources → Import telemetry | `test_telemetry.py` (validation, UTC, provenance, rejection reasons, atomicity) |
| 6 | PredictNet trains and evaluates a forecasting model | `services/forecasting.py`, `services/congestion_training_service.py` | ML Laboratory → PredictNet models | `test_congestion_prediction.py` (past-only features, chronological split, baselines, minimum history) |
| 7 | Forecasts shown alongside historical measurements | `services/congestion_prediction_service.py::backtest`, `views/predictnet.py` | PredictNet Congestion → Forecast vs actual | `test_backtest_labels_periods`, `test_app.py::test_predictnet_and_settings_pages` |
| 8 | Congestion alerts use configured, documented thresholds | `services/settings_service.py`, `assess_risk`, Settings page | Settings; Congestion Center → "How risk is assessed" | `test_risk_levels_follow_configured_thresholds`, `test_congestion_alerts_are_performance_alerts_with_cooldown` |
| 9 | Bandwidth recommendations respect capacity | `services/bandwidth_allocation.py` (water-filling) | Bandwidth Management → Recommend → constraint checks | `test_bandwidth_allocation.py` (invariants on 500 randomized policies, infeasible minimums) |
| 10 | Recommendations clearly distinguished from enforcement | `services/bandwidth_service.py`, `services/traffic_shaping_service.py` | The "Recommendation mode" banner; Enforcement tab (off by default) | `test_bandwidth.py` (disabled by default, accepted-only, typed confirmation, rollback, emergency disable) |
| 11 | Live monitoring works where supported, fails gracefully otherwise | `services/live_monitor_service.py`, `services/capture_worker.py` | Live Monitoring → "What this server can capture" | `test_live_monitoring.py` (lifecycle, errors, refusal with reason), plus a real counter capture on macOS (Phase 7 report) |
| 12 | Live features are compatible with the active model | `LIVE_FLOW_FEATURES`, `services/flow_extractor.py`, `_prepare_detection` | Live capture → detection status (compatible or REJECTED) | `test_full_feature_model_is_rejected_for_live_use_not_zero_filled`, `test_live_detection_with_compatible_model_raises_grouped_alert` |
| 13 | Correlation without assuming congestion means attack | `services/incident_correlation_service.py` | Incident Center | `test_incident_correlation.py::test_scenario_b_congestion_alone_is_never_an_attack` (and scenarios A, C, D) |
| 14 | Reports use actual persisted data | `services/reporting_service.py`, `views/reports.py` | Reports → Generate | `test_report_counts_only_persisted_data_in_period`, `test_end_to_end.py` |
| 15 | Model versions and metrics are traceable | `services/model_registry_service.py` (version, SHA-256, metadata, metrics) | ML Laboratory → Model registry; every alert, flow and prediction shows its model version | `test_tampered_artifact_is_refused`, `test_forecast_stores_predictions_with_model_version` |
| 16 | Polished, consistent interface | `assets/styles.css`, `components/theme.py`, `components/ui.py` | Every page | Rendering tests in `test_app.py`; visual checks in the browser in each phase |
| 17 | Database initialisation and startup documented | `README.md`, `scripts/manage.py`, `database/migrations/` | — | `test_database.py` (idempotent migrations, `schema.sql` drift), `test_manage_init_db_and_create_admin` |
| 18 | Automated tests cover core functionality | `tests/` (20 modules) | — | `pytest -q`: about 260 tests |
| 19 | README explains limitations and setup | `README.md` ("Known limitations"), `docs/SECURITY_REVIEW.md` | — | — |
| 20 | No fake live data or fabricated results presented as real | Provenance labels everywhere; empty states; labelled sample data | Overview empty state; provenance chips; `samples/README.md` | `test_utilization_not_invented_without_capacity`, `test_null_measurements_are_allowed_not_zero_filled`, `test_sample_files_are_labelled_reproducible_and_importable` |

## Not verified

- **Real-world data:** no real CIC-IDS2017 files, and no real network telemetry. Validation used synthetic files built
  in the same formats, so expect different (usually lower) scores on real data.
- **Live packet capture:** real capture was not exercised (it needs root on macOS). Counter mode was verified live;
  packet mode was verified with simulated flows.
- **Linux traffic shaping:** `tc` enforcement was verified with a mocked command runner only.
- **Windows:** not run on Windows.
