MASTER PROJECT PROMPT

SMART SHIELD + PREDICTNET

AI-Powered Cybersecurity, Network Congestion Prediction, and Intelligent Bandwidth Management Platform

Act as a senior network engineer, cybersecurity specialist, machine learning engineer, Python architect, and UI/UX designer.

I want to build an advanced final-year Computer Science engineering project that combines two intelligent network technologies into one unified application:

1. Smart Shield: Machine-learning-based network intrusion detection, abnormal traffic analysis, DDoS detection, and security alert management.

2. PredictNet: AI-powered network congestion prediction, network performance forecasting, traffic analysis, and intelligent bandwidth management.

The application should be a professional, modular, fully functional network intelligence platform built with Python and Streamlit.

Do not build two unrelated dashboards. Integrate both systems into one coherent application with shared network telemetry, a unified database, common monitoring infrastructure, and separate but connected machine learning pipelines.

The final product should demonstrate both network security and network performance optimization.

The system must use real data, genuine model inference, persistent storage, secure authentication, and measurable evaluation results. Never fabricate live traffic, predictions, detection statistics, or model performance.

⸻

1. PROJECT IDENTITY

Application name: Smart Shield

Integrated network intelligence module: PredictNet

Full project title:

“Smart Shield: An AI-Powered Network Intelligence Platform for Intrusion Detection, Congestion Prediction, and Intelligent Bandwidth Management.”

Alternative branding:

“Smart Shield — Powered by PredictNet”

Primary technologies:

* Cybersecurity.
* Machine learning.
* Network intrusion detection.
* Network traffic analytics.
* Congestion forecasting.
* Time-series prediction.
* Intelligent bandwidth allocation.
* Network performance optimization.
* Traffic anomaly detection.

The application should be suitable for:

* Final-year engineering project evaluation.
* Academic research demonstrations.
* Machine learning experiments.
* Network performance analysis.
* Controlled network test environments.
* Future development into a more advanced network management system.

2. CORE OBJECTIVES

The unified platform must accomplish six main objectives.

OBJECTIVE 1: NETWORK SECURITY

Detect suspicious network traffic, potential DDoS attacks, abnormal flow patterns, and other supported intrusion categories using machine learning.

OBJECTIVE 2: NETWORK CONGESTION PREDICTION

Predict whether network traffic is likely to cause congestion in the near future using historical traffic measurements and time-series features.

OBJECTIVE 3: INTELLIGENT BANDWIDTH MANAGEMENT

Recommend or apply bandwidth allocations based on traffic demand, configured limits, service priorities, and predicted congestion.

OBJECTIVE 4: NETWORK PERFORMANCE MONITORING

Monitor measurable traffic statistics, throughput, latency, packet loss, utilization, and other supported performance indicators.

OBJECTIVE 5: UNIFIED NETWORK INTELLIGENCE

Correlate security and performance information to help users investigate whether unusual network behavior is associated with congestion, a possible attack, or a legitimate traffic spike.

OBJECTIVE 6: VISUALIZATION AND REPORTING

Provide a polished dashboard that displays network health, security incidents, predicted congestion, bandwidth utilization, and historical model performance.

3. UNIFIED SYSTEM ARCHITECTURE

Design the application around a shared network telemetry pipeline.

NETWORK DATA SOURCES

* Labeled intrusion-detection datasets.
* Historical network traffic measurements.
* Authorized live network traffic.
* Flow records from Zeek or compatible tools.
* Network performance measurements from supported interfaces.
* Controlled traffic-generator experiments in an isolated test environment.

↓

SHARED DATA INGESTION LAYER

* Dataset ingestion.
* Flow-record ingestion.
* Performance-metric ingestion.
* Live telemetry ingestion.
* Data validation.
* Timestamp normalization.
* Source tracking.

↓

SHARED FEATURE AND TELEMETRY LAYER

* Network flow statistics.
* Traffic rates.
* Bytes and packets per second.
* Historical utilization.
* Throughput measurements.
* Latency measurements where available.
* Packet loss where measurable.
* Flow and protocol distributions.
* Time-based forecasting features.

↓

TWO SPECIALIZED AI ENGINES

ENGINE A: SMART SHIELD

* Binary intrusion classification.
* Optional multiclass attack classification.
* Anomaly detection.
* Suspicious traffic identification.
* Potential DDoS detection.
* Alert generation.

ENGINE B: PREDICTNET

* Congestion forecasting.
* Traffic demand prediction.
* Utilization forecasting.
* Congestion risk classification.
* Bandwidth allocation recommendations.
* Optional controlled traffic shaping.

↓

DECISION AND CORRELATION LAYER

* Correlate security alerts with traffic anomalies.
* Compare predicted and actual congestion.
* Generate network health summaries.
* Recommend corrective actions.
* Enforce configured safety limits for bandwidth management.

↓

DATABASE AND MODEL REGISTRY

* User accounts.
* Network telemetry.
* Monitoring sessions.
* Security alerts.
* Congestion predictions.
* Bandwidth recommendations.
* Applied bandwidth policies.
* Model versions.
* Audit logs.

↓

STREAMLIT APPLICATION

* Overview dashboard.
* Smart Shield security center.
* PredictNet congestion center.
* Bandwidth management.
* Live monitoring.
* ML laboratory.
* Reports.
* Settings.

4. APPLICATION TECHNOLOGY STACK

Use Python as the primary programming language.

Frontend:

* Streamlit.
* Plotly.
* Custom CSS.

Data processing:

* Pandas.
* NumPy.

Machine learning:

* Scikit-learn.
* Random Forest.
* Isolation Forest.
* Gradient boosting where appropriate.
* Time-series forecasting models.

Optional advanced forecasting:

* XGBoost or another suitable regression model.
* HistGradientBoostingRegressor.
* A lightweight time-series forecasting library if justified.

Database:

* SQLite.
* SQLAlchemy or a clean repository layer.

Network monitoring:

* Zeek.
* CICFlowMeter or a compatible flow extractor.
* Scapy for authorized packet capture and controlled experiments.
* Operating-system network statistics where supported.

Testing:

* Pytest.

Do not add unnecessary infrastructure. The initial implementation should run locally on a standard student laptop.

5. SMART SHIELD MODULE

Preserve all Smart Shield requirements.

The security engine must support:

* Dataset upload.
* Network traffic preprocessing.
* Binary benign-versus-attack classification.
* Optional multiclass attack classification.
* Anomaly detection.
* Suspicious traffic analysis.
* Potential DDoS detection.
* Alert generation.
* Alert severity.
* Alert investigation.
* Historical reports.
* Model evaluation.
* Model versioning.

Use CIC-IDS2017 as the initial training dataset.

Support CIC-IDS2017-style flow features where appropriate.

Recommended baseline models:

1. Random Forest for supervised intrusion classification.
2. Isolation Forest for anomaly detection.
3. Optional multiclass classifier for attack categories.

Evaluate models using:

* Precision.
* Recall.
* F1-score.
* Confusion matrix.
* Per-class metrics.
* False-positive rate.

Prevent data leakage and maintain separate training, validation, and test datasets.

Never apply a model to incompatible live features.

6. PREDICTNET MODULE

Build PredictNet as a distinct machine-learning subsystem within the unified application.

Its primary purpose is to forecast network traffic conditions and help prevent congestion before it occurs.

6.1 Network performance telemetry

Collect or ingest the following measurements when available:

* Incoming bytes per second.
* Outgoing bytes per second.
* Incoming packets per second.
* Outgoing packets per second.
* Current throughput.
* Interface capacity, when known.
* Interface utilization.
* Round-trip latency.
* Packet loss.
* Flow count.
* Active connection count.
* Protocol distribution.
* Historical traffic averages.
* Traffic growth rate.
* Short-term utilization changes.

Not every data source will provide every metric.

For each metric, track:

* Value.
* Timestamp.
* Source.
* Measurement unit.
* Collection method.
* Validity status.

Do not substitute zero for unavailable measurements without explicitly identifying the limitation.

6.2 Network congestion prediction

Build a model that predicts future traffic utilization and congestion risk.

Initial forecasting target:

Predict network utilization over the next:

* 1 minute.
* 5 minutes.
* 15 minutes.

Make the forecast horizons configurable.

For the initial prototype, focus on five-minute utilization forecasting.

Use a configurable sampling interval and ensure the forecasting horizon is consistent with that interval.

Possible input features:

* Recent utilization values.
* Rolling mean utilization.
* Rolling maximum utilization.
* Traffic growth rate.
* Recent packet rate.
* Recent throughput.
* Time of day.
* Day of week.
* Previous congestion events, if available.

Use lagged observations and rolling statistics to build the feature set.

Do not use future values when constructing historical training features.

Do not randomly shuffle time-series observations before splitting the dataset.

Use chronological training, validation, and test splits.

6.3 Forecasting models

Implement a simple baseline first.

Baseline:

* Last-value prediction.
* Moving-average prediction.

Machine learning:

* Random Forest Regressor or HistGradientBoostingRegressor.

Optional advanced model:

* XGBoost regression if the dependency is justified.

Compare the machine learning model with the baseline.

Use the simplest model that performs reliably.

Evaluate using:

* MAE.
* RMSE.
* R² where appropriate.
* Forecast error by prediction horizon.

Show predicted utilization alongside actual utilization on a time-series chart.

Display the forecast horizon and last updated timestamp.

Do not claim that a forecast is reliable if insufficient historical data is available.

6.4 Congestion risk classification

PredictNet must estimate whether the network is approaching congestion.

Use configurable utilization thresholds.

Initial example:

* Normal: below 60%.
* Elevated: 60% to below 75%.
* High: 75% to below 90%.
* Critical: 90% or above.

These values are initial configuration defaults, not universal network standards.

Allow administrators to configure thresholds according to the actual network and its service requirements.

Congestion risk should consider:

* Current measured utilization.
* Predicted utilization.
* Traffic growth rate.
* Prediction uncertainty or historical forecast error.
* Available capacity.
* Latency or packet-loss indicators when available.

If actual link capacity is unknown, do not invent a utilization percentage. Show absolute traffic rates and indicate that capacity-based utilization is unavailable.

6.5 Congestion alerts

Generate an alert when:

* Predicted utilization crosses a configured threshold.
* Utilization rises rapidly.
* Sustained high utilization is observed.
* Available performance measurements indicate degradation.

Each alert should contain:

* Timestamp.
* Network interface or source.
* Current utilization, if known.
* Predicted utilization.
* Forecast horizon.
* Congestion category.
* Model version.
* Evidence.
* Recommended action.

Do not generate repeated identical alerts every few seconds.

Implement configurable cooldowns or alert deduplication.

7. INTELLIGENT BANDWIDTH MANAGEMENT

Build a bandwidth management subsystem that starts in recommendation mode.

This subsystem should use traffic measurements and predicted congestion to recommend how bandwidth could be allocated more efficiently.

Important distinction:

Bandwidth management is not automatically possible on every network interface. Actual enforcement depends on operating-system capabilities, permissions, network topology, and the traffic-control mechanism.

Do not pretend that changing a number in Streamlit changes real network bandwidth.

7.1 Phase A: Recommendation mode

This must work without administrator privileges.

Display:

* Current traffic measurements.
* Predicted utilization.
* Congestion risk.
* Configured bandwidth limit.
* Recommended traffic-class allocations.
* Expected effect.
* Reason for the recommendation.

Provide configurable traffic classes such as:

* Critical services.
* Interactive applications.
* Standard traffic.
* Background transfers.

Use configurable priorities rather than assuming every network uses the same traffic categories.

The recommendation engine must respect:

* Total available capacity.
* Minimum service allocations.
* Maximum class allocations.
* Configured priorities.
* Current traffic demand.
* Safety margins.
* Fairness requirements.

The total of all recommended allocations must never exceed the configured capacity.

If demand exceeds capacity, report unmet demand rather than inventing additional bandwidth.

Use a deterministic allocation algorithm with documented rules.

7.2 Phase B: Controlled traffic shaping

Make actual bandwidth enforcement an optional advanced feature.

For a Linux laboratory environment, consider an explicitly configured traffic-control backend using tc and suitable queueing disciplines.

Do not assume this backend is available on macOS or Windows.

Before applying any policy:

1. Show the proposed changes.
2. Show the target interface.
3. Show the bandwidth limits.
4. Require administrator authorization.
5. Require explicit confirmation.
6. Validate all parameters.
7. Record the action in the audit log.

Provide:

* Apply policy.
* View current policy.
* Restore previous policy.
* Emergency disable.
* Error reporting.
* Policy history.

Implement rollback and recovery instructions.

Do not modify firewall rules, routing tables, or network interfaces without explicit configuration and confirmation.

Do not enable automatic bandwidth enforcement by default.

Do not allow the web application to execute arbitrary shell commands.

Use a restricted, validated backend with a predefined set of supported operations.

If actual enforcement is unsupported, keep recommendation mode fully functional and explain how to configure a supported test environment.

7.3 Traffic allocation logic

Implement a baseline bandwidth recommendation algorithm.

Inputs:

* Total configured capacity.
* Estimated demand for each traffic class.
* Minimum allocation.
* Maximum allocation.
* Priority weight.
* Congestion state.

Outputs:

* Recommended allocation.
* Estimated unmet demand.
* Allocation rationale.
* Whether the recommendation satisfies all constraints.

Enforce these invariants:

* Every allocation is nonnegative.
* No allocation exceeds its configured maximum.
* Minimum allocations are respected when mathematically feasible.
* Total allocations never exceed capacity.
* Infeasible constraints produce a clear error.
* Recommendations are reproducible for the same inputs.

Do not claim that the system has measured real traffic-class demand unless the necessary telemetry or explicit input exists.

8. NETWORK PERFORMANCE MONITORING

Create a shared monitoring subsystem for security and performance.

Support:

* Interface selection where available.
* Incoming and outgoing traffic.
* Flow counts.
* Traffic rates.
* Historical throughput.
* Latency where measurable.
* Packet loss where measurable.
* Monitoring-session history.
* Start and stop controls.

Use appropriate platform-specific APIs or tools.

The system must distinguish:

* Measured values.
* Derived values.
* Predicted values.
* Manually configured values.
* Unavailable values.

Use explicit labels in the interface.

For example:
“Measured throughput” must refer to an actual measurement.

“Predicted utilization” must refer to a model output.

“Configured capacity” must refer to an administrator-provided or verified capacity value.

Do not present a predicted value as a measured result.

9. UNIFIED NETWORK INTELLIGENCE

Create a shared event-correlation engine.

The purpose is to help analysts understand the relationship between network security and performance.

Examples:

Scenario A:
Traffic volume rises sharply, and Smart Shield identifies suspicious flows.

PredictNet forecasts sustained congestion.

The platform generates a combined incident containing the security evidence and congestion forecast.

Scenario B:
Traffic increases, but Smart Shield finds no strong evidence of malicious behavior.

PredictNet forecasts congestion.

The platform generates a performance warning rather than automatically labeling the traffic as an attack.

Scenario C:
Traffic remains normal, but a model reports an anomaly.

The system generates a security investigation alert and records the evidence.

Scenario D:
The network is congested because of a legitimate large transfer.

The system can recommend prioritizing latency-sensitive traffic, subject to the configured allocation rules.

The correlation engine must not automatically conclude that congestion means an attack.

Each combined incident should contain:

* Incident ID.
* Related security alerts.
* Related congestion alerts.
* Relevant time window.
* Measured traffic changes.
* Model outputs.
* Correlation rationale.
* Suggested investigation steps.

10. UNIFIED DASHBOARD DESIGN

Use a premium dark cybersecurity interface.

Design:

* Dark navy background.
* Muted blue accents.
* White text.
* Green normal-state indicators.
* Amber warning indicators.
* Red critical indicators.
* Minimal borders.
* Clean charts.
* Consistent spacing.
* Professional typography.

The application should resemble a modern network operations and security monitoring platform.

Create a shared sidebar with:

* Smart Shield branding.
* Current user.
* System health.
* Navigation.
* Monitoring status.
* Logout.

Required pages:

1. Overview.
2. Live Network Monitoring.
3. Smart Shield Security Center.
4. PredictNet Congestion Center.
5. Bandwidth Management.
6. ML Laboratory.
7. Incident Center.
8. Reports.
9. Settings.
10. Administration.

Overview dashboard

Show:

* Current monitoring status.
* Incoming and outgoing traffic.
* Measured throughput.
* Active flows.
* Unresolved security alerts.
* Predicted congestion risk.
* Forecasted utilization.
* Bandwidth recommendations.
* Recent incidents.

Use only actual data, model outputs, or clearly labeled examples.

PredictNet Congestion Center

Show:

* Current traffic rates.
* Historical utilization.
* Predicted utilization.
* Forecast confidence or historical error information where supported.
* Congestion risk.
* Forecast horizon.
* Congestion history.
* Model evaluation metrics.

Provide controls for forecast horizons and congestion thresholds.

Bandwidth Management

Show:

* Configured link capacity.
* Current demand by traffic class, if available.
* Recommended allocation.
* Current allocation where measurable.
* Minimum and maximum limits.
* Priority weights.
* Expected unmet demand.
* Policy history.
* Apply and rollback controls when a supported enforcement backend is configured.

ML Laboratory

Organize the page into two independent model workspaces:

SMART SHIELD:

* Dataset upload.
* Intrusion model training.
* Classification metrics.
* Anomaly detection.
* Model registry.

PREDICTNET:

* Historical telemetry upload.
* Time-series inspection.
* Forecast model training.
* Baseline comparison.
* Forecast error metrics.
* Congestion classification.
* Model registry.

Clearly label each model by purpose, version, training data, and evaluation results.

11. DATABASE SCHEMA

Use SQLite initially.

Create the following tables.

users:

* id.
* name.
* email.
* password_hash.
* role.
* is_active.
* created_at.
* last_login_at.

monitoring_sessions:

* id.
* user_id.
* source_type.
* interface_name.
* started_at.
* ended_at.
* status.
* configuration_json.

network_flows:

* id.
* session_id.
* timestamp.
* src_ip.
* dst_ip.
* src_port.
* dst_port.
* protocol.
* packet_count.
* byte_count.
* duration.
* intrusion_prediction.
* anomaly_score.
* model_version.
* feature_summary_json.

network_metrics:

* id.
* session_id.
* timestamp.
* source_name.
* interface_name.
* incoming_bytes_per_second.
* outgoing_bytes_per_second.
* incoming_packets_per_second.
* outgoing_packets_per_second.
* throughput_bps.
* latency_ms.
* packet_loss_ratio.
* utilization_ratio.
* configured_capacity_bps.
* measurement_method.
* validity_status.

Allow nullable fields when measurements are unavailable.

congestion_predictions:

* id.
* timestamp.
* source_name.
* interface_name.
* forecast_horizon_seconds.
* predicted_utilization_ratio.
* predicted_throughput_bps.
* congestion_risk.
* model_version.
* prediction_metadata_json.

alerts:

* id.
* session_id.
* flow_id, nullable.
* alert_type.
* severity.
* category.
* reason.
* status.
* created_at.
* acknowledged_by.
* acknowledged_at.
* resolved_by.
* resolved_at.
* investigation_notes.

bandwidth_policies:

* id.
* policy_name.
* interface_name.
* configured_capacity_bps.
* traffic_class.
* minimum_bps.
* maximum_bps.
* priority_weight.
* enabled.
* created_at.
* updated_at.

bandwidth_recommendations:

* id.
* timestamp.
* source_name.
* interface_name.
* capacity_bps.
* recommendation_json.
* unmet_demand_bps.
* rationale.
* status.
* created_by.

policy_actions:

* id.
* recommendation_id.
* action_type.
* target_interface.
* policy_before_json.
* policy_after_json.
* status.
* executed_by.
* executed_at.
* rollback_at.
* error_message.

model_registry:

* id.
* model_family.
* model_name.
* version.
* artifact_path.
* feature_schema_version.
* metrics_json.
* training_metadata_json.
* trained_at.
* created_by.
* is_active.

audit_logs:

* id.
* user_id.
* action.
* details_json.
* created_at.

Add:

* Foreign-key constraints.
* Indexes on timestamps and frequently filtered fields.
* Appropriate transaction handling.
* Parameterized database operations.
* Schema migrations.
* Retention policies.

Use database constraints to prevent invalid states wherever practical.

12. MODEL TRAINING AND EVALUATION

Implement separate training pipelines for the security and performance models.

Smart Shield training

Use labeled intrusion-detection datasets.

Perform:

* Schema validation.
* Label normalization.
* Missing-value handling.
* Feature selection.
* Leakage prevention.
* Chronological or capture-group validation where feasible.
* Model training.
* Independent evaluation.
* Artifact persistence.

PredictNet training

Use historical network performance measurements.

Accept a CSV with a documented schema, for example:

timestamp,
interface_name,
incoming_bytes_per_second,
outgoing_bytes_per_second,
throughput_bps,
utilization_ratio,
latency_ms,
packet_loss_ratio

Some columns may be optional, depending on the forecasting target.

Allow the user to choose the forecasting target when appropriate.

For example:

* Future throughput.
* Future utilization.
* Congestion risk.

Build lag features from past measurements.

Do not use observations from the future to predict the past.

Split the time series chronologically into training, validation, and test sets.

Compare the trained model against a baseline.

Report the test period and number of observations used.

Save the preprocessing pipeline and model together.

Store:

* Model version.
* Training date.
* Training period.
* Evaluation period.
* Forecast horizon.
* Feature schema.
* Evaluation metrics.

Do not train a forecasting model when there is insufficient historical data.

Explain the minimum data requirements and provide a sample schema.

13. MODEL VERSIONING AND COMPATIBILITY

Every model must have:

* A unique version.
* A documented feature schema.
* Training metadata.
* Evaluation metrics.
* Artifact location.
* Creation timestamp.

Before activation:

* Validate the artifact.
* Validate the feature schema.
* Confirm the model family.
* Check required dependencies.
* Confirm compatibility with the selected data source.

Do not load arbitrary untrusted model artifacts.

Maintain independent active-model references for:

* Intrusion classification.
* Anomaly detection.
* Congestion forecasting.
* Congestion classification, if implemented.

Do not overwrite the previous working model when training a new model fails.

14. SECURITY AND SAFETY

The application must use secure authentication and authorization.

Requirements:

* Argon2 or bcrypt password hashing.
* Protected pages.
* Server-side role checks.
* Parameterized SQL.
* Safe dataset ingestion.
* No hardcoded credentials.
* No secrets committed to source control.
* Audit logging.
* Bounded queues.
* Controlled worker processes.
* Safe error handling.

Live monitoring must be restricted to authorized network interfaces and traffic sources.

Bandwidth enforcement must be opt-in, restricted, auditable, and reversible.

Default to:

* Passive monitoring.
* Dataset-based experimentation.
* Bandwidth recommendations.
* Manual approval for actual network changes.

Do not implement offensive scanning, automatic attack generation, packet injection, or automatic blocking as part of this project.

Do not execute arbitrary shell commands from the dashboard.

15. PROJECT STRUCTURE

Use a modular structure similar to:

smart-shield/
app.py
requirements.txt
README.md
.env.example
.gitignore

.streamlit/
    config.toml
pages/
    1_Overview.py
    2_Live_Monitoring.py
    3_Smart_Shield.py
    4_PredictNet.py
    5_Bandwidth_Management.py
    6_ML_Laboratory.py
    7_Incident_Center.py
    8_Reports.py
    9_Settings.py
    10_Administration.py
components/
    navigation.py
    metric_cards.py
    charts.py
    tables.py
    alerts.py
    forms.py
services/
    auth_service.py
    database_service.py
    telemetry_service.py
    monitoring_service.py
    dataset_service.py
    preprocessing_service.py
    intrusion_training_service.py
    congestion_training_service.py
    intrusion_inference_service.py
    congestion_prediction_service.py
    bandwidth_recommendation_service.py
    traffic_shaping_service.py
    incident_correlation_service.py
    alert_service.py
    reporting_service.py
    audit_service.py
repositories/
    user_repository.py
    telemetry_repository.py
    flow_repository.py
    alert_repository.py
    prediction_repository.py
    policy_repository.py
    model_repository.py
models/
    schemas.py
    model_registry.py
database/
    schema.sql
    migrations/
tests/
    test_auth.py
    test_database.py
    test_telemetry.py
    test_intrusion_detection.py
    test_congestion_prediction.py
    test_bandwidth_allocation.py
    test_incident_correlation.py
    test_authorization.py
data/
    .gitkeep
artifacts/
    .gitkeep
reports/
    .gitkeep

Adjust the structure if needed, but keep the modules separated and maintainable.

16. TESTING REQUIREMENTS

Create automated tests for:

Authentication:

* Registration.
* Duplicate users.
* Password verification.
* Login failures.
* Role permissions.

Smart Shield:

* Dataset validation.
* Preprocessing.
* Training.
* Inference.
* Alert generation.
* Feature compatibility.

PredictNet:

* Time-series feature generation.
* Chronological splitting.
* Baseline forecasting.
* Forecast evaluation.
* Congestion classification.
* Missing measurement handling.

Bandwidth management:

* Capacity constraints.
* Minimum and maximum allocations.
* Priority allocation.
* Unmet demand.
* Infeasible policies.
* Rollback validation.

Integration:

* Telemetry ingestion.
* Prediction persistence.
* Alert persistence.
* Dashboard queries.
* Incident correlation.
* Model version consistency.

Use synthetic fixtures for unit tests so the tests do not require large external datasets.

17. ACCEPTANCE CRITERIA

The application is complete only when:

1. Users can register, log in, and log out.
2. Unauthorized users cannot access protected pages.
3. Smart Shield can train and evaluate an intrusion-detection model.
4. Smart Shield can generate persistent alerts from real inference results.
5. PredictNet can ingest historical network telemetry.
6. PredictNet can train and evaluate a forecasting model.
7. PredictNet can display forecasts alongside historical measurements.
8. Congestion alerts use configured and documented thresholds.
9. The bandwidth recommendation engine respects capacity constraints.
10. The application clearly distinguishes recommendations from actual enforcement.
11. Live monitoring works where supported and fails gracefully where unsupported.
12. Live features are compatible with the active model.
13. The system can correlate security and performance events without assuming congestion means an attack.
14. Reports use actual persisted data.
15. Model versions and evaluation metrics are traceable.
16. The interface is polished and consistent.
17. Database initialization and application startup are documented.
18. Automated tests cover core functionality.
19. The README explains limitations and setup.
20. No fake live data or fabricated model results are presented as real.

18. IMPLEMENTATION PLAN

Do not generate the entire application as one enormous response.

Build it incrementally.

PHASE 1: FOUNDATION

* Project structure.
* Authentication.
* Database.
* Shared UI.
* Overview dashboard.
* Basic tests.

PHASE 2: SHARED TELEMETRY

* Dataset ingestion.
* Historical metric ingestion.
* Common telemetry schema.
* Monitoring sessions.
* Telemetry visualizations.

PHASE 3: SMART SHIELD

* Intrusion dataset processing.
* Model training.
* Evaluation.
* Model persistence.
* Inference.
* Threat center.

PHASE 4: PREDICTNET

* Historical performance data upload.
* Time-series feature generation.
* Baseline forecasting.
* ML forecasting.
* Congestion risk assessment.
* Forecast visualization.

PHASE 5: BANDWIDTH MANAGEMENT

* Allocation constraints.
* Recommendation algorithm.
* Policy configuration.
* Recommendation history.
* Optional controlled traffic shaping.

PHASE 6: INTEGRATION

* Shared dashboard.
* Unified alerts.
* Security/performance event correlation.
* Incident investigation.

PHASE 7: LIVE MONITORING

* Authorized capture.
* Flow extraction.
* Performance telemetry.
* Model compatibility checks.
* Background workers.
* Start/stop lifecycle.

PHASE 8: FINALIZATION

* Reports.
* Administration.
* Security review.
* Testing.
* Documentation.
* End-to-end verification.

At the end of each phase, explain:

* What was implemented.
* Which files were created or changed.
* How to run it.
* How to test it.
* What remains incomplete.
* Any operating-system limitations.

If you have access to a coding environment, create the files and execute the tests. Do not merely describe code that should be written.

If you cannot execute the application, clearly identify what has not been verified.

FINAL INSTRUCTION

Begin by reviewing the architecture and identifying the most important implementation decisions.

Then implement Phase 1 with complete, runnable files.

Prioritize correctness, security, modularity, and real functionality over unnecessary complexity.

The final result should be a professional AI-powered network intelligence platform combining Smart Shield’s intrusion detection with PredictNet’s congestion forecasting and intelligent bandwidth management.