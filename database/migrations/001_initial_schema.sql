-- 001_initial_schema: full SPEC §11 schema plus the CLAUDE.md extensions
-- (login_attempts, alert_events, incidents, incident_alerts, app_settings,
-- model_registry.artifact_sha256 and one active model per family).
--
-- Conventions
--   * Timestamps are ISO-8601 UTC strings (e.g. 2026-10-22T06:40:00.000000+00:00).
--   * *_json columns hold JSON text validated by the application layer.
--   * provenance is one of measured / derived / predicted / configured / unavailable.
--   * Ratios are stored as 0..1, never percentages.
--   * Missing measurements are NULL, never 0.

CREATE TABLE users (
    id              INTEGER PRIMARY KEY,
    name            TEXT    NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 100),
    email           TEXT    NOT NULL UNIQUE CHECK (email = lower(trim(email)) AND length(email) BETWEEN 3 AND 254),
    password_hash   TEXT    NOT NULL CHECK (length(password_hash) > 0),
    role            TEXT    NOT NULL CHECK (role IN ('admin', 'analyst')),
    is_active       INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    last_login_at   TEXT
);

CREATE INDEX idx_users_role_active ON users (role, is_active);

-- Defence in depth: the service layer refuses these changes too.
CREATE TRIGGER trg_users_keep_last_admin_update
BEFORE UPDATE OF role, is_active ON users
WHEN OLD.role = 'admin' AND OLD.is_active = 1
     AND (NEW.role <> 'admin' OR NEW.is_active = 0)
     AND (SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1 AND id <> OLD.id) = 0
BEGIN
    SELECT RAISE(ABORT, 'cannot remove the last active admin');
END;

CREATE TRIGGER trg_users_keep_last_admin_delete
BEFORE DELETE ON users
WHEN OLD.role = 'admin' AND OLD.is_active = 1
     AND (SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1 AND id <> OLD.id) = 0
BEGIN
    SELECT RAISE(ABORT, 'cannot remove the last active admin');
END;

-- Tracked per normalized email key, including emails with no account.
CREATE TABLE login_attempts (
    id            INTEGER PRIMARY KEY,
    email_key     TEXT    NOT NULL CHECK (length(email_key) BETWEEN 1 AND 254),
    attempted_at  TEXT    NOT NULL,
    succeeded     INTEGER NOT NULL CHECK (succeeded IN (0, 1))
);

CREATE INDEX idx_login_attempts_key_time ON login_attempts (email_key, attempted_at);

CREATE TABLE monitoring_sessions (
    id                  INTEGER PRIMARY KEY,
    user_id             INTEGER REFERENCES users (id) ON DELETE SET NULL,
    source_type         TEXT    NOT NULL CHECK (source_type IN ('dataset', 'historical_import', 'flow_import', 'live_capture')),
    interface_name      TEXT,
    started_at          TEXT    NOT NULL,
    ended_at            TEXT    CHECK (ended_at IS NULL OR ended_at >= started_at),
    status              TEXT    NOT NULL CHECK (status IN ('STOPPED', 'STARTING', 'RUNNING', 'STOPPING', 'ERROR')),
    status_message      TEXT,
    configuration_json  TEXT
);

CREATE INDEX idx_monitoring_sessions_started ON monitoring_sessions (started_at);
CREATE INDEX idx_monitoring_sessions_status ON monitoring_sessions (status);

CREATE TABLE model_registry (
    id                      INTEGER PRIMARY KEY,
    model_family            TEXT    NOT NULL CHECK (model_family IN ('intrusion_classifier', 'anomaly_detector', 'congestion_forecaster', 'congestion_classifier')),
    model_name              TEXT    NOT NULL CHECK (length(trim(model_name)) > 0),
    version                 TEXT    NOT NULL CHECK (length(trim(version)) > 0),
    artifact_path           TEXT    NOT NULL,
    artifact_sha256         TEXT    NOT NULL CHECK (length(artifact_sha256) = 64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'),
    feature_schema_version  TEXT    NOT NULL,
    metrics_json            TEXT,
    training_metadata_json  TEXT,
    trained_at              TEXT    NOT NULL,
    created_by              INTEGER REFERENCES users (id) ON DELETE SET NULL,
    is_active               INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1)),
    UNIQUE (model_family, version)
);

-- At most one active model per family.
CREATE UNIQUE INDEX uq_model_registry_one_active_per_family
    ON model_registry (model_family) WHERE is_active = 1;
CREATE INDEX idx_model_registry_trained ON model_registry (trained_at);

CREATE TABLE network_flows (
    id                    INTEGER PRIMARY KEY,
    session_id            INTEGER NOT NULL REFERENCES monitoring_sessions (id) ON DELETE CASCADE,
    timestamp             TEXT    NOT NULL,
    src_ip                TEXT,
    dst_ip                TEXT,
    src_port              INTEGER CHECK (src_port IS NULL OR src_port BETWEEN 0 AND 65535),
    dst_port              INTEGER CHECK (dst_port IS NULL OR dst_port BETWEEN 0 AND 65535),
    protocol              TEXT,
    packet_count          INTEGER CHECK (packet_count IS NULL OR packet_count >= 0),
    byte_count            INTEGER CHECK (byte_count IS NULL OR byte_count >= 0),
    duration              REAL    CHECK (duration IS NULL OR duration >= 0),
    intrusion_prediction  TEXT,
    anomaly_score         REAL,
    model_id              INTEGER REFERENCES model_registry (id) ON DELETE SET NULL,
    model_version         TEXT,
    feature_summary_json  TEXT,
    provenance            TEXT    NOT NULL DEFAULT 'measured' CHECK (provenance IN ('measured', 'derived', 'predicted', 'configured', 'unavailable'))
);

CREATE INDEX idx_network_flows_session_time ON network_flows (session_id, timestamp);
CREATE INDEX idx_network_flows_time ON network_flows (timestamp);
CREATE INDEX idx_network_flows_prediction ON network_flows (intrusion_prediction);

CREATE TABLE network_metrics (
    id                           INTEGER PRIMARY KEY,
    session_id                   INTEGER REFERENCES monitoring_sessions (id) ON DELETE CASCADE,
    timestamp                    TEXT    NOT NULL,
    source_name                  TEXT    NOT NULL,
    interface_name               TEXT,
    incoming_bytes_per_second    REAL    CHECK (incoming_bytes_per_second IS NULL OR incoming_bytes_per_second >= 0),
    outgoing_bytes_per_second    REAL    CHECK (outgoing_bytes_per_second IS NULL OR outgoing_bytes_per_second >= 0),
    incoming_packets_per_second  REAL    CHECK (incoming_packets_per_second IS NULL OR incoming_packets_per_second >= 0),
    outgoing_packets_per_second  REAL    CHECK (outgoing_packets_per_second IS NULL OR outgoing_packets_per_second >= 0),
    throughput_bps               REAL    CHECK (throughput_bps IS NULL OR throughput_bps >= 0),
    latency_ms                   REAL    CHECK (latency_ms IS NULL OR latency_ms >= 0),
    packet_loss_ratio            REAL    CHECK (packet_loss_ratio IS NULL OR packet_loss_ratio BETWEEN 0 AND 1),
    utilization_ratio            REAL    CHECK (utilization_ratio IS NULL OR utilization_ratio BETWEEN 0 AND 1),
    configured_capacity_bps      REAL    CHECK (configured_capacity_bps IS NULL OR configured_capacity_bps > 0),
    measurement_method           TEXT    NOT NULL,
    provenance                   TEXT    NOT NULL CHECK (provenance IN ('measured', 'derived', 'predicted', 'configured', 'unavailable')),
    validity_status              TEXT    NOT NULL CHECK (validity_status IN ('valid', 'partial', 'invalid', 'unavailable'))
);

CREATE INDEX idx_network_metrics_time ON network_metrics (timestamp);
CREATE INDEX idx_network_metrics_session_time ON network_metrics (session_id, timestamp);
CREATE INDEX idx_network_metrics_source_iface_time ON network_metrics (source_name, interface_name, timestamp);

CREATE TABLE congestion_predictions (
    id                           INTEGER PRIMARY KEY,
    timestamp                    TEXT    NOT NULL,
    source_name                  TEXT    NOT NULL,
    interface_name               TEXT,
    forecast_horizon_seconds     INTEGER NOT NULL CHECK (forecast_horizon_seconds > 0),
    predicted_utilization_ratio  REAL    CHECK (predicted_utilization_ratio IS NULL OR predicted_utilization_ratio BETWEEN 0 AND 1),
    predicted_throughput_bps     REAL    CHECK (predicted_throughput_bps IS NULL OR predicted_throughput_bps >= 0),
    congestion_risk              TEXT    NOT NULL CHECK (congestion_risk IN ('normal', 'elevated', 'high', 'critical', 'unknown')),
    model_id                     INTEGER REFERENCES model_registry (id) ON DELETE SET NULL,
    model_version                TEXT    NOT NULL,
    prediction_metadata_json     TEXT,
    provenance                   TEXT    NOT NULL DEFAULT 'predicted' CHECK (provenance = 'predicted')
);

CREATE INDEX idx_congestion_predictions_time ON congestion_predictions (timestamp);
CREATE INDEX idx_congestion_predictions_source_iface_time ON congestion_predictions (source_name, interface_name, timestamp);
CREATE INDEX idx_congestion_predictions_risk ON congestion_predictions (congestion_risk);

CREATE TABLE alerts (
    id                   INTEGER PRIMARY KEY,
    session_id           INTEGER REFERENCES monitoring_sessions (id) ON DELETE SET NULL,
    flow_id              INTEGER REFERENCES network_flows (id) ON DELETE SET NULL,
    alert_type           TEXT    NOT NULL CHECK (alert_type IN ('security', 'anomaly', 'congestion', 'performance')),
    severity             TEXT    NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    category             TEXT    NOT NULL,
    reason               TEXT    NOT NULL,
    status               TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved', 'false_positive')),
    dedup_key            TEXT,
    evidence_json        TEXT,
    model_id             INTEGER REFERENCES model_registry (id) ON DELETE SET NULL,
    model_version        TEXT,
    created_at           TEXT    NOT NULL,
    acknowledged_by      INTEGER REFERENCES users (id) ON DELETE SET NULL,
    acknowledged_at      TEXT,
    resolved_by          INTEGER REFERENCES users (id) ON DELETE SET NULL,
    resolved_at          TEXT,
    investigation_notes  TEXT
);

CREATE INDEX idx_alerts_created ON alerts (created_at);
CREATE INDEX idx_alerts_status_severity ON alerts (status, severity);
CREATE INDEX idx_alerts_type ON alerts (alert_type);
CREATE INDEX idx_alerts_dedup ON alerts (dedup_key, created_at);

-- Status history and analyst notes for each alert.
CREATE TABLE alert_events (
    id           INTEGER PRIMARY KEY,
    alert_id     INTEGER NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    event_type   TEXT    NOT NULL CHECK (event_type IN ('created', 'status_change', 'note')),
    from_status  TEXT    CHECK (from_status IS NULL OR from_status IN ('open', 'acknowledged', 'resolved', 'false_positive')),
    to_status    TEXT    CHECK (to_status IS NULL OR to_status IN ('open', 'acknowledged', 'resolved', 'false_positive')),
    note         TEXT,
    user_id      INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at   TEXT    NOT NULL
);

CREATE INDEX idx_alert_events_alert_time ON alert_events (alert_id, created_at);

-- Correlated security/performance incidents.
CREATE TABLE incidents (
    id                         INTEGER PRIMARY KEY,
    title                      TEXT    NOT NULL CHECK (length(trim(title)) > 0),
    classification             TEXT    NOT NULL CHECK (classification IN ('security', 'performance', 'combined', 'undetermined')),
    status                     TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'closed')),
    window_start               TEXT    NOT NULL,
    window_end                 TEXT    NOT NULL CHECK (window_end >= window_start),
    measured_changes_json      TEXT,
    model_outputs_json         TEXT,
    correlation_rationale      TEXT    NOT NULL,
    investigation_steps_json   TEXT,
    created_by                 INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at                 TEXT    NOT NULL,
    updated_at                 TEXT    NOT NULL
);

CREATE INDEX idx_incidents_created ON incidents (created_at);
CREATE INDEX idx_incidents_status ON incidents (status);

CREATE TABLE incident_alerts (
    incident_id  INTEGER NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    alert_id     INTEGER NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, alert_id)
);

CREATE INDEX idx_incident_alerts_alert ON incident_alerts (alert_id);

CREATE TABLE bandwidth_policies (
    id                       INTEGER PRIMARY KEY,
    policy_name              TEXT    NOT NULL CHECK (length(trim(policy_name)) > 0),
    interface_name           TEXT,
    configured_capacity_bps  REAL    NOT NULL CHECK (configured_capacity_bps > 0),
    traffic_class            TEXT    NOT NULL CHECK (length(trim(traffic_class)) > 0),
    minimum_bps              REAL    NOT NULL DEFAULT 0 CHECK (minimum_bps >= 0),
    maximum_bps              REAL    NOT NULL CHECK (maximum_bps >= minimum_bps AND maximum_bps <= configured_capacity_bps),
    priority_weight          REAL    NOT NULL CHECK (priority_weight > 0),
    enabled                  INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at               TEXT    NOT NULL,
    updated_at               TEXT    NOT NULL,
    UNIQUE (policy_name, traffic_class)
);

CREATE TABLE bandwidth_recommendations (
    id                   INTEGER PRIMARY KEY,
    timestamp            TEXT    NOT NULL,
    source_name          TEXT    NOT NULL,
    interface_name       TEXT,
    capacity_bps         REAL    NOT NULL CHECK (capacity_bps > 0),
    recommendation_json  TEXT    NOT NULL,
    unmet_demand_bps     REAL    NOT NULL DEFAULT 0 CHECK (unmet_demand_bps >= 0),
    rationale            TEXT    NOT NULL,
    status               TEXT    NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed', 'accepted', 'rejected', 'applied', 'superseded')),
    created_by           INTEGER REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX idx_bandwidth_recommendations_time ON bandwidth_recommendations (timestamp);

CREATE TABLE policy_actions (
    id                  INTEGER PRIMARY KEY,
    recommendation_id   INTEGER REFERENCES bandwidth_recommendations (id) ON DELETE SET NULL,
    action_type         TEXT    NOT NULL CHECK (action_type IN ('apply', 'rollback', 'emergency_disable')),
    target_interface    TEXT    NOT NULL,
    policy_before_json  TEXT,
    policy_after_json   TEXT,
    status              TEXT    NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed', 'rolled_back')),
    executed_by         INTEGER REFERENCES users (id) ON DELETE SET NULL,
    executed_at         TEXT    NOT NULL,
    rollback_at         TEXT,
    error_message       TEXT
);

CREATE INDEX idx_policy_actions_executed ON policy_actions (executed_at);

CREATE TABLE audit_logs (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER REFERENCES users (id) ON DELETE SET NULL,
    action        TEXT    NOT NULL CHECK (length(action) > 0),
    outcome       TEXT    NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    details_json  TEXT,
    created_at    TEXT    NOT NULL
);

CREATE INDEX idx_audit_logs_created ON audit_logs (created_at);
CREATE INDEX idx_audit_logs_action ON audit_logs (action);
CREATE INDEX idx_audit_logs_user ON audit_logs (user_id);

-- Validated key/value settings (values are JSON text).
CREATE TABLE app_settings (
    key          TEXT PRIMARY KEY CHECK (key GLOB '[a-z]*' AND key NOT GLOB '*[^a-z0-9_.]*'),
    value_json   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    updated_by   INTEGER REFERENCES users (id) ON DELETE SET NULL
);
