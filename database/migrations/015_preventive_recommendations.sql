-- What PredictNet's forecasts recommend doing before a link fills. Everything here is a prediction, not a measurement.
CREATE TABLE preventive_recommendations (
    id                        INTEGER PRIMARY KEY,
    session_id                INTEGER NOT NULL REFERENCES monitoring_sessions (id) ON DELETE CASCADE,
    origin                    TEXT    NOT NULL CHECK (origin IN ('real', 'replay', 'simulation')),
    source_name               TEXT    NOT NULL CHECK (length(source_name) <= 200),
    interface_name            TEXT    CHECK (interface_name IS NULL OR length(interface_name) <= 64),
    base_time                 TEXT    NOT NULL,
    target_time               TEXT    NOT NULL,
    horizon_seconds           INTEGER NOT NULL CHECK (horizon_seconds > 0),
    predicted_utilization     REAL    NOT NULL CHECK (predicted_utilization BETWEEN 0 AND 1),
    upper_utilization         REAL    CHECK (upper_utilization IS NULL OR upper_utilization BETWEEN 0 AND 1),
    threshold                 REAL    NOT NULL CHECK (threshold BETWEEN 0 AND 1),
    capacity_bps              REAL    CHECK (capacity_bps IS NULL OR capacity_bps > 0),
    strength                  TEXT    NOT NULL CHECK (strength IN ('likely', 'possible')),
    risk                      TEXT    NOT NULL CHECK (risk IN ('normal', 'elevated', 'high', 'critical', 'unknown')),
    model_id                  INTEGER REFERENCES model_registry (id) ON DELETE SET NULL,
    model_version             TEXT    NOT NULL,
    prediction_id             INTEGER REFERENCES congestion_predictions (id) ON DELETE SET NULL,
    model_validated           INTEGER NOT NULL CHECK (model_validated IN (0, 1)),
    consecutive               INTEGER NOT NULL DEFAULT 1 CHECK (consecutive >= 1),
    current_allocation_json   TEXT,
    projected_allocation_json TEXT,
    actions_json              TEXT    NOT NULL,
    automatic_note            TEXT    CHECK (automatic_note IS NULL OR length(automatic_note) <= 500),
    status                    TEXT    NOT NULL CHECK (status IN ('open', 'applied', 'dismissed', 'expired')),
    mitigation_id             INTEGER REFERENCES mitigation_actions (id) ON DELETE SET NULL,
    created_at                TEXT    NOT NULL,
    updated_at                TEXT    NOT NULL,
    decided_at                TEXT,
    decided_by                INTEGER REFERENCES users (id) ON DELETE SET NULL,
    decision_note             TEXT    CHECK (decision_note IS NULL OR length(decision_note) <= 500),
    provenance                TEXT    NOT NULL DEFAULT 'predicted' CHECK (provenance = 'predicted')
);
CREATE UNIQUE INDEX idx_preventive_one_open ON preventive_recommendations (session_id, COALESCE(interface_name, ''))
    WHERE status = 'open';
CREATE INDEX idx_preventive_session ON preventive_recommendations (session_id, id);
