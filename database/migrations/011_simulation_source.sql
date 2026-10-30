-- requires: foreign_keys_off
-- Simulation mode (adaptive mitigation, phase M2). Synthetic traffic records created in memory, never packets on a
-- network, are stored under their own source type so they never mix with captured, imported or replayed data and
-- can be cleared on their own. SQLite cannot change a CHECK in place, so monitoring_sessions is rebuilt the same way
-- as migration 008: every row and column is copied.
CREATE TABLE monitoring_sessions_new (
    id                  INTEGER PRIMARY KEY,
    user_id             INTEGER REFERENCES users (id) ON DELETE SET NULL,
    source_type         TEXT    NOT NULL CHECK (source_type IN ('dataset', 'historical_import', 'flow_import', 'live_capture', 'replay', 'simulation')),
    interface_name      TEXT,
    started_at          TEXT    NOT NULL,
    ended_at            TEXT    CHECK (ended_at IS NULL OR ended_at >= started_at),
    status              TEXT    NOT NULL CHECK (status IN ('STOPPED', 'STARTING', 'RUNNING', 'STOPPING', 'ERROR')),
    status_message      TEXT,
    configuration_json  TEXT,
    dataset_id          INTEGER REFERENCES datasets (id) ON DELETE SET NULL
);

INSERT INTO monitoring_sessions_new (id, user_id, source_type, interface_name, started_at, ended_at, status,
                                     status_message, configuration_json, dataset_id)
SELECT id, user_id, source_type, interface_name, started_at, ended_at, status, status_message, configuration_json,
       dataset_id
FROM monitoring_sessions;

DROP TABLE monitoring_sessions;

ALTER TABLE monitoring_sessions_new RENAME TO monitoring_sessions;

CREATE INDEX idx_monitoring_sessions_dataset ON monitoring_sessions (dataset_id);

CREATE INDEX idx_monitoring_sessions_started ON monitoring_sessions (started_at);

CREATE INDEX idx_monitoring_sessions_status ON monitoring_sessions (status);

CREATE INDEX idx_monitoring_sessions_source ON monitoring_sessions (source_type);

-- Incidents built only from simulated alerts are marked, so correlation never merges them with anything else.
ALTER TABLE incidents ADD COLUMN is_simulation INTEGER NOT NULL DEFAULT 0 CHECK (is_simulation IN (0, 1));
