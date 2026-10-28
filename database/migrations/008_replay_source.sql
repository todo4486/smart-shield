-- requires: foreign_keys_off
-- Replay / demo mode (UI upgrade, phase 3). A labelled dataset replayed through the detection pipeline is
-- stored under its own source type, 'replay', so it never mixes with captured or imported data and can be
-- cleared on its own. SQLite cannot change a CHECK constraint in place, so monitoring_sessions is rebuilt
-- with the documented copy-and-rename procedure. No row is dropped: every column is copied as it is.
-- The runner switches foreign keys off for this migration (otherwise dropping the old table would cascade
-- to network_flows and network_metrics) and runs PRAGMA foreign_key_check before committing.
CREATE TABLE monitoring_sessions_new (
    id                  INTEGER PRIMARY KEY,
    user_id             INTEGER REFERENCES users (id) ON DELETE SET NULL,
    source_type         TEXT    NOT NULL CHECK (source_type IN ('dataset', 'historical_import', 'flow_import', 'live_capture', 'replay')),
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

-- Incidents built only from replayed alerts are marked, so correlation never merges replay alerts with real
-- ones and "Clear replay data" can remove them.
ALTER TABLE incidents ADD COLUMN is_replay INTEGER NOT NULL DEFAULT 0 CHECK (is_replay IN (0, 1));
