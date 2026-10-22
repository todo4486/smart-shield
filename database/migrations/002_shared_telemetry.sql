-- 002_shared_telemetry: registered datasets, links from monitoring sessions to
-- their source dataset, and per-field provenance for values the importer derives.

CREATE TABLE datasets (
    id                       INTEGER PRIMARY KEY,
    name                     TEXT    NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 200),
    kind                     TEXT    NOT NULL CHECK (kind IN ('intrusion_flows', 'telemetry')),
    original_filename        TEXT    NOT NULL,
    stored_path              TEXT,
    sha256                   TEXT    NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    size_bytes               INTEGER NOT NULL CHECK (size_bytes >= 0),
    row_count                INTEGER NOT NULL CHECK (row_count >= 0),
    column_count             INTEGER NOT NULL CHECK (column_count >= 0),
    columns_json             TEXT    NOT NULL,
    label_column             TEXT,
    label_distribution_json  TEXT,
    has_timestamps           INTEGER NOT NULL DEFAULT 0 CHECK (has_timestamps IN (0, 1)),
    profile_json             TEXT,
    uploaded_by              INTEGER REFERENCES users (id) ON DELETE SET NULL,
    uploaded_at              TEXT    NOT NULL,
    UNIQUE (kind, sha256)
);

CREATE INDEX idx_datasets_uploaded ON datasets (uploaded_at);

ALTER TABLE monitoring_sessions ADD COLUMN dataset_id INTEGER REFERENCES datasets (id) ON DELETE SET NULL;

CREATE INDEX idx_monitoring_sessions_dataset ON monitoring_sessions (dataset_id);

-- Row-level `provenance` describes the measurements as delivered. These two
-- columns say how the throughput / utilization value in the same row was obtained.
ALTER TABLE network_metrics ADD COLUMN throughput_provenance TEXT
    CHECK (throughput_provenance IS NULL OR throughput_provenance IN ('measured', 'derived', 'unavailable'));

ALTER TABLE network_metrics ADD COLUMN utilization_provenance TEXT
    CHECK (utilization_provenance IS NULL OR utilization_provenance IN ('measured', 'derived', 'unavailable'));

ALTER TABLE network_metrics ADD COLUMN capacity_provenance TEXT
    CHECK (capacity_provenance IS NULL OR capacity_provenance IN ('measured', 'configured', 'unavailable'));
