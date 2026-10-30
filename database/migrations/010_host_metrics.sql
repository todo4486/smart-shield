-- Per-host live bandwidth (adaptive mitigation, phase M1): what each IP address sent and received in one sampling
-- interval, measured from captured packets. A host with no traffic in an interval has no row, never a row of zeros.
CREATE TABLE host_metrics (
    id                  INTEGER PRIMARY KEY,
    session_id          INTEGER NOT NULL REFERENCES monitoring_sessions (id) ON DELETE CASCADE,
    timestamp           TEXT    NOT NULL,
    host                TEXT    NOT NULL CHECK (length(trim(host)) BETWEEN 1 AND 64),
    sent_bps            REAL    NOT NULL CHECK (sent_bps >= 0),
    received_bps        REAL    NOT NULL CHECK (received_bps >= 0),
    sent_pps            REAL    NOT NULL CHECK (sent_pps >= 0),
    received_pps        REAL    NOT NULL CHECK (received_pps >= 0),
    active_connections  INTEGER NOT NULL CHECK (active_connections >= 0),
    provenance          TEXT    NOT NULL DEFAULT 'measured' CHECK (provenance IN ('measured', 'derived', 'unavailable'))
);

CREATE INDEX idx_host_metrics_session_time ON host_metrics (session_id, timestamp);

CREATE INDEX idx_host_metrics_time ON host_metrics (timestamp);
