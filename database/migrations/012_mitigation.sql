-- Adaptive mitigation M3. A mitigation is one decision about one target: proposed by the engine or an administrator,
-- then approved, rejected, applied, expired or rolled back. Nothing here is deleted when it ends; the row is the history.
CREATE TABLE mitigation_actions (
    id                        INTEGER PRIMARY KEY,
    origin                    TEXT    NOT NULL CHECK (origin IN ('real', 'simulation')),
    session_id                INTEGER REFERENCES monitoring_sessions (id) ON DELETE SET NULL,
    incident_id               INTEGER REFERENCES incidents (id) ON DELETE SET NULL,
    action_type               TEXT    NOT NULL CHECK (action_type IN ('rate_limit', 'prioritize', 'block', 'isolate')),
    target_kind               TEXT    NOT NULL CHECK (target_kind IN ('source', 'destination', 'link')),
    target                    TEXT    NOT NULL CHECK (length(trim(target)) BETWEEN 1 AND 64),
    status                    TEXT    NOT NULL CHECK (status IN ('proposed', 'active', 'rejected', 'expired', 'rolled_back',
                                                                 'failed', 'ended')),
    initiated_by              TEXT    NOT NULL CHECK (initiated_by IN ('engine', 'admin')),
    limit_bps                 REAL    CHECK (limit_bps IS NULL OR limit_bps > 0),
    duration_seconds          INTEGER NOT NULL CHECK (duration_seconds BETWEEN 60 AND 86400),
    reason                    TEXT    NOT NULL CHECK (length(trim(reason)) BETWEEN 5 AND 500),
    -- What the engine saw. Confidence and false-positive risk are heuristics, never calibrated probabilities.
    category                  TEXT    CHECK (category IS NULL OR length(category) <= 120),
    source_ip                 TEXT    CHECK (source_ip IS NULL OR length(source_ip) <= 64),
    destination_ip            TEXT    CHECK (destination_ip IS NULL OR length(destination_ip) <= 64),
    severity                  TEXT    CHECK (severity IS NULL OR severity IN ('low', 'medium', 'high', 'critical')),
    confidence                REAL    CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    confidence_basis          TEXT    CHECK (confidence_basis IS NULL OR confidence_basis IN ('classifier_votes', 'flag_share')),
    false_positive_risk       REAL    CHECK (false_positive_risk IS NULL OR false_positive_risk BETWEEN 0 AND 1),
    repetition                INTEGER CHECK (repetition IS NULL OR repetition >= 0),
    flagged_flows             INTEGER CHECK (flagged_flows IS NULL OR flagged_flows >= 0),
    traffic_bps               REAL    CHECK (traffic_bps IS NULL OR traffic_bps >= 0),
    assessment_json           TEXT,
    upstream_required         INTEGER NOT NULL DEFAULT 0 CHECK (upstream_required IN (0, 1)),
    -- Before and after, taken from stored samples.
    previous_allocation_json  TEXT,
    new_allocation_json       TEXT,
    before_json               TEXT,
    after_json                TEXT,
    recovery_status           TEXT    NOT NULL DEFAULT 'not_applied'
                                      CHECK (recovery_status IN ('not_applied', 'pending', 'recovered', 'partial',
                                                                 'not_recovered', 'unavailable')),
    recovery_note             TEXT    CHECK (recovery_note IS NULL OR length(recovery_note) <= 500),
    adapter                   TEXT    CHECK (adapter IS NULL OR length(adapter) <= 40),
    execution_ms              REAL    CHECK (execution_ms IS NULL OR execution_ms >= 0),
    failure_reason            TEXT    CHECK (failure_reason IS NULL OR length(failure_reason) <= 500),
    created_at                TEXT    NOT NULL,
    decided_at                TEXT,
    decided_by                INTEGER REFERENCES users (id) ON DELETE SET NULL,
    decision_note             TEXT    CHECK (decision_note IS NULL OR length(decision_note) <= 500),
    applied_at                TEXT,
    expires_at                TEXT    CHECK (expires_at IS NULL OR applied_at IS NULL OR expires_at > applied_at),
    ended_at                  TEXT,
    ended_by                  INTEGER REFERENCES users (id) ON DELETE SET NULL,
    end_reason                TEXT    CHECK (end_reason IS NULL OR length(end_reason) <= 500),
    -- A rate limit needs a limit; blocking, isolating and prioritizing do not take one.
    CHECK ((action_type = 'rate_limit') = (limit_bps IS NOT NULL)),
    -- Only prioritizing acts on the whole link.
    CHECK ((action_type = 'prioritize') = (target_kind = 'link')),
    -- Whatever is active has a decision and an expiry. The service only lets an administrator decide a block or isolation.
    CHECK (status <> 'active' OR (decided_at IS NOT NULL AND applied_at IS NOT NULL AND expires_at IS NOT NULL))
);

CREATE UNIQUE INDEX idx_mitigation_one_open_per_target
    ON mitigation_actions (origin, COALESCE(session_id, 0), action_type, target_kind, target)
    WHERE status IN ('proposed', 'active');
CREATE INDEX idx_mitigation_session_status ON mitigation_actions (session_id, status);
CREATE INDEX idx_mitigation_status_expiry ON mitigation_actions (status, expires_at);
CREATE INDEX idx_mitigation_incident ON mitigation_actions (incident_id);

-- What the allocator calculated for one interval: the class and host split, and whether it was being enforced.
CREATE TABLE allocation_snapshots (
    id            INTEGER PRIMARY KEY,
    session_id    INTEGER NOT NULL REFERENCES monitoring_sessions (id) ON DELETE CASCADE,
    timestamp     TEXT    NOT NULL,
    capacity_bps  REAL    NOT NULL CHECK (capacity_bps > 0),
    enforced      INTEGER NOT NULL CHECK (enforced IN (0, 1)),
    classes_json  TEXT    NOT NULL,
    hosts_json    TEXT    NOT NULL,
    provenance    TEXT    NOT NULL CHECK (provenance IN ('derived'))
);

CREATE INDEX idx_allocation_snapshots_session_time ON allocation_snapshots (session_id, timestamp);
