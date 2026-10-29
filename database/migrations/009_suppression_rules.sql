-- Alert noise control (UI upgrade, phase 4). A suppression rule hides matching NEW alerts from the
-- unresolved queues, counts, correlation and the map. Suppressed alerts are still stored, keep their
-- status, and are listed under the "Suppressed" filter; nothing is deleted. Every rule has an author,
-- a reason and an expiry. Analysts can only request a rule; an administrator approves it.
CREATE TABLE suppression_rules (
    id            INTEGER PRIMARY KEY,
    alert_type    TEXT    CHECK (alert_type IS NULL OR alert_type IN ('security', 'anomaly', 'congestion', 'performance')),
    category      TEXT    CHECK (category IS NULL OR length(trim(category)) BETWEEN 1 AND 120),
    host          TEXT    CHECK (host IS NULL OR length(trim(host)) BETWEEN 1 AND 64),
    host_role     TEXT    NOT NULL DEFAULT 'source' CHECK (host_role IN ('source', 'destination')),
    reason        TEXT    NOT NULL CHECK (length(trim(reason)) BETWEEN 5 AND 500),
    status        TEXT    NOT NULL CHECK (status IN ('requested', 'active', 'rejected', 'revoked')),
    requested_by  INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at    TEXT    NOT NULL,
    expires_at    TEXT    NOT NULL CHECK (expires_at > created_at),
    reviewed_by   INTEGER REFERENCES users (id) ON DELETE SET NULL,
    reviewed_at   TEXT,
    review_note   TEXT    CHECK (review_note IS NULL OR length(review_note) <= 500),
    -- A rule must narrow something: at least one of type, category or host.
    CHECK (alert_type IS NOT NULL OR category IS NOT NULL OR host IS NOT NULL)
);

CREATE INDEX idx_suppression_rules_status_expiry ON suppression_rules (status, expires_at);

ALTER TABLE alerts ADD COLUMN suppressed_by_rule INTEGER REFERENCES suppression_rules (id) ON DELETE SET NULL;

CREATE INDEX idx_alerts_suppressed ON alerts (suppressed_by_rule);
