-- Incident triage (UI upgrade, phase 2): assignment and a full event history (status changes,
-- assignments, analyst notes). Acknowledge = open → investigating.
ALTER TABLE incidents ADD COLUMN assigned_to INTEGER REFERENCES users (id) ON DELETE SET NULL;

CREATE TABLE incident_events (
    id           INTEGER PRIMARY KEY,
    incident_id  INTEGER NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    event_type   TEXT    NOT NULL CHECK (event_type IN ('status_change', 'assignment', 'note')),
    from_status  TEXT    CHECK (from_status IS NULL OR from_status IN ('open', 'investigating', 'resolved', 'closed')),
    to_status    TEXT    CHECK (to_status IS NULL OR to_status IN ('open', 'investigating', 'resolved', 'closed')),
    assigned_to  INTEGER REFERENCES users (id) ON DELETE SET NULL,
    note         TEXT    CHECK (note IS NULL OR length(note) <= 2000),
    user_id      INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at   TEXT    NOT NULL
);

CREATE INDEX idx_incident_events_incident_time ON incident_events (incident_id, created_at);
