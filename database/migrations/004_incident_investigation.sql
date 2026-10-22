-- 004_incident_investigation: analyst notes on incidents and lookups used by the
-- correlation engine.

ALTER TABLE incidents ADD COLUMN investigation_notes TEXT;

CREATE INDEX idx_incidents_window ON incidents (window_start, window_end);
CREATE INDEX idx_alerts_status_created ON alerts (status, created_at);
