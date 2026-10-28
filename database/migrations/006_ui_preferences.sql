-- Per-user display preferences (UI upgrade, phase 1).
CREATE TABLE user_preferences (
    user_id        INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    reduce_motion  INTEGER NOT NULL DEFAULT 0 CHECK (reduce_motion IN (0, 1)),
    updated_at     TEXT    NOT NULL
);

-- Header strip: newest utilization per interface without scanning every metric row.
CREATE INDEX idx_network_metrics_util_iface_time ON network_metrics (interface_name, timestamp)
    WHERE utilization_ratio IS NOT NULL;
