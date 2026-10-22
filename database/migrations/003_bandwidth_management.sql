-- 003_bandwidth_management: optional DSCP match per traffic class (used only by
-- the opt-in traffic-shaping backend to classify packets) and an index for
-- looking up the latest shaping action per interface.

ALTER TABLE bandwidth_policies ADD COLUMN dscp INTEGER CHECK (dscp IS NULL OR dscp BETWEEN 0 AND 63);

CREATE INDEX idx_bandwidth_policies_name ON bandwidth_policies (policy_name);
CREATE INDEX idx_policy_actions_interface ON policy_actions (target_interface, executed_at);
