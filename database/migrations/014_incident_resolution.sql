-- Why a resolved incident was resolved. The other lifecycle states (Mitigation pending, Mitigation active, Failed
-- mitigation) are worked out from mitigation_actions, so they can never disagree with what is really in force.
ALTER TABLE incidents ADD COLUMN resolution TEXT CHECK (resolution IS NULL OR resolution IN ('false_positive'));
