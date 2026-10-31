-- Real enforcement: which interface a mitigation acts on, and the exact commands it ran (or, in a dry run, would run).
ALTER TABLE mitigation_actions ADD COLUMN interface_name TEXT CHECK (interface_name IS NULL OR length(interface_name) <= 64);
ALTER TABLE mitigation_actions ADD COLUMN commands_json TEXT;
