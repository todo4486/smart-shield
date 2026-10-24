-- 005_session_epoch: a counter bumped whenever a user's password is changed or reset.
-- Sessions remember the value they started with; a mismatch ends them, so a password
-- change signs out every other tab or device.

ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0 CHECK (session_epoch >= 0);
