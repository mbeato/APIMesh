-- Migration 003: Allow NULL user_id in auth_events for failed login attempts on unknown emails
-- SQLite doesn't support ALTER COLUMN, so we recreate the table

CREATE TABLE IF NOT EXISTS auth_events_new (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  event TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  metadata TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT OR IGNORE INTO auth_events_new SELECT * FROM auth_events;

DROP TABLE IF EXISTS auth_events;

ALTER TABLE auth_events_new RENAME TO auth_events;

-- Recreate index
CREATE INDEX IF NOT EXISTS idx_auth_events_user_id ON auth_events(user_id);
