-- Migration 010: Email capture + traffic attribution
-- Two changes:
--   1. Add referer + UTM columns to requests for traffic-source attribution
--      (lets us see which cold-email link / X post / SEO term sent the visit).
--   2. Add signup_notifications table for "notify me when X launches" capture
--      from wedge landing pages (agentcontext, sigdebug).

ALTER TABLE requests ADD COLUMN referer TEXT DEFAULT NULL;
ALTER TABLE requests ADD COLUMN utm_source TEXT DEFAULT NULL;
ALTER TABLE requests ADD COLUMN utm_medium TEXT DEFAULT NULL;
ALTER TABLE requests ADD COLUMN utm_campaign TEXT DEFAULT NULL;

CREATE TABLE IF NOT EXISTS signup_notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  source TEXT NOT NULL,
  interest TEXT,
  ip TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(email, source)
);

CREATE INDEX IF NOT EXISTS idx_signup_notifications_source ON signup_notifications(source);
CREATE INDEX IF NOT EXISTS idx_signup_notifications_created_at ON signup_notifications(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_requests_utm_source ON requests(utm_source);
