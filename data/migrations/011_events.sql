-- Migration 011: events table for wedge funnel analytics.
-- Captures coarse interaction signals (page_load, demo_started, demo_success,
-- signup_focused, etc) so we can see WHERE in the page visitors fall off,
-- not just whether they hit the entry endpoint.

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  event_type TEXT NOT NULL,
  client_ip TEXT,
  user_agent TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_source_type_created ON events(source, event_type, created_at DESC);
