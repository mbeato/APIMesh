-- Migration 001: Existing tables (idempotent with IF NOT EXISTS)
-- These match the schemas from shared/db.ts exactly

CREATE TABLE IF NOT EXISTS api_registry (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  port INTEGER NOT NULL,
  subdomain TEXT UNIQUE NOT NULL,
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  api_name TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  method TEXT NOT NULL,
  status_code INTEGER,
  response_time_ms REAL,
  paid INTEGER DEFAULT 0,
  amount_usd REAL DEFAULT 0,
  client_ip TEXT,
  payer_wallet TEXT,
  user_id TEXT,
  api_key_id TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS revenue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  api_name TEXT NOT NULL,
  amount_usd REAL NOT NULL,
  tx_hash TEXT,
  network TEXT,
  payer_wallet TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS spend_caps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  wallet TEXT UNIQUE NOT NULL,
  label TEXT,
  daily_limit_usd REAL,
  monthly_limit_usd REAL,
  enabled INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS backlog (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  description TEXT,
  demand_score REAL DEFAULT 0,
  effort_score REAL DEFAULT 0,
  competition_score REAL DEFAULT 0,
  overall_score REAL DEFAULT 0,
  status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT (datetime('now'))
);

-- Indexes for existing tables
CREATE INDEX IF NOT EXISTS idx_requests_created_at ON requests(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_requests_payer_wallet ON requests(payer_wallet);
CREATE INDEX IF NOT EXISTS idx_revenue_payer_wallet ON revenue(payer_wallet);
