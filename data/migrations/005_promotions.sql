CREATE TABLE IF NOT EXISTS promotions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  api_name TEXT NOT NULL,
  channel TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  url TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(api_name, channel)
);
