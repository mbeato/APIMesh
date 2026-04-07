-- Migration 007: Add ToS acceptance timestamp to users
ALTER TABLE users ADD COLUMN tos_accepted_at TEXT;
