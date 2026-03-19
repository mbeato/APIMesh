-- Migration 004: Add alert threshold and last alert sent columns to credit_balances
-- These support the low-balance email alert feature (BILL-08)

ALTER TABLE credit_balances ADD COLUMN alert_threshold_microdollars INTEGER DEFAULT NULL;
ALTER TABLE credit_balances ADD COLUMN last_alert_sent_at TEXT DEFAULT NULL;
