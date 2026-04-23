-- Migration 009: Add user_agent column to requests for crawler/client identification
ALTER TABLE requests ADD COLUMN user_agent TEXT DEFAULT NULL;
