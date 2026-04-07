-- Migration 008: Add demand data columns to backlog
ALTER TABLE backlog ADD COLUMN search_volume INTEGER DEFAULT NULL;
ALTER TABLE backlog ADD COLUMN marketplace_listings INTEGER DEFAULT NULL;
ALTER TABLE backlog ADD COLUMN measured_demand_score REAL DEFAULT NULL;
ALTER TABLE backlog ADD COLUMN demand_source TEXT DEFAULT NULL;
ALTER TABLE backlog ADD COLUMN category TEXT DEFAULT NULL;
