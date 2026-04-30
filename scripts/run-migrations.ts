#!/usr/bin/env bun
// Runs database migrations idempotently. Safe to re-run.
// Usage on prod: ssh conway-prod 'cd /opt/conway-agent && DATA_DIR=/opt/conway-agent/data bun scripts/run-migrations.ts'
//
// The migration system in shared/migrate.ts tracks applied migrations by
// name + SHA-256 checksum in the _migrations table, so re-running this
// script is a no-op once every file has been applied.
import "../shared/db";
console.log("✓ migrations applied");
