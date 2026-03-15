import { test, expect, describe, beforeEach } from "bun:test";
import { Database } from "bun:sqlite";
import { migrate } from "../shared/migrate";
import { join } from "path";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";

const MIGRATIONS_DIR = join(import.meta.dir, "..", "data", "migrations");

describe("migrate", () => {
  let db: Database;

  beforeEach(() => {
    db = new Database(":memory:");
    db.exec("PRAGMA journal_mode=WAL;");
    db.exec("PRAGMA foreign_keys=ON;");
  });

  test("creates _migrations table with 2 rows (001, 002)", () => {
    migrate(db, MIGRATIONS_DIR);
    const rows = db.query("SELECT name FROM _migrations ORDER BY name").all() as { name: string }[];
    expect(rows).toHaveLength(2);
    expect(rows[0].name).toBe("001_existing_tables.sql");
    expect(rows[1].name).toBe("002_auth_tables.sql");
  });

  test("all 13 tables exist after migration", () => {
    migrate(db, MIGRATIONS_DIR);
    const tables = db
      .query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('_migrations', 'sqlite_sequence') ORDER BY name")
      .all() as { name: string }[];
    const tableNames = tables.map((t) => t.name).sort();
    expect(tableNames).toEqual([
      "api_keys",
      "api_registry",
      "auth_events",
      "auth_rate_limits",
      "backlog",
      "credit_balances",
      "credit_transactions",
      "requests",
      "revenue",
      "sessions",
      "spend_caps",
      "users",
      "verification_codes",
    ]);
  });

  test("requests table has user_id and api_key_id columns after migration", () => {
    migrate(db, MIGRATIONS_DIR);
    const cols = db
      .query("SELECT name FROM pragma_table_info('requests') WHERE name IN ('user_id', 'api_key_id')")
      .all() as { name: string }[];
    const colNames = cols.map((c) => c.name).sort();
    expect(colNames).toEqual(["api_key_id", "user_id"]);
  });

  test("all indexes exist", () => {
    migrate(db, MIGRATIONS_DIR);
    const indexes = db
      .query("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%' ORDER BY name")
      .all() as { name: string }[];
    const indexNames = indexes.map((i) => i.name);
    expect(indexNames).toContain("idx_sessions_user_id");
    expect(indexNames).toContain("idx_sessions_expires_at");
    expect(indexNames).toContain("idx_api_keys_user_id");
    expect(indexNames).toContain("idx_api_keys_key_hash");
    expect(indexNames).toContain("idx_credit_transactions_user_id");
    expect(indexNames).toContain("idx_verification_codes_user_id");
    expect(indexNames).toContain("idx_auth_events_user_id");
    expect(indexNames).toContain("idx_requests_user_id");
    expect(indexNames).toContain("idx_api_keys_active");
    expect(indexNames).toContain("idx_requests_created_at");
    expect(indexNames).toContain("idx_requests_payer_wallet");
    expect(indexNames).toContain("idx_revenue_payer_wallet");
  });

  test("running migrate() twice produces no errors (idempotency)", () => {
    migrate(db, MIGRATIONS_DIR);
    expect(() => migrate(db, MIGRATIONS_DIR)).not.toThrow();

    const rows = db.query("SELECT name FROM _migrations ORDER BY name").all() as { name: string }[];
    expect(rows).toHaveLength(2);
  });

  test("foreign keys work - inserting session with nonexistent user_id fails", () => {
    migrate(db, MIGRATIONS_DIR);
    expect(() => {
      db.exec(
        `INSERT INTO sessions (id, user_id, expires_at, absolute_expires_at) VALUES ('s1', 'nonexistent', datetime('now', '+1 hour'), datetime('now', '+90 days'))`
      );
    }).toThrow();
  });

  test("credit_balances.balance_microdollars is INTEGER type", () => {
    migrate(db, MIGRATIONS_DIR);
    const col = db
      .query("SELECT type FROM pragma_table_info('credit_balances') WHERE name='balance_microdollars'")
      .get() as { type: string } | null;
    expect(col).not.toBeNull();
    expect(col!.type).toBe("INTEGER");
  });

  test("credit_balances CHECK constraint rejects negative balance", () => {
    migrate(db, MIGRATIONS_DIR);
    // First create a user so FK passes
    db.exec(`INSERT INTO users (id, email, password_hash) VALUES ('u1', 'a@b.com', 'hash')`);
    expect(() => {
      db.exec(
        `INSERT INTO credit_balances (user_id, balance_microdollars) VALUES ('u1', -1)`
      );
    }).toThrow();
  });

  test("credit_transactions CHECK constraint rejects invalid type", () => {
    migrate(db, MIGRATIONS_DIR);
    db.exec(`INSERT INTO users (id, email, password_hash) VALUES ('u1', 'a@b.com', 'hash')`);
    expect(() => {
      db.exec(
        `INSERT INTO credit_transactions (id, user_id, type, amount_microdollars) VALUES ('t1', 'u1', 'invalid', 100)`
      );
    }).toThrow();
  });

  test("verification_codes has code_hash and purpose columns (not plaintext code column)", () => {
    migrate(db, MIGRATIONS_DIR);
    const cols = db
      .query("SELECT name FROM pragma_table_info('verification_codes')")
      .all() as { name: string }[];
    const colNames = cols.map((c) => c.name);
    expect(colNames).toContain("code_hash");
    expect(colNames).toContain("purpose");
    expect(colNames).not.toContain("code");
  });

  test("sessions has absolute_expires_at column", () => {
    migrate(db, MIGRATIONS_DIR);
    const col = db
      .query("SELECT name FROM pragma_table_info('sessions') WHERE name='absolute_expires_at'")
      .get() as { name: string } | null;
    expect(col).not.toBeNull();
  });

  test("migration runner detects modified .sql file", () => {
    migrate(db, MIGRATIONS_DIR);

    // Create a temp migration dir with a modified file
    const tmpDir = join(import.meta.dir, "__tmp_migrations__");
    mkdirSync(tmpDir, { recursive: true });

    try {
      // Write a migration file
      writeFileSync(join(tmpDir, "001_test.sql"), "CREATE TABLE test_table (id INTEGER PRIMARY KEY);");

      const db2 = new Database(":memory:");
      db2.exec("PRAGMA journal_mode=WAL;");
      db2.exec("PRAGMA foreign_keys=ON;");
      migrate(db2, tmpDir);

      // Modify the file
      writeFileSync(join(tmpDir, "001_test.sql"), "CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT);");

      // Second run should throw due to checksum mismatch
      expect(() => migrate(db2, tmpDir)).toThrow();
      db2.close();
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test("partial index idx_api_keys_active exists", () => {
    migrate(db, MIGRATIONS_DIR);
    const idx = db
      .query("SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_api_keys_active'")
      .get() as { sql: string } | null;
    expect(idx).not.toBeNull();
    expect(idx!.sql).toContain("WHERE revoked = 0");
  });
});
