import { test, expect, beforeEach, describe } from "bun:test";
import { Database } from "bun:sqlite";
import { join } from "path";
import { migrate } from "../shared/migrate";
import {
  getBalance,
  initBalance,
  addCredits,
  deductAndRecord,
  getTransactions,
} from "../shared/credits";

const migrationsDir = join(import.meta.dir, "..", "data", "migrations");
const testUserId = "user-credits-001";
let testKeyId: string;

let db: Database;

beforeEach(() => {
  db = new Database(":memory:");
  db.exec("PRAGMA journal_mode=WAL;");
  db.exec("PRAGMA foreign_keys=ON;");
  migrate(db, migrationsDir);

  // Insert a test user
  db.run(
    "INSERT INTO users (id, email, password_hash, email_verified) VALUES (?, ?, ?, 1)",
    [testUserId, "credits@example.com", "hash"]
  );

  // Initialize balance (as signup would do)
  initBalance(db, testUserId);

  // Insert a test API key for deductAndRecord tests
  testKeyId = crypto.randomUUID();
  db.run(
    "INSERT INTO api_keys (id, user_id, key_hash, key_prefix, label) VALUES (?, ?, ?, ?, ?)",
    [testKeyId, testUserId, "testhash123", "sk_live_te", "Test Key"]
  );
});

describe("Credits", () => {
  test("getBalance returns 0 for new user", () => {
    const balance = getBalance(db, testUserId);
    expect(balance).toBe(0);
  });

  test("addCredits increases balance and inserts credit_transactions row", () => {
    const result = addCredits(db, testUserId, 500000, "purchase", "pi_123");
    expect(result.success).toBe(true);
    expect(result.newBalance).toBe(500000);

    // Verify transaction was recorded
    const txns = getTransactions(db, testUserId);
    expect(txns).toHaveLength(1);
    expect(txns[0].type).toBe("purchase");
    expect(txns[0].amount_microdollars).toBe(500000);
  });

  test("addCredits with duplicate stripe_payment_intent returns error (idempotency)", () => {
    addCredits(db, testUserId, 500000, "purchase", "pi_duplicate");
    const result = addCredits(db, testUserId, 500000, "purchase again", "pi_duplicate");
    expect(result.success).toBe(false);
    expect(result.error).toBe("duplicate");
    // Balance should not have doubled
    expect(getBalance(db, testUserId)).toBe(500000);
  });

  test("deductAndRecord succeeds when balance >= cost", () => {
    addCredits(db, testUserId, 500000, "purchase");
    const result = deductAndRecord(db, testUserId, 10, "API call", testKeyId, "seo-analyzer");
    expect(result.success).toBe(true);
    expect(result.newBalance).toBe(499990);
  });

  test("deductAndRecord rejects when balance < cost, balance unchanged", () => {
    // Balance is 0
    const result = deductAndRecord(db, testUserId, 10, "API call", testKeyId, "seo-analyzer");
    expect(result.success).toBe(false);
    expect(getBalance(db, testUserId)).toBe(0);
  });

  test("deductAndRecord inserts a negative amount_microdollars credit_transactions row", () => {
    addCredits(db, testUserId, 500000, "purchase");
    deductAndRecord(db, testUserId, 10, "API call", testKeyId, "seo-analyzer");

    const txns = getTransactions(db, testUserId);
    const usageTxn = txns.find(t => t.type === "usage");
    expect(usageTxn).not.toBeUndefined();
    expect(usageTxn!.amount_microdollars).toBe(-10);
  });

  test("deductAndRecord updates api_keys.last_used_at atomically", () => {
    addCredits(db, testUserId, 500000, "purchase");

    // Verify last_used_at is initially null
    const before = db.query("SELECT last_used_at FROM api_keys WHERE id = ?").get(testKeyId) as any;
    expect(before.last_used_at).toBeNull();

    deductAndRecord(db, testUserId, 10, "API call", testKeyId, "seo-analyzer");

    const after = db.query("SELECT last_used_at FROM api_keys WHERE id = ?").get(testKeyId) as any;
    expect(after.last_used_at).not.toBeNull();
  });

  test("Balance never goes negative after deduction (CHECK constraint)", () => {
    addCredits(db, testUserId, 5, "small purchase");
    const result = deductAndRecord(db, testUserId, 10, "API call", testKeyId, "seo-analyzer");
    expect(result.success).toBe(false);
    expect(getBalance(db, testUserId)).toBe(5);
  });

  test("DB rejects direct UPDATE setting balance_microdollars to negative (CHECK constraint)", () => {
    expect(() => {
      db.run(
        "UPDATE credit_balances SET balance_microdollars = -1 WHERE user_id = ?",
        [testUserId]
      );
    }).toThrow();
  });
});
