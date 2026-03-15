import { test, expect, beforeEach, describe } from "bun:test";
import { Database } from "bun:sqlite";
import { join } from "path";
import { migrate } from "../shared/migrate";
import {
  generateApiKey,
  hashApiKey,
  createApiKey,
  lookupByHash,
  revokeApiKey,
  getUserKeys,
} from "../shared/api-key";

const migrationsDir = join(import.meta.dir, "..", "data", "migrations");
const testUserId = "user-apikey-001";

let db: Database;

beforeEach(() => {
  db = new Database(":memory:");
  db.exec("PRAGMA journal_mode=WAL;");
  db.exec("PRAGMA foreign_keys=ON;");
  migrate(db, migrationsDir);

  // Insert a test user
  db.run(
    "INSERT INTO users (id, email, password_hash, email_verified) VALUES (?, ?, ?, 1)",
    [testUserId, "keys@example.com", "hash"]
  );
});

describe("API Key generation", () => {
  test("generateApiKey returns plaintext starting with sk_live_ and 72 chars total, hash is 64 hex, prefix is 10 chars", () => {
    const { plaintext, hash, prefix } = generateApiKey();
    expect(plaintext).toStartWith("sk_live_");
    expect(plaintext).toHaveLength(72); // "sk_live_" (8) + 64 hex chars
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(prefix).toHaveLength(10);
    expect(prefix).toBe(plaintext.slice(0, 10));
  });

  test("hashApiKey(plaintext) === hash from generateApiKey (deterministic)", () => {
    const { plaintext, hash } = generateApiKey();
    expect(hashApiKey(plaintext)).toBe(hash);
  });
});

describe("API Key storage", () => {
  test("createApiKey stores hash and prefix, not plaintext", () => {
    const result = createApiKey(db, testUserId, "My Key");
    expect("plaintext" in result).toBe(true);

    if ("plaintext" in result) {
      // Verify plaintext is NOT stored in DB
      const row = db.query("SELECT key_hash, key_prefix FROM api_keys WHERE user_id = ?").get(testUserId) as any;
      expect(row.key_hash).not.toBe(result.plaintext);
      expect(row.key_hash).toBe(hashApiKey(result.plaintext));
      expect(row.key_prefix).toBe(result.prefix);
    }
  });

  test("lookupByHash finds the key row by plaintext", () => {
    const result = createApiKey(db, testUserId, "My Key");
    if (!("plaintext" in result)) throw new Error("Expected plaintext");

    const found = lookupByHash(db, result.plaintext);
    expect(found).not.toBeNull();
    expect(found!.user_id).toBe(testUserId);
    expect(found!.label).toBe("My Key");
  });

  test("lookupByHash with wrong key returns null", () => {
    createApiKey(db, testUserId, "My Key");
    const found = lookupByHash(db, "sk_live_" + "0".repeat(64));
    expect(found).toBeNull();
  });
});

describe("API Key revocation", () => {
  test("revokeApiKey sets revoked = 1", () => {
    const result = createApiKey(db, testUserId, "My Key");
    if (!("id" in result)) throw new Error("Expected id");

    const revoked = revokeApiKey(db, result.id, testUserId);
    expect(revoked).toBe(true);

    const row = db.query("SELECT revoked FROM api_keys WHERE id = ?").get(result.id) as any;
    expect(row.revoked).toBe(1);
  });

  test("lookupByHash on revoked key returns null (WHERE revoked = 0 filter)", () => {
    const result = createApiKey(db, testUserId, "My Key");
    if (!("plaintext" in result) || !("id" in result)) throw new Error("Expected plaintext and id");

    revokeApiKey(db, result.id, testUserId);
    const found = lookupByHash(db, result.plaintext);
    expect(found).toBeNull();
  });
});

describe("API Key listing", () => {
  test("getUserKeys returns list with prefix, label, last_used_at, revoked, created_at (never hash)", () => {
    createApiKey(db, testUserId, "Key 1");
    createApiKey(db, testUserId, "Key 2");

    const keys = getUserKeys(db, testUserId);
    expect(keys).toHaveLength(2);

    for (const key of keys) {
      expect(key).toHaveProperty("id");
      expect(key).toHaveProperty("key_prefix");
      expect(key).toHaveProperty("label");
      expect(key).toHaveProperty("last_used_at");
      expect(key).toHaveProperty("revoked");
      expect(key).toHaveProperty("created_at");
      // Ensure hash is never returned
      expect((key as any).key_hash).toBeUndefined();
    }
  });
});
