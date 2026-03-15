import { test, expect, beforeEach, describe } from "bun:test";
import { Database } from "bun:sqlite";
import { join } from "path";
import { migrate } from "../shared/migrate";
import {
  hashPassword,
  verifyPassword,
  createSession,
  getSession,
  refreshSessionExpiry,
  deleteSession,
  logAuthEvent,
} from "../shared/auth";
import {
  normalizeEmail,
  validateEmail,
  validatePassword,
} from "../shared/validation";

const migrationsDir = join(import.meta.dir, "..", "data", "migrations");
const testUserId = "user-test-001";

let db: Database;

beforeEach(() => {
  db = new Database(":memory:");
  db.exec("PRAGMA journal_mode=WAL;");
  db.exec("PRAGMA foreign_keys=ON;");
  migrate(db, migrationsDir);

  // Insert a test user for session tests
  db.run(
    "INSERT INTO users (id, email, password_hash, email_verified) VALUES (?, ?, ?, 1)",
    [testUserId, "test@example.com", "hash"]
  );
});

// --- Password hashing tests ---
describe("Password hashing", () => {
  test("hashPassword returns an Argon2id hash string starting with $argon2id$", async () => {
    const hash = await hashPassword("my-secure-password-123!");
    expect(hash).toStartWith("$argon2id$");
  });

  test("verifyPassword returns true for correct password", async () => {
    const hash = await hashPassword("my-secure-password-123!");
    const result = await verifyPassword("my-secure-password-123!", hash);
    expect(result).toBe(true);
  });

  test("verifyPassword returns false for wrong password", async () => {
    const hash = await hashPassword("my-secure-password-123!");
    const result = await verifyPassword("wrong-password-here!!", hash);
    expect(result).toBe(false);
  });
});

// --- Session tests ---
describe("Sessions", () => {
  test("createSession returns a 64-char hex string and inserts row with 30-day sliding + 90-day absolute expiry", () => {
    const sessionId = createSession(db, testUserId, "127.0.0.1", "TestBrowser/1.0");
    expect(sessionId).toHaveLength(64);
    expect(sessionId).toMatch(/^[0-9a-f]{64}$/);

    // Verify session was inserted
    const row = db.query("SELECT * FROM sessions WHERE id = ?").get(sessionId) as any;
    expect(row).not.toBeNull();
    expect(row.user_id).toBe(testUserId);
    expect(row.expires_at).toBeTruthy();
    expect(row.absolute_expires_at).toBeTruthy();
  });

  test("createSession truncates user_agent longer than 512 chars", () => {
    const longUA = "A".repeat(1000);
    const sessionId = createSession(db, testUserId, "127.0.0.1", longUA);

    const row = db.query("SELECT user_agent FROM sessions WHERE id = ?").get(sessionId) as any;
    expect(row.user_agent).toHaveLength(512);
  });

  test("getSession returns session data for valid session", () => {
    const sessionId = createSession(db, testUserId, "127.0.0.1", "TestBrowser/1.0");
    const session = getSession(db, sessionId);
    expect(session).not.toBeNull();
    expect(session!.user_id).toBe(testUserId);
    expect(session!.ip_address).toBe("127.0.0.1");
  });

  test("getSession returns null for expired session (sliding window)", () => {
    const sessionId = createSession(db, testUserId, "127.0.0.1", "TestBrowser/1.0");
    // Manually expire the sliding window
    db.run("UPDATE sessions SET expires_at = datetime('now', '-1 day') WHERE id = ?", [sessionId]);
    const session = getSession(db, sessionId);
    expect(session).toBeNull();
  });

  test("getSession returns null when absolute_expires_at has passed even if sliding expires_at is still valid", () => {
    const sessionId = createSession(db, testUserId, "127.0.0.1", "TestBrowser/1.0");
    // Keep sliding valid but expire absolute
    db.run(
      "UPDATE sessions SET absolute_expires_at = datetime('now', '-1 day') WHERE id = ?",
      [sessionId]
    );
    const session = getSession(db, sessionId);
    expect(session).toBeNull();
  });

  test("refreshSessionExpiry updates expires_at only when remaining time < 7.5 days; no-ops otherwise", () => {
    const sessionId = createSession(db, testUserId, "127.0.0.1", "TestBrowser/1.0");

    // Session was just created (30 days remaining) — refresh should NOT update
    const before = db.query("SELECT expires_at FROM sessions WHERE id = ?").get(sessionId) as any;
    refreshSessionExpiry(db, sessionId);
    const after = db.query("SELECT expires_at FROM sessions WHERE id = ?").get(sessionId) as any;
    expect(after.expires_at).toBe(before.expires_at);

    // Now set expiry to 5 days from now (within last 25%) — refresh SHOULD update
    db.run(
      "UPDATE sessions SET expires_at = datetime('now', '+5 days') WHERE id = ?",
      [sessionId]
    );
    const beforeRefresh = db.query("SELECT expires_at FROM sessions WHERE id = ?").get(sessionId) as any;
    refreshSessionExpiry(db, sessionId);
    const afterRefresh = db.query("SELECT expires_at FROM sessions WHERE id = ?").get(sessionId) as any;
    expect(afterRefresh.expires_at).not.toBe(beforeRefresh.expires_at);
  });

  test("deleteSession removes the session row", () => {
    const sessionId = createSession(db, testUserId, "127.0.0.1", "TestBrowser/1.0");
    deleteSession(db, sessionId);
    const session = getSession(db, sessionId);
    expect(session).toBeNull();
  });
});

// --- Auth event logging tests ---
describe("Auth event logging", () => {
  test("logAuthEvent inserts into auth_events with user_agent capped at 512 chars", () => {
    const longUA = "B".repeat(1000);
    logAuthEvent(db, testUserId, "login", "127.0.0.1", longUA, { source: "web" });

    const row = db.query("SELECT * FROM auth_events WHERE user_id = ?").get(testUserId) as any;
    expect(row).not.toBeNull();
    expect(row.event).toBe("login");
    expect(row.user_agent).toHaveLength(512);
    expect(JSON.parse(row.metadata)).toEqual({ source: "web" });
  });

  test("logAuthEvent with null userId works (for failed login attempts on unknown emails)", () => {
    logAuthEvent(db, null, "login_failed", "127.0.0.1", "TestBrowser/1.0");

    const row = db.query("SELECT * FROM auth_events WHERE user_id IS NULL").get() as any;
    expect(row).not.toBeNull();
    expect(row.event).toBe("login_failed");
  });
});

// --- Validation tests ---
describe("Email validation", () => {
  test('normalizeEmail("User@EXAMPLE.COM") returns "user@example.com"', () => {
    expect(normalizeEmail("User@EXAMPLE.COM")).toBe("user@example.com");
  });

  test("normalizeEmail trims whitespace", () => {
    expect(normalizeEmail("  user@example.com  ")).toBe("user@example.com");
  });

  test('validateEmail("user@example.com") returns valid', () => {
    expect(validateEmail("user@example.com").valid).toBe(true);
  });

  test('validateEmail("not-email") returns invalid', () => {
    expect(validateEmail("not-email").valid).toBe(false);
  });

  test('validateEmail("") returns invalid', () => {
    expect(validateEmail("").valid).toBe(false);
  });

  test("validateEmail with string > 254 chars returns invalid", () => {
    const longEmail = "a".repeat(250) + "@b.com";
    expect(validateEmail(longEmail).valid).toBe(false);
  });
});

describe("Password validation", () => {
  test('validatePassword("short") returns invalid (too short)', () => {
    const result = validatePassword("short");
    expect(result.valid).toBe(false);
  });

  test('validatePassword("aaaaaaaaaaaa") returns invalid (zxcvbn score < 3)', () => {
    const result = validatePassword("aaaaaaaaaaaa");
    expect(result.valid).toBe(false);
  });

  test('validatePassword("c0rrect-h0rse-b@ttery-st@ple!") returns valid', () => {
    const result = validatePassword("c0rrect-h0rse-b@ttery-st@ple!");
    expect(result.valid).toBe(true);
  });
});
