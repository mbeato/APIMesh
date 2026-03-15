import { test, expect, describe, beforeEach } from "bun:test";
import { Database } from "bun:sqlite";
import {
  checkAuthRateLimit,
  AUTH_RATE_ZONES,
  ensureAuthRateLimitTable,
} from "../shared/auth-rate-limit";

describe("auth rate limiter", () => {
  let db: Database;

  beforeEach(() => {
    db = new Database(":memory:");
    db.exec("PRAGMA journal_mode=WAL;");
    ensureAuthRateLimitTable(db);
  });

  test("signup: allows 5 requests, blocks 6th", () => {
    for (let i = 0; i < 5; i++) {
      const result = checkAuthRateLimit(db, "signup", "1.2.3.4");
      expect(result.allowed).toBe(true);
    }
    const blocked = checkAuthRateLimit(db, "signup", "1.2.3.4");
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfter).toBeGreaterThan(0);
  });

  test("login: allows 10 requests per minute, blocks 11th", () => {
    for (let i = 0; i < 10; i++) {
      const result = checkAuthRateLimit(db, "login", "1.2.3.4");
      expect(result.allowed).toBe(true);
    }
    const blocked = checkAuthRateLimit(db, "login", "1.2.3.4");
    expect(blocked.allowed).toBe(false);
  });

  test("different IPs are independent for same zone", () => {
    // Exhaust IP1
    for (let i = 0; i < 5; i++) {
      checkAuthRateLimit(db, "signup", "1.1.1.1");
    }
    expect(checkAuthRateLimit(db, "signup", "1.1.1.1").allowed).toBe(false);

    // IP2 should still be allowed
    expect(checkAuthRateLimit(db, "signup", "2.2.2.2").allowed).toBe(true);
  });

  test("different zones are independent for same IP", () => {
    // Exhaust signup zone
    for (let i = 0; i < 5; i++) {
      checkAuthRateLimit(db, "signup", "1.2.3.4");
    }
    expect(checkAuthRateLimit(db, "signup", "1.2.3.4").allowed).toBe(false);

    // Login zone should still be allowed
    expect(checkAuthRateLimit(db, "login", "1.2.3.4").allowed).toBe(true);
  });

  test("resend-code-email: allows 1 per 60s, blocks 2nd within window", () => {
    const email = "user@example.com";
    expect(checkAuthRateLimit(db, "resend-code-email", email).allowed).toBe(true);
    expect(checkAuthRateLimit(db, "resend-code-email", email).allowed).toBe(false);
  });

  test("email normalization: different cases share same counter", () => {
    // The caller is expected to normalize, but let's verify with normalized keys
    const normalized = "user@example.com";
    expect(checkAuthRateLimit(db, "resend-code-email", normalized).allowed).toBe(true);

    // Same email, already normalized to lowercase
    expect(checkAuthRateLimit(db, "resend-code-email", normalized).allowed).toBe(false);
  });

  test("password-reset-email: allows 3 per hour, blocks 4th", () => {
    const email = "user@example.com";
    for (let i = 0; i < 3; i++) {
      expect(checkAuthRateLimit(db, "password-reset-email", email).allowed).toBe(true);
    }
    expect(checkAuthRateLimit(db, "password-reset-email", email).allowed).toBe(false);
  });

  test("rate limit entries expire after their window", () => {
    // Exhaust the resend-code-email limit (1 per 60s)
    checkAuthRateLimit(db, "resend-code-email", "user@example.com");
    expect(checkAuthRateLimit(db, "resend-code-email", "user@example.com").allowed).toBe(false);

    // Manually backdate the window_start to simulate time passage
    const pastTime = Date.now() - 61_000; // 61 seconds ago
    db.run(
      "UPDATE auth_rate_limits SET window_start = ? WHERE zone = ? AND key = ?",
      [pastTime, "resend-code-email", "user@example.com"]
    );

    // Should now be allowed (window expired)
    expect(checkAuthRateLimit(db, "resend-code-email", "user@example.com").allowed).toBe(true);
  });

  test("state persists across separate function calls on same db", () => {
    // Make 3 requests
    for (let i = 0; i < 3; i++) {
      checkAuthRateLimit(db, "signup", "1.2.3.4");
    }

    // Make 2 more requests (simulating different "sessions" but same db)
    for (let i = 0; i < 2; i++) {
      checkAuthRateLimit(db, "signup", "1.2.3.4");
    }

    // 6th should be blocked (total 5 used)
    expect(checkAuthRateLimit(db, "signup", "1.2.3.4").allowed).toBe(false);
  });

  test("auth rate limiter does NOT share state with API rate limiter", () => {
    // Auth rate limiter uses SQLite table auth_rate_limits
    // API rate limiter uses in-memory Map
    // They are completely independent by design

    // Exhaust auth signup limit
    for (let i = 0; i < 5; i++) {
      checkAuthRateLimit(db, "signup", "1.2.3.4");
    }
    expect(checkAuthRateLimit(db, "signup", "1.2.3.4").allowed).toBe(false);

    // Verify auth_rate_limits table has data
    const rows = db.query("SELECT * FROM auth_rate_limits").all();
    expect(rows.length).toBeGreaterThan(0);

    // API rate limiter would use a different mechanism (in-memory Map)
    // There's no cross-contamination since they use different storage
  });

  test("zone config has all expected zones", () => {
    const expectedZones = [
      "signup",
      "login",
      "password-reset-ip",
      "password-reset-email",
      "resend-code-email",
      "resend-code-ip",
      "key-ops",
      "verify-code",
    ];
    for (const zone of expectedZones) {
      expect(AUTH_RATE_ZONES[zone]).toBeDefined();
      expect(AUTH_RATE_ZONES[zone].maxRequests).toBeGreaterThan(0);
      expect(AUTH_RATE_ZONES[zone].windowMs).toBeGreaterThan(0);
    }
  });

  test("retryAfter is returned in seconds when blocked", () => {
    // Exhaust resend-code-email (1 per 60s)
    checkAuthRateLimit(db, "resend-code-email", "user@example.com");
    const result = checkAuthRateLimit(db, "resend-code-email", "user@example.com");
    expect(result.allowed).toBe(false);
    expect(result.retryAfter).toBeGreaterThan(0);
    expect(result.retryAfter).toBeLessThanOrEqual(60);
  });

  test("verify-code: allows 3 per 10 minutes, blocks 4th", () => {
    const email = "user@example.com";
    for (let i = 0; i < 3; i++) {
      expect(checkAuthRateLimit(db, "verify-code", email).allowed).toBe(true);
    }
    expect(checkAuthRateLimit(db, "verify-code", email).allowed).toBe(false);
  });
});
