// /signup-notify endpoint tests for the sigdebug wedge.
// Covers: valid email accepted, malformed rejected, dedup via INSERT OR IGNORE,
// and rate-limit kicks in at the 6th request from a single IP within a minute.
//
// Tests run against a hermetic Hono app that mounts only the signup-notify
// handler + its rate-limiter, so we don't pull in the rest of the wedge's
// dependency graph (sig-verify, hints, etc).

import { test, expect, describe, beforeAll, afterAll } from "bun:test";
import { Hono } from "hono";
import { rateLimit } from "../../shared/rate-limit";
import { signupNotifyHandler } from "../../shared/signup-notify";
import db, { getRecentSignupNotifications } from "../../shared/db";

// Use a fresh rate-limit zone per test file so the bucket can't be polluted
// by a sibling test file already in the same Bun test process.
const RL_ZONE = "test-sigdebug-signup-" + Date.now();

// Marker domain that real signups will never use. Used to scope afterAll
// cleanup so we don't pollute the dev DB with test rows. (CODE-REVIEW B1.)
const TEST_DOMAIN = "@example.invalid";

beforeAll(() => {
  // Set NODE_ENV=development so rate-limit accepts missing x-real-ip
  // (it falls back to 127.0.0.1). We always pass x-real-ip explicitly,
  // but this guards against test runners that strip env.
  process.env.NODE_ENV = process.env.NODE_ENV ?? "development";
});

afterAll(() => {
  db.run(
    `DELETE FROM signup_notifications WHERE source = 'sigdebug' AND email LIKE ?`,
    [`%${TEST_DOMAIN}`],
  );
});

function buildApp(): Hono {
  const app = new Hono();
  app.use("/signup-notify", rateLimit(RL_ZONE, 5, 60_000));
  app.post("/signup-notify", signupNotifyHandler({
    allowed: [{ source: "sigdebug", interest: "paid-tier" }],
    allowedOrigins: ["https://stripesig.apimesh.xyz"],
  }));
  return app;
}

function makeReq(body: unknown, ip: string): Request {
  return new Request("http://localhost/signup-notify", {
    method: "POST",
    headers: { "content-type": "application/json", "x-real-ip": ip },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function uniqueEmail(): string {
  return `sigdebug-${Date.now()}-${Math.random().toString(36).slice(2, 8)}${TEST_DOMAIN}`;
}

describe("sigdebug /signup-notify", () => {
  const app = buildApp();

  test("valid email accepted, persisted to signup_notifications", async () => {
    const email = uniqueEmail();
    const res = await app.request(
      makeReq({ email, source: "sigdebug", interest: "paid-tier" }, "10.0.0.1"),
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.deduped).toBe(false);

    const row = db
      .query(
        `SELECT email, source, interest FROM signup_notifications
         WHERE email = ? AND source = 'sigdebug'`,
      )
      .get(email) as { email: string; source: string; interest: string } | null;
    expect(row).not.toBeNull();
    expect(row!.source).toBe("sigdebug");
    expect(row!.interest).toBe("paid-tier");
  });

  test("malformed email rejected with 400", async () => {
    const res = await app.request(
      makeReq({ email: "not-an-email", source: "sigdebug", interest: "paid-tier" }, "10.0.0.2"),
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBeTruthy();
  });

  test("missing email rejected with 400", async () => {
    const res = await app.request(
      makeReq({ source: "sigdebug", interest: "paid-tier" }, "10.0.0.3"),
    );
    expect(res.status).toBe(400);
  });

  test("invalid JSON body rejected with 400", async () => {
    const res = await app.request(
      makeReq("not json{", "10.0.0.4"),
    );
    expect(res.status).toBe(400);
  });

  test("unknown source rejected", async () => {
    const res = await app.request(
      makeReq({ email: uniqueEmail(), source: "evil", interest: "paid-tier" }, "10.0.0.5"),
    );
    expect(res.status).toBe(400);
  });

  test("unknown interest rejected for valid source", async () => {
    const res = await app.request(
      makeReq({ email: uniqueEmail(), source: "sigdebug", interest: "free-tier-bypass" }, "10.0.0.6"),
    );
    expect(res.status).toBe(400);
  });

  test("dedupe: second submission with same email returns deduped=true", async () => {
    const email = uniqueEmail();
    const ip = "10.0.0.7";
    const r1 = await app.request(
      makeReq({ email, source: "sigdebug", interest: "paid-tier" }, ip),
    );
    expect(r1.status).toBe(200);
    expect((await r1.json()).deduped).toBe(false);

    const r2 = await app.request(
      makeReq({ email, source: "sigdebug", interest: "paid-tier" }, ip),
    );
    expect(r2.status).toBe(200);
    expect((await r2.json()).deduped).toBe(true);

    const rows = db
      .query(
        `SELECT COUNT(*) AS cnt FROM signup_notifications WHERE email = ? AND source = 'sigdebug'`,
      )
      .get(email) as { cnt: number };
    expect(rows.cnt).toBe(1);
  });

  test("rate-limit kicks in after 5 requests/min from single IP", async () => {
    // Use a dedicated IP so the 5-request budget isn't shared with other tests.
    const ip = "10.99.99.99";
    // First 5 should succeed (200 or 400 — what matters is that they're not 429).
    for (let i = 0; i < 5; i++) {
      const res = await app.request(
        makeReq({ email: uniqueEmail(), source: "sigdebug", interest: "paid-tier" }, ip),
      );
      expect(res.status).not.toBe(429);
    }
    // 6th must be rate-limited.
    const sixth = await app.request(
      makeReq({ email: uniqueEmail(), source: "sigdebug", interest: "paid-tier" }, ip),
    );
    expect(sixth.status).toBe(429);
  });

  test("cross-origin POST blocked when Origin doesn't match allowlist", async () => {
    const req = new Request("http://localhost/signup-notify", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-real-ip": "10.0.0.42",
        "origin": "https://evil.example.invalid",
      },
      body: JSON.stringify({ email: uniqueEmail(), source: "sigdebug", interest: "paid-tier" }),
    });
    const res = await app.request(req);
    expect(res.status).toBe(403);
  });

  test("cross-origin POST allowed when Origin matches allowlist", async () => {
    const req = new Request("http://localhost/signup-notify", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-real-ip": "10.0.0.43",
        "origin": "https://stripesig.apimesh.xyz",
      },
      body: JSON.stringify({ email: uniqueEmail(), source: "sigdebug", interest: "paid-tier" }),
    });
    const res = await app.request(req);
    expect(res.status).toBe(200);
  });

  test("getRecentSignupNotifications filters by source", async () => {
    const recent = getRecentSignupNotifications("sigdebug", 5);
    expect(Array.isArray(recent)).toBe(true);
    for (const row of recent) {
      expect(row.source).toBe("sigdebug");
    }
  });
});
