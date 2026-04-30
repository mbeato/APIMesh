// /signup-notify endpoint tests for the agentcontext wedge.
// Mirrors tests/sigdebug/signup-notify.test.ts but with source=agentcontext +
// interest=github-app. Uses a hermetic test Hono app to avoid pulling in
// the wedge's full import graph (@mbeato/agentcontext parsers).

import { test, expect, describe, beforeAll, afterAll } from "bun:test";
import { Hono } from "hono";
import { rateLimit } from "../../shared/rate-limit";
import { signupNotifyHandler } from "../../shared/signup-notify";
import db, { getRecentSignupNotifications } from "../../shared/db";

const RL_ZONE = "test-agentcontext-signup-" + Date.now();
// Marker domain so afterAll cleanup never touches a real signup. (CODE-REVIEW B1.)
const TEST_DOMAIN = "@example.invalid";

beforeAll(() => {
  process.env.NODE_ENV = process.env.NODE_ENV ?? "development";
});

afterAll(() => {
  db.run(
    `DELETE FROM signup_notifications WHERE source = 'agentcontext' AND email LIKE ?`,
    [`%${TEST_DOMAIN}`],
  );
});

function buildApp(): Hono {
  const app = new Hono();
  app.use("/signup-notify", rateLimit(RL_ZONE, 5, 60_000));
  app.post("/signup-notify", signupNotifyHandler({
    allowed: [{ source: "agentcontext", interest: "github-app" }],
    allowedOrigins: ["https://agentsmd.apimesh.xyz"],
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
  return `agentcontext-${Date.now()}-${Math.random().toString(36).slice(2, 8)}${TEST_DOMAIN}`;
}

describe("agentcontext /signup-notify", () => {
  const app = buildApp();

  test("valid email accepted, persisted with normalized casing", async () => {
    const rawEmail = `  TestUser+ac@Example.INVALID  `;
    const expected = "testuser+ac@example.invalid";
    const res = await app.request(
      makeReq({ email: rawEmail, source: "agentcontext", interest: "github-app" }, "10.1.0.1"),
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);

    const row = db
      .query(
        `SELECT email FROM signup_notifications
         WHERE email = ? AND source = 'agentcontext'`,
      )
      .get(expected) as { email: string } | null;
    expect(row).not.toBeNull();
  });

  test("malformed email rejected", async () => {
    const res = await app.request(
      makeReq({ email: "not-an-email", source: "agentcontext", interest: "github-app" }, "10.1.0.2"),
    );
    expect(res.status).toBe(400);
  });

  test("email without TLD rejected", async () => {
    const res = await app.request(
      makeReq({ email: "user@host", source: "agentcontext", interest: "github-app" }, "10.1.0.3"),
    );
    expect(res.status).toBe(400);
  });

  test("oversized email (>254 chars) rejected", async () => {
    const huge = "a".repeat(250) + "@x.co";
    const res = await app.request(
      makeReq({ email: huge, source: "agentcontext", interest: "github-app" }, "10.1.0.4"),
    );
    expect(res.status).toBe(400);
  });

  test("dedupe by (email, source) — second insert is no-op", async () => {
    const email = uniqueEmail();
    const ip = "10.1.0.5";
    const r1 = await app.request(
      makeReq({ email, source: "agentcontext", interest: "github-app" }, ip),
    );
    expect(r1.status).toBe(200);
    const b1 = await r1.json();
    expect(b1.deduped).toBe(false);

    const r2 = await app.request(
      makeReq({ email, source: "agentcontext", interest: "github-app" }, ip),
    );
    expect(r2.status).toBe(200);
    expect((await r2.json()).deduped).toBe(true);
  });

  test("rate-limit kicks in after 5 requests/min/IP", async () => {
    const ip = "10.88.88.88";
    for (let i = 0; i < 5; i++) {
      const res = await app.request(
        makeReq({ email: uniqueEmail(), source: "agentcontext", interest: "github-app" }, ip),
      );
      expect(res.status).not.toBe(429);
    }
    const sixth = await app.request(
      makeReq({ email: uniqueEmail(), source: "agentcontext", interest: "github-app" }, ip),
    );
    expect(sixth.status).toBe(429);
  });

  test("cross-origin POST rejected with 403", async () => {
    const req = new Request("http://localhost/signup-notify", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-real-ip": "10.1.0.99",
        "origin": "https://attacker.example.invalid",
      },
      body: JSON.stringify({
        email: uniqueEmail(), source: "agentcontext", interest: "github-app",
      }),
    });
    const res = await app.request(req);
    expect(res.status).toBe(403);
  });

  test("getRecentSignupNotifications filtered by source returns only agentcontext rows", async () => {
    const recent = getRecentSignupNotifications("agentcontext", 5);
    for (const row of recent) {
      expect(row.source).toBe("agentcontext");
    }
  });
});
