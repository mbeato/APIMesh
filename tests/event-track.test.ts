// /event endpoint tests. Same hermetic Hono+rate-limit pattern as the
// signup-notify suite. Cleaned up via afterAll using a unique source marker
// so test rows can't pollute the dev DB.

import { test, expect, describe, beforeAll, afterAll } from "bun:test";
import { Hono } from "hono";
import { rateLimit } from "../shared/rate-limit";
import { eventTrackHandler } from "../shared/event-track";
import db, { getEventCounts } from "../shared/db";

const RL_ZONE = "test-event-track-" + Date.now();
const TEST_SOURCE = `test-event-${Date.now()}`;
const ALLOWED = ["page_load", "demo_visible", "demo_started", "demo_success", "demo_error", "signup_focused"] as const;

beforeAll(() => {
  process.env.NODE_ENV = process.env.NODE_ENV ?? "development";
});

afterAll(() => {
  db.run(`DELETE FROM events WHERE source = ?`, [TEST_SOURCE]);
});

function buildApp(): Hono {
  const app = new Hono();
  app.use("/event", rateLimit(RL_ZONE, 30, 60_000));
  app.post("/event", eventTrackHandler({
    source: TEST_SOURCE,
    allowedEvents: ALLOWED,
    allowedOrigins: ["https://stripesig.apimesh.xyz"],
  }));
  return app;
}

function makeReq(body: unknown, ip: string, origin?: string): Request {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-real-ip": ip,
    "user-agent": "test/1.0",
  };
  if (origin) headers.origin = origin;
  return new Request("http://localhost/event", {
    method: "POST",
    headers,
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

describe("/event", () => {
  const app = buildApp();

  test("valid event accepted, persisted to events table", async () => {
    const res = await app.request(makeReq({ event: "page_load" }, "10.5.0.1"));
    expect(res.status).toBe(200);
    expect((await res.json()).ok).toBe(true);

    const rows = db
      .query(`SELECT event_type, user_agent FROM events WHERE source = ? ORDER BY id DESC LIMIT 1`)
      .get(TEST_SOURCE) as { event_type: string; user_agent: string } | null;
    expect(rows).not.toBeNull();
    expect(rows!.event_type).toBe("page_load");
    expect(rows!.user_agent).toBe("test/1.0");
  });

  test("unknown event rejected", async () => {
    const res = await app.request(makeReq({ event: "drop_table" }, "10.5.0.2"));
    expect(res.status).toBe(400);
  });

  test("missing event field rejected", async () => {
    const res = await app.request(makeReq({}, "10.5.0.3"));
    expect(res.status).toBe(400);
  });

  test("invalid JSON rejected", async () => {
    const res = await app.request(makeReq("not json{", "10.5.0.4"));
    expect(res.status).toBe(400);
  });

  test("oversized event name rejected", async () => {
    const res = await app.request(makeReq({ event: "x".repeat(100) }, "10.5.0.5"));
    expect(res.status).toBe(400);
  });

  test("cross-origin POST rejected when Origin doesn't match allowlist", async () => {
    const res = await app.request(
      makeReq({ event: "page_load" }, "10.5.0.6", "https://evil.example.invalid"),
    );
    expect(res.status).toBe(403);
  });

  test("rate-limit kicks in past 30/min/IP", async () => {
    const ip = "10.99.0.1";
    for (let i = 0; i < 30; i++) {
      const res = await app.request(makeReq({ event: "page_load" }, ip));
      expect(res.status).not.toBe(429);
    }
    const overflow = await app.request(makeReq({ event: "page_load" }, ip));
    expect(overflow.status).toBe(429);
  });

  test("getEventCounts groups by source + event_type", async () => {
    await app.request(makeReq({ event: "demo_started" }, "10.5.0.10"));
    await app.request(makeReq({ event: "demo_started" }, "10.5.0.11"));
    await app.request(makeReq({ event: "demo_success" }, "10.5.0.12"));

    const counts = getEventCounts(24);
    const ours = counts.filter((c) => c.source === TEST_SOURCE);
    const started = ours.find((c) => c.event_type === "demo_started");
    const success = ours.find((c) => c.event_type === "demo_success");
    expect((started?.count ?? 0) >= 2).toBe(true);
    expect((success?.count ?? 0) >= 1).toBe(true);
  });
});
