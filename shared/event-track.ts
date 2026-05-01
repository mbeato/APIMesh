import type { Handler } from "hono";
import { recordEvent } from "./db";

export interface EventTrackConfig {
  source: string;
  // Allowlist of event_type strings the endpoint will accept. Anything else
  // is rejected — keeps untrusted clients from filling the table with junk.
  allowedEvents: readonly string[];
  // Origins accepted for browser-issued POSTs. Same-origin / no-Origin
  // (curl, server-side) is always accepted.
  allowedOrigins: readonly string[];
}

const MAX_EVENT_LEN = 64;

export function eventTrackHandler(config: EventTrackConfig): Handler {
  const allowed = new Set(config.allowedEvents);
  const allowedOrigins = new Set(config.allowedOrigins);

  return async (c) => {
    const origin = c.req.header("origin");
    if (origin && !allowedOrigins.has(origin)) {
      return c.json({ error: "cross-origin request not allowed" }, 403);
    }

    let body: { event?: unknown };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "invalid JSON body" }, 400);
    }

    if (typeof body.event !== "string" || body.event.length > MAX_EVENT_LEN) {
      return c.json({ error: "event (string) required" }, 400);
    }
    if (!allowed.has(body.event)) {
      return c.json({ error: "unknown event" }, 400);
    }

    const ipRaw = c.req.header("x-real-ip");
    const ip = ipRaw && ipRaw.length <= 64 ? ipRaw : null;
    const uaRaw = c.req.header("user-agent");
    const ua = uaRaw ? uaRaw.slice(0, 256) : null;

    recordEvent(config.source, body.event, ip, ua);
    return c.json({ ok: true });
  };
}
