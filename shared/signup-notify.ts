import type { Handler } from "hono";
import { recordSignupNotification } from "./db";
import { normalizeEmail, validateEmail } from "./validation";

export interface SignupNotifyConfig {
  allowed: Array<{ source: string; interest: string }>;
  // Origins accepted for browser-issued POSTs. Same-origin / no-Origin
  // (curl, server-side callers) is always accepted. CORS alone doesn't stop
  // a cross-site POST from causing the side effect — only the response read.
  allowedOrigins: string[];
}

const MAX_INTEREST_LEN = 64;
const MAX_SOURCE_LEN = 64;

export function signupNotifyHandler(config: SignupNotifyConfig): Handler {
  const allowedSources = new Set(config.allowed.map(a => a.source));
  const allowedPairs = new Set(config.allowed.map(a => `${a.source}|${a.interest}`));
  const allowedOrigins = new Set(config.allowedOrigins);

  return async (c) => {
    const origin = c.req.header("origin");
    if (origin && !allowedOrigins.has(origin)) {
      return c.json({ error: "cross-origin request not allowed" }, 403);
    }

    let body: { email?: unknown; source?: unknown; interest?: unknown };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "invalid JSON body" }, 400);
    }

    if (typeof body.email !== "string") {
      return c.json({ error: "email (string) required" }, 400);
    }
    if (typeof body.source !== "string" || body.source.length > MAX_SOURCE_LEN) {
      return c.json({ error: "source (string) required" }, 400);
    }
    if (typeof body.interest !== "string" || body.interest.length > MAX_INTEREST_LEN) {
      return c.json({ error: "interest (string) required" }, 400);
    }

    if (!allowedSources.has(body.source)) {
      return c.json({ error: "unknown source" }, 400);
    }
    if (!allowedPairs.has(`${body.source}|${body.interest}`)) {
      return c.json({ error: "unknown interest for this source" }, 400);
    }

    const emailCheck = validateEmail(body.email);
    if (!emailCheck.valid) {
      return c.json({ error: emailCheck.error ?? "invalid email" }, 400);
    }
    const email = normalizeEmail(body.email);

    const ipRaw = c.req.header("x-real-ip");
    const ip = ipRaw && ipRaw.length <= 64 ? ipRaw : null;

    const result = recordSignupNotification(email, body.source, body.interest, ip);
    if (!result.ok) {
      return c.json({ error: "signup list temporarily unavailable" }, 503);
    }
    return c.json({ ok: true, deduped: result.deduped });
  };
}
