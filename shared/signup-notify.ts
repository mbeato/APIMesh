import type { Handler } from "hono";
import { recordSignupNotification, SignupTableFullError } from "./db";
import { normalizeEmail, validateEmail } from "./validation";

export interface SignupNotifyConfig {
  // Allowed (source, interest) combinations the endpoint will accept.
  // The handler is mounted per-wedge, so each wedge restricts to its own
  // legitimate combinations rather than letting any caller pick anything.
  allowed: Array<{ source: string; interest: string }>;
  // Origins the endpoint will accept browser-issued POSTs from. Same-origin
  // (no Origin header) is always accepted — server-side callers / curl /
  // older browsers don't send it. (SECURITY-AUDIT M1.)
  allowedOrigins: string[];
}

const MAX_INTEREST_LEN = 64;
const MAX_SOURCE_LEN = 64;
const MAX_EMAIL_LEN = 254;

export function signupNotifyHandler(config: SignupNotifyConfig): Handler {
  const allowedSources = new Set(config.allowed.map(a => a.source));
  const allowedPairs = new Set(config.allowed.map(a => `${a.source}|${a.interest}`));
  const allowedOrigins = new Set(config.allowedOrigins);

  return async (c) => {
    // Origin pinning: a third-party page must not be able to subscribe a
    // victim's email by issuing a cross-site POST. CORS alone doesn't
    // prevent the side effect — only the response read.
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

    if (typeof body.email !== "string" || body.email.length > MAX_EMAIL_LEN) {
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

    try {
      const inserted = recordSignupNotification(email, body.source, body.interest, ip);
      return c.json({ ok: true, deduped: !inserted });
    } catch (e) {
      if (e instanceof SignupTableFullError) {
        return c.json({ error: "signup list temporarily unavailable" }, 503);
      }
      throw e;
    }
  };
}
