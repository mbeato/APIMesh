import { Hono } from "hono";
import { cors } from "hono/cors";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { rateLimit } from "../../shared/rate-limit";
import { apiLogger } from "../../shared/logger";
import { verify, type Provider, type VerifyInput } from "../../shared/sig-verify";
import { generateHints } from "../../shared/sig-hints";

const app = new Hono();
const API_NAME = "sigdebug";

const LANDING_HTML = readFileSync(resolve(import.meta.dir, "landing.html"), "utf8");

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET", "POST", "OPTIONS"],
  allowHeaders: ["Content-Type"],
}));

app.get("/health", (c) => c.json({ status: "ok" }));

// Subdomain canonicalization: sigdebug.apimesh.xyz → 301 → stripesig.apimesh.xyz
// (stripesig owns the higher-volume "stripe webhook signature" SEO term)
app.use("*", async (c, next) => {
  const host = c.req.header("host") ?? "";
  const hostname = host.split(":")[0]!;
  if (hostname === "sigdebug.apimesh.xyz") {
    const url = new URL(c.req.url);
    url.host = "stripesig.apimesh.xyz";
    return c.redirect(url.toString(), 301);
  }
  return next();
});

// Single rate-limit zone applies to /check + landing alike. The earlier
// double-registration (one wildcard, one /check-specific) summed to ~120/min
// effective on /check (SECURITY-AUDIT M1). One zone, one limit.
app.use("*", rateLimit("sigdebug", 60, 60_000));
app.use("*", apiLogger(API_NAME, 0));

app.get("/", (c) => c.html(LANDING_HTML));

const SUPPORTED_PROVIDERS: Provider[] = ["stripe", "github", "slack", "shopify"];
const MAX_BODY_CHARS = 100_000;
const MAX_SECRET_CHARS = 1_024;
const MAX_HEADER_CHARS = 4_096;

app.post("/check", async (c) => {
  let body: {
    provider?: string;
    secret?: string;
    raw_body?: string;
    headers?: Record<string, string>;
    tolerance_seconds?: number;
  };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "invalid JSON body" }, 400);
  }

  if (!body.provider || !SUPPORTED_PROVIDERS.includes(body.provider as Provider)) {
    return c.json({
      error: `provider must be one of: ${SUPPORTED_PROVIDERS.join(", ")}`,
    }, 400);
  }
  if (typeof body.secret !== "string") {
    return c.json({ error: "secret (string) required" }, 400);
  }
  if (typeof body.raw_body !== "string") {
    return c.json({ error: "raw_body (string) required" }, 400);
  }
  if (!body.headers || typeof body.headers !== "object") {
    return c.json({ error: "headers (object) required" }, 400);
  }

  // Size caps to prevent resource abuse.
  if (body.raw_body.length > MAX_BODY_CHARS) {
    return c.json({ error: `raw_body exceeds ${MAX_BODY_CHARS} chars` }, 413);
  }
  if (body.secret.length > MAX_SECRET_CHARS) {
    return c.json({ error: `secret exceeds ${MAX_SECRET_CHARS} chars` }, 413);
  }
  for (const [k, v] of Object.entries(body.headers)) {
    if (typeof v !== "string") {
      return c.json({ error: `header ${k} must be a string` }, 400);
    }
    if (v.length > MAX_HEADER_CHARS) {
      return c.json({ error: `header ${k} exceeds ${MAX_HEADER_CHARS} chars` }, 413);
    }
  }

  const input: VerifyInput = {
    provider: body.provider as Provider,
    secret: body.secret,
    raw_body: body.raw_body,
    headers: body.headers as Record<string, string>,
    tolerance_seconds: body.tolerance_seconds,
  };

  const result = verify(input);
  const hints = generateHints({ result, input });

  // Redact full HMAC bytes on failure paths to avoid leaking
  // HMAC(user_secret, user_body) as an oracle (SECURITY-AUDIT FINDING-01).
  // The first 8 hex chars + first_diff_byte preserve the user-facing diff UX
  // while removing usable cryptographic material.
  const details = result.valid
    ? result.details
    : {
        ...result.details,
        computed_signature: redact(result.details.computed_signature),
        provided_signature: redact(result.details.provided_signature),
      };

  return c.json({
    valid: result.valid,
    provider: result.provider,
    reason: result.reason,
    hints,
    details,
  });
});

function redact(sig: string | undefined): string | undefined {
  if (!sig) return sig;
  if (sig.length <= 12) return sig;
  return sig.slice(0, 8) + "…(redacted)";
}

export { app };
