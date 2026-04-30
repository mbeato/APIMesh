// Hints engine — turns a structured VerifyResult into plain-English diagnostic
// strings. The hint is the wedge: "your timestamp is 47 hours stale" beats
// "signature_mismatch."
//
// Pure function. Inputs: VerifyResult + the original VerifyInput (we re-read
// the secret prefix and body shape to suggest causes).

import type { Provider, VerifyResult, VerifyInput } from "./sig-verify";

export type HintContext = {
  result: VerifyResult;
  input: VerifyInput;
};

export function generateHints(ctx: HintContext): string[] {
  const { result, input } = ctx;
  if (result.valid) return [];
  const hints: string[] = [];

  // Most-actionable first.
  hints.push(...secretFormatHints(input));
  hints.push(...timestampHints(result));
  hints.push(...bodyShapeHints(input));
  hints.push(...headerHints(result, input));
  hints.push(...schemeHints(result));
  hints.push(...sigPatternHints(result));

  // Always end with the universal "raw body" hint for signature_mismatch —
  // it's the #1 root cause across providers.
  if (result.reason === "signature_mismatch" && hints.length === 0) {
    hints.push(GENERIC_RAW_BODY_HINT(result.provider));
  }

  return hints;
}

// --- secret format checks ---

function secretFormatHints(input: VerifyInput): string[] {
  const out: string[] = [];
  const s = input.secret.trim();

  if (input.secret !== s) {
    out.push(
      "Your secret has leading or trailing whitespace. Trim it before passing to the verifier — most signing libraries do not trim for you.",
    );
  }

  if (s.length === 0) {
    out.push("The secret is empty. Make sure you're loading it from your environment correctly.");
    return out;
  }

  if (input.provider === "stripe") {
    if (s.startsWith("pk_live_") || s.startsWith("pk_test_")) {
      out.push(
        "Your secret starts with 'pk_' which is a Stripe publishable key, not a webhook signing secret. Webhook secrets start with 'whsec_'. Find it in your Stripe dashboard under Developers → Webhooks → click your endpoint → Signing secret.",
      );
    } else if (s.startsWith("sk_live_") || s.startsWith("sk_test_")) {
      out.push(
        "Your secret starts with 'sk_' which is a Stripe API secret key, not a webhook signing secret. Webhook secrets start with 'whsec_'.",
      );
    } else if (!s.startsWith("whsec_")) {
      out.push(
        "Stripe webhook signing secrets start with 'whsec_'. Yours doesn't — double-check you copied the signing secret (not an API key) from the dashboard.",
      );
    }
  }

  if (input.provider === "github" && s.length < 16) {
    out.push(
      "Your GitHub webhook secret is unusually short (under 16 chars). GitHub recommends a long random secret — short ones may indicate you're using something else.",
    );
  }

  if (input.provider === "shopify" && s.startsWith("shpss_")) {
    out.push(
      "Note: 'shpss_' prefixed values are Shopify shared secrets — these are valid for HMAC. If verification still fails, the issue is likely in the body (see other hints).",
    );
  }

  return out;
}

// --- timestamp checks ---

function timestampHints(result: VerifyResult): string[] {
  const out: string[] = [];
  const age = result.details.age_seconds;
  if (typeof age !== "number") return out;

  const absAge = Math.abs(age);
  if (result.reason === "timestamp_skew") {
    if (age > 0) {
      // Past timestamp.
      const human = humanDuration(absAge);
      out.push(
        `Your timestamp is ${human} in the past. This usually means: (1) you're testing with a recorded payload from earlier (Stripe CLI sessions, fixtures, replays — Stripe rejects events older than 5 minutes), or (2) your server's clock is significantly behind (check NTP).`,
      );
    } else {
      // Future timestamp.
      const human = humanDuration(absAge);
      out.push(
        `Your timestamp is ${human} in the future, which means your server's clock is ahead of the real time. Check NTP / system clock — large drift breaks signature verification across the board.`,
      );
    }
  } else if (absAge > 60 && result.reason === "signature_mismatch") {
    // Mismatch with a stale timestamp — could be either issue.
    out.push(
      `Side note: your timestamp is ${humanDuration(absAge)} ${age > 0 ? "old" : "in the future"}. If you fix the signature mismatch and still get errors, the timestamp will be the next problem.`,
    );
  }
  return out;
}

// --- body shape checks ---

function bodyShapeHints(input: VerifyInput): string[] {
  const out: string[] = [];
  const body = input.raw_body;

  if (body.length === 0) {
    out.push(
      "The body is empty. Make sure you're capturing the raw request body BEFORE any JSON or URL-encoded parser runs. Express's `body-parser` consumes the body — use the `verify` callback option to capture it first.",
    );
    return out;
  }

  // Pretty-printed JSON tell: 2-space indent and key+colon+space pattern.
  // Common sources: JSON.stringify(obj, null, 2), `jq` formatting, IDE
  // auto-format, copy from a pretty-printer extension.
  if (body.startsWith("{") && body.includes('": ')) {
    out.push(
      `Your body looks pretty-printed (key + colon + space, like '"id": "evt_..."'). Webhooks send compact JSON without that spacing. If you copied this from a logger that pretty-prints, from \`jq\`, from JSON.stringify(obj, null, 2), or from your IDE auto-format — those byte changes break the signature. Use the raw bytes the webhook sender actually transmitted.`,
    );
  }

  // Trailing newline is a common Express middleware artifact.
  if (body.endsWith("\n")) {
    out.push(
      "Your body ends with a newline character. Some HTTP frameworks add one when reading the body; the original webhook payload usually doesn't. Try verifying without the trailing newline.",
    );
  }

  // Non-ASCII characters could indicate encoding mismatch.
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7F]/.test(body) && body.length < 1000) {
    out.push(
      "Your body contains non-ASCII characters. Verify both sides are using UTF-8 — a UTF-16 or Latin-1 round-trip silently mangles bytes and breaks the hash.",
    );
  }

  return out;
}

// --- header checks ---

function headerHints(result: VerifyResult, input: VerifyInput): string[] {
  const out: string[] = [];
  if (result.reason === "header_missing") {
    out.push(`The expected ${expectedHeaderName(result.provider)} header is missing.`);
    const lc = Object.keys(input.headers).map((k) => k.toLowerCase());
    if (lc.some((k) => k.startsWith("x-forwarded") || k === "x-real-ip")) {
      out.push(
        "It looks like the request went through a proxy (X-Forwarded-* headers present). Some proxies strip vendor headers — check your proxy config (Cloudflare, Vercel Edge, Cloudfront) for a header allowlist.",
      );
    }
  }
  if (result.reason === "header_malformed") {
    out.push(
      `The signature header is present but doesn't match the expected format for ${result.provider}. Expected: ${expectedHeaderShape(result.provider)}. Got: ${result.details.raw_header ?? "(empty)"}.`,
    );
  }
  return out;
}

// --- scheme checks ---

function schemeHints(result: VerifyResult): string[] {
  const out: string[] = [];
  if (result.reason !== "unsupported_scheme") return out;
  if (result.provider === "github" && result.details.scheme === "sha1") {
    out.push(
      "You're sending the legacy X-Hub-Signature (SHA-1) header instead of X-Hub-Signature-256 (SHA-256). SHA-1 is cryptographically deprecated for webhook signatures — every modern webhook provider has moved to SHA-256. Switch your webhook listener to read X-Hub-Signature-256.",
    );
  }
  if (result.provider === "stripe" && result.details.scheme === "v0") {
    out.push(
      "You sent a 'v0' Stripe signature scheme. Stripe currently signs with v1 (SHA-256). v0 was an internal/debug scheme — make sure your webhook listener reads the 'v1' value out of the Stripe-Signature header.",
    );
  }
  return out;
}

// --- signature pattern checks ---

function sigPatternHints(result: VerifyResult): string[] {
  const out: string[] = [];
  if (result.reason !== "signature_mismatch") return out;

  const computed = result.details.computed_signature;
  const provided = result.details.provided_signature;
  if (!computed || !provided) return out;

  if (computed.length !== provided.length) {
    out.push(
      `The signatures are different lengths (computed=${computed.length}, provided=${provided.length}). This is a sure sign you're using the wrong hash algorithm or encoding — check whether you're hex-encoding when the provider uses base64 (or vice-versa).`,
    );
  } else if (result.details.first_diff_byte === 0) {
    out.push(
      "The signatures differ from the very first byte, which usually means the wrong secret entirely. Test secret on a live event? Live secret on a test event? Two different webhook endpoints in the dashboard with different secrets?",
    );
  } else if ((result.details.first_diff_byte ?? 0) > 4) {
    // First few bytes match — that's odd because HMAC outputs avalanche-distribute.
    out.push(
      "The first few bytes of computed and provided signatures match, then diverge. This is statistically unlikely from a true HMAC mismatch — double-check you're not accidentally trimming or transforming the signature header value before comparing.",
    );
  }

  return out;
}

// --- generic fallback ---

function GENERIC_RAW_BODY_HINT(provider: Provider): string {
  return `The most common cause for ${provider} signature mismatch is using the parsed/transformed body instead of the raw bytes received from the wire. If your framework parses JSON or URL-encoded data automatically, capture and store the raw body BEFORE that parser runs (Express: use express.raw() or the body-parser 'verify' option; Fastify: use the rawBody plugin; Hono: c.req.raw.text() or arrayBuffer; Bun.serve: req.text() before any json()).`;
}

// --- formatting helpers ---

function humanDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const mins = Math.floor(seconds / 60);
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 48) return `${hours}h ${mins % 60}m`;
  const days = Math.floor(hours / 24);
  return `${days} days`;
}

function expectedHeaderName(provider: Provider): string {
  switch (provider) {
    case "stripe": return "Stripe-Signature";
    case "github": return "X-Hub-Signature-256";
    case "slack": return "X-Slack-Signature (and X-Slack-Request-Timestamp)";
    case "shopify": return "X-Shopify-Hmac-SHA256";
  }
}

function expectedHeaderShape(provider: Provider): string {
  switch (provider) {
    case "stripe": return "t=<timestamp>,v1=<hex-sha256>";
    case "github": return "sha256=<hex-sha256>";
    case "slack": return "v0=<hex-sha256>";
    case "shopify": return "<base64-sha256>";
  }
}
