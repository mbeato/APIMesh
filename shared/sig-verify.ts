// Webhook signature verification + diagnostic engine.
// Multi-provider: Stripe, GitHub, Slack, Shopify (all HMAC-SHA256).
//
// Goal: when verification fails, surface WHY in plain English — not just a
// boolean. Each verifier returns a structured VerifyResult that downstream
// hints engine consumes.
//
// Crypto: HMAC-SHA256 via Node's built-in `node:crypto` (timing-safe compare
// via `timingSafeEqual`). No third-party deps.

import { createHmac, timingSafeEqual } from "node:crypto";

export type Provider = "stripe" | "github" | "slack" | "shopify";

export type FailureReason =
  | "signature_mismatch"
  | "timestamp_skew"
  | "header_missing"
  | "header_malformed"
  | "body_empty"
  | "secret_format_invalid"
  | "unsupported_scheme";

export type VerifyResult = {
  valid: boolean;
  provider: Provider;
  reason?: FailureReason;
  details: {
    computed_signature?: string;
    provided_signature?: string;
    /** Index of first byte mismatch in hex/base64 representation. */
    first_diff_byte?: number;
    /** Unix seconds, when the provider includes a timestamp. */
    timestamp?: number;
    /** Difference between timestamp and now, in seconds. Positive = past. */
    age_seconds?: number;
    /** Hash algorithm name. */
    hash_algo: "sha256" | "sha1";
    /** Encoding of the signature: hex or base64. */
    encoding: "hex" | "base64";
    /** Provider-specific scheme tag (e.g. Stripe's "v1", Slack's "v0"). */
    scheme?: string;
    /** Echo of the raw signature header for diagnostics. */
    raw_header?: string;
  };
};

export type VerifyInput = {
  provider: Provider;
  secret: string;
  raw_body: string;
  /** Case-insensitive header bag. Keys lowercased. */
  headers: Record<string, string>;
  /** Optional override for "now" — for testing. Defaults to Date.now(). */
  now_seconds?: number;
  /** Tolerance for timestamp skew (seconds). Default 300 (5 minutes). */
  tolerance_seconds?: number;
};

const DEFAULT_TOLERANCE = 300;

export function verify(input: VerifyInput): VerifyResult {
  const headers = lowerKeys(input.headers);
  switch (input.provider) {
    case "stripe":
      return verifyStripe(input, headers);
    case "github":
      return verifyGithub(input, headers);
    case "slack":
      return verifySlack(input, headers);
    case "shopify":
      return verifyShopify(input, headers);
  }
}

// --- Stripe ---
// Stripe-Signature: t=<unix-ts>,v1=<hex-sig>[,v0=<hex-sig>]
// Computed: HMAC-SHA256(`${t}.${body}`)
function verifyStripe(input: VerifyInput, headers: Record<string, string>): VerifyResult {
  const raw = headers["stripe-signature"];
  if (!raw) {
    return failure("stripe", "header_missing", { hash_algo: "sha256", encoding: "hex" });
  }
  const parts = parseStripeHeader(raw);
  if (!parts.t || (!parts.v1 && !parts.v0)) {
    return failure("stripe", "header_malformed", {
      hash_algo: "sha256",
      encoding: "hex",
      raw_header: raw,
    });
  }
  if (input.raw_body.length === 0) {
    return failure("stripe", "body_empty", {
      hash_algo: "sha256",
      encoding: "hex",
      timestamp: parseInt(parts.t, 10),
      raw_header: raw,
    });
  }

  // Stripe currently only signs with v1 (sha256). v0 was a deprecated debug
  // scheme. We only attempt v1.
  if (!parts.v1) {
    return failure("stripe", "unsupported_scheme", {
      hash_algo: "sha256",
      encoding: "hex",
      timestamp: parseInt(parts.t, 10),
      scheme: "v0",
      raw_header: raw,
    });
  }

  const t = parseInt(parts.t, 10);
  const now = input.now_seconds ?? Math.floor(Date.now() / 1000);
  const tolerance = input.tolerance_seconds ?? DEFAULT_TOLERANCE;
  const age = now - t;

  const computed = createHmac("sha256", input.secret)
    .update(`${parts.t}.${input.raw_body}`)
    .digest("hex");

  const matches = constantTimeEqualHex(computed, parts.v1);

  if (!matches) {
    return failure("stripe", "signature_mismatch", {
      computed_signature: computed,
      provided_signature: parts.v1,
      first_diff_byte: firstDiffByte(computed, parts.v1),
      timestamp: t,
      age_seconds: age,
      hash_algo: "sha256",
      encoding: "hex",
      scheme: "v1",
      raw_header: raw,
    });
  }

  if (Math.abs(age) > tolerance) {
    return failure("stripe", "timestamp_skew", {
      computed_signature: computed,
      provided_signature: parts.v1,
      timestamp: t,
      age_seconds: age,
      hash_algo: "sha256",
      encoding: "hex",
      scheme: "v1",
      raw_header: raw,
    });
  }

  return success("stripe", {
    computed_signature: computed,
    provided_signature: parts.v1,
    timestamp: t,
    age_seconds: age,
    hash_algo: "sha256",
    encoding: "hex",
    scheme: "v1",
    raw_header: raw,
  });
}

function parseStripeHeader(raw: string): { t?: string; v1?: string; v0?: string } {
  const out: { t?: string; v1?: string; v0?: string } = {};
  for (const pair of raw.split(",")) {
    const idx = pair.indexOf("=");
    if (idx < 0) continue;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k === "t" || k === "v0" || k === "v1") out[k] = v;
  }
  return out;
}

// --- GitHub ---
// X-Hub-Signature-256: sha256=<hex>
// Computed: HMAC-SHA256(body)
// (Legacy X-Hub-Signature: sha1=... still emitted but considered insecure.)
function verifyGithub(input: VerifyInput, headers: Record<string, string>): VerifyResult {
  const raw = headers["x-hub-signature-256"];
  const legacy = headers["x-hub-signature"];

  if (!raw && !legacy) {
    return failure("github", "header_missing", { hash_algo: "sha256", encoding: "hex" });
  }
  if (!raw && legacy) {
    return failure("github", "unsupported_scheme", {
      hash_algo: "sha1",
      encoding: "hex",
      raw_header: legacy,
      scheme: "sha1",
    });
  }
  // Header format: "sha256=<hex>"
  const m = raw!.match(/^sha256=([a-fA-F0-9]+)$/);
  if (!m) {
    return failure("github", "header_malformed", {
      hash_algo: "sha256",
      encoding: "hex",
      raw_header: raw!,
    });
  }
  const provided = m[1]!;

  if (input.raw_body.length === 0) {
    return failure("github", "body_empty", {
      hash_algo: "sha256",
      encoding: "hex",
      raw_header: raw!,
    });
  }

  const computed = createHmac("sha256", input.secret)
    .update(input.raw_body)
    .digest("hex");

  if (!constantTimeEqualHex(computed, provided)) {
    return failure("github", "signature_mismatch", {
      computed_signature: computed,
      provided_signature: provided,
      first_diff_byte: firstDiffByte(computed, provided),
      hash_algo: "sha256",
      encoding: "hex",
      scheme: "sha256",
      raw_header: raw!,
    });
  }

  return success("github", {
    computed_signature: computed,
    provided_signature: provided,
    hash_algo: "sha256",
    encoding: "hex",
    scheme: "sha256",
    raw_header: raw!,
  });
}

// --- Slack ---
// X-Slack-Signature: v0=<hex>
// X-Slack-Request-Timestamp: <unix-ts>
// Computed: HMAC-SHA256(`v0:${ts}:${body}`)
function verifySlack(input: VerifyInput, headers: Record<string, string>): VerifyResult {
  const sig = headers["x-slack-signature"];
  const tsRaw = headers["x-slack-request-timestamp"];

  if (!sig || !tsRaw) {
    return failure("slack", "header_missing", { hash_algo: "sha256", encoding: "hex" });
  }
  const m = sig.match(/^v0=([a-fA-F0-9]+)$/);
  if (!m) {
    return failure("slack", "header_malformed", {
      hash_algo: "sha256",
      encoding: "hex",
      raw_header: sig,
    });
  }
  const provided = m[1]!;
  const t = parseInt(tsRaw, 10);
  if (!Number.isFinite(t)) {
    return failure("slack", "header_malformed", {
      hash_algo: "sha256",
      encoding: "hex",
      raw_header: tsRaw,
    });
  }

  const now = input.now_seconds ?? Math.floor(Date.now() / 1000);
  const tolerance = input.tolerance_seconds ?? DEFAULT_TOLERANCE;
  const age = now - t;

  const computed = createHmac("sha256", input.secret)
    .update(`v0:${t}:${input.raw_body}`)
    .digest("hex");

  const matches = constantTimeEqualHex(computed, provided);

  if (!matches) {
    return failure("slack", "signature_mismatch", {
      computed_signature: computed,
      provided_signature: provided,
      first_diff_byte: firstDiffByte(computed, provided),
      timestamp: t,
      age_seconds: age,
      hash_algo: "sha256",
      encoding: "hex",
      scheme: "v0",
      raw_header: sig,
    });
  }

  if (Math.abs(age) > tolerance) {
    return failure("slack", "timestamp_skew", {
      computed_signature: computed,
      provided_signature: provided,
      timestamp: t,
      age_seconds: age,
      hash_algo: "sha256",
      encoding: "hex",
      scheme: "v0",
      raw_header: sig,
    });
  }

  return success("slack", {
    computed_signature: computed,
    provided_signature: provided,
    timestamp: t,
    age_seconds: age,
    hash_algo: "sha256",
    encoding: "hex",
    scheme: "v0",
    raw_header: sig,
  });
}

// --- Shopify ---
// X-Shopify-Hmac-Sha256: <base64>
// Computed: HMAC-SHA256(body) → base64
function verifyShopify(input: VerifyInput, headers: Record<string, string>): VerifyResult {
  const provided = headers["x-shopify-hmac-sha256"];
  if (!provided) {
    return failure("shopify", "header_missing", { hash_algo: "sha256", encoding: "base64" });
  }
  if (input.raw_body.length === 0) {
    return failure("shopify", "body_empty", {
      hash_algo: "sha256",
      encoding: "base64",
      raw_header: provided,
    });
  }

  const computed = createHmac("sha256", input.secret)
    .update(input.raw_body)
    .digest("base64");

  if (!constantTimeEqualString(computed, provided)) {
    return failure("shopify", "signature_mismatch", {
      computed_signature: computed,
      provided_signature: provided,
      first_diff_byte: firstDiffByte(computed, provided),
      hash_algo: "sha256",
      encoding: "base64",
      raw_header: provided,
    });
  }

  return success("shopify", {
    computed_signature: computed,
    provided_signature: provided,
    hash_algo: "sha256",
    encoding: "base64",
    raw_header: provided,
  });
}

// --- helpers ---

function lowerKeys(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = v;
  return out;
}

function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  } catch {
    return false;
  }
}

function constantTimeEqualString(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function firstDiffByte(a: string, b: string): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return i;
  }
  return len;
}

function failure(provider: Provider, reason: FailureReason, details: VerifyResult["details"]): VerifyResult {
  return { valid: false, provider, reason, details };
}

function success(provider: Provider, details: VerifyResult["details"]): VerifyResult {
  return { valid: true, provider, details };
}
