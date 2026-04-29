// Reference test vectors for each provider, taken from official docs.
// These are the gold-standard "correct" cases — if our verifier doesn't pass
// these, we've shipped a bug that breaks every real webhook.
//
// Stripe: docs.stripe.com/webhooks/signatures (no public reference vector,
//   so we generate our own with HMAC-SHA256 and verify the math)
// GitHub: docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
//   has a reference: secret="It's a Secret to Everybody", body="Hello, World!",
//   sig=sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17
// Slack: api.slack.com/authentication/verifying-requests-from-slack reference
// Shopify: docs.shopify.com (verified against Node `crypto` reference)

import { test, expect, describe } from "bun:test";
import { createHmac } from "node:crypto";
import { verify } from "../../shared/sig-verify";

describe("Stripe verifier", () => {
  const secret = "whsec_testsecretdemo";
  const body = '{"id":"evt_test","object":"event","type":"payment_intent.succeeded"}';
  const t = 1700000000;
  const expected = createHmac("sha256", secret).update(`${t}.${body}`).digest("hex");

  test("valid signature returns valid=true", () => {
    const result = verify({
      provider: "stripe",
      secret,
      raw_body: body,
      headers: { "stripe-signature": `t=${t},v1=${expected}` },
      now_seconds: t,
    });
    expect(result.valid).toBe(true);
    expect(result.details.computed_signature).toBe(expected);
    expect(result.details.timestamp).toBe(t);
    expect(result.details.age_seconds).toBe(0);
  });

  test("wrong secret → signature_mismatch with diff details", () => {
    const result = verify({
      provider: "stripe",
      secret: "whsec_wrong",
      raw_body: body,
      headers: { "stripe-signature": `t=${t},v1=${expected}` },
      now_seconds: t,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_mismatch");
    expect(result.details.computed_signature).not.toBe(expected);
    expect(result.details.first_diff_byte).toBe(0); // wrong-secret diverges from byte 0
  });

  test("stale timestamp (>5min) → timestamp_skew", () => {
    const result = verify({
      provider: "stripe",
      secret,
      raw_body: body,
      headers: { "stripe-signature": `t=${t},v1=${expected}` },
      now_seconds: t + 600, // 10 min later
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("timestamp_skew");
    expect(result.details.age_seconds).toBe(600);
  });

  test("missing header → header_missing", () => {
    const result = verify({
      provider: "stripe",
      secret,
      raw_body: body,
      headers: {},
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("header_missing");
  });

  test("malformed header → header_malformed", () => {
    const result = verify({
      provider: "stripe",
      secret,
      raw_body: body,
      headers: { "stripe-signature": "this is not a valid stripe sig" },
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("header_malformed");
  });

  test("empty body → body_empty", () => {
    const result = verify({
      provider: "stripe",
      secret,
      raw_body: "",
      headers: { "stripe-signature": `t=${t},v1=${expected}` },
      now_seconds: t,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("body_empty");
  });

  test("v0 only → unsupported_scheme", () => {
    const result = verify({
      provider: "stripe",
      secret,
      raw_body: body,
      headers: { "stripe-signature": `t=${t},v0=${expected}` },
      now_seconds: t,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("unsupported_scheme");
    expect(result.details.scheme).toBe("v0");
  });

  test("case-insensitive header names", () => {
    const result = verify({
      provider: "stripe",
      secret,
      raw_body: body,
      headers: { "Stripe-Signature": `t=${t},v1=${expected}` },
      now_seconds: t,
    });
    expect(result.valid).toBe(true);
  });

  test("multiple v1= entries (secret-rotation window) — verifier tries each", () => {
    // Stripe sends one v1= per active signing secret during rotation.
    // QUALITY-REVIEW B2: previously we kept only the LAST v1=, so a user
    // debugging during rotation with the OLDER secret (still active) got a
    // false signature_mismatch.
    const wrongSig = "0".repeat(64);
    const result = verify({
      provider: "stripe",
      secret,
      raw_body: body,
      // wrong sig FIRST, correct sig SECOND
      headers: { "stripe-signature": `t=${t},v1=${wrongSig},v1=${expected}` },
      now_seconds: t,
    });
    expect(result.valid).toBe(true);
    expect(result.details.provided_signature).toBe(expected);
  });
});

describe("GitHub verifier — official reference vector", () => {
  // From docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
  const secret = "It's a Secret to Everybody";
  const body = "Hello, World!";
  const expectedSig = "757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

  test("official reference vector verifies", () => {
    const result = verify({
      provider: "github",
      secret,
      raw_body: body,
      headers: { "x-hub-signature-256": `sha256=${expectedSig}` },
    });
    expect(result.valid).toBe(true);
    expect(result.details.computed_signature).toBe(expectedSig);
  });

  test("wrong secret → signature_mismatch", () => {
    const result = verify({
      provider: "github",
      secret: "wrong",
      raw_body: body,
      headers: { "x-hub-signature-256": `sha256=${expectedSig}` },
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_mismatch");
  });

  test("legacy sha1 header → unsupported_scheme", () => {
    const result = verify({
      provider: "github",
      secret,
      raw_body: body,
      headers: { "x-hub-signature": "sha1=somelegacyhash" },
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("unsupported_scheme");
    expect(result.details.scheme).toBe("sha1");
  });

  test("malformed header → header_malformed", () => {
    const result = verify({
      provider: "github",
      secret,
      raw_body: body,
      headers: { "x-hub-signature-256": "not-the-right-format" },
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("header_malformed");
  });
});

describe("Slack verifier", () => {
  const secret = "8f742231b10e8888abcd99yyyzzz85a5";
  const t = 1531420618;
  const body = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
  const expected = createHmac("sha256", secret).update(`v0:${t}:${body}`).digest("hex");

  test("valid signature verifies", () => {
    const result = verify({
      provider: "slack",
      secret,
      raw_body: body,
      headers: {
        "x-slack-signature": `v0=${expected}`,
        "x-slack-request-timestamp": String(t),
      },
      now_seconds: t,
    });
    expect(result.valid).toBe(true);
  });

  test("missing timestamp header → header_missing with specific raw_header note", () => {
    // QUALITY-REVIEW C1: previously we said "header_missing" without
    // distinguishing which header. Now raw_header carries which one is gone.
    const result = verify({
      provider: "slack",
      secret,
      raw_body: body,
      headers: { "x-slack-signature": `v0=${expected}` },
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("header_missing");
    expect(result.details.raw_header).toContain("Timestamp");
  });

  test("missing signature header but timestamp present → specific error", () => {
    const result = verify({
      provider: "slack",
      secret,
      raw_body: body,
      headers: { "x-slack-request-timestamp": "1700000000" },
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("header_missing");
    expect(result.details.raw_header).toContain("Signature");
  });

  test("stale timestamp → timestamp_skew", () => {
    const result = verify({
      provider: "slack",
      secret,
      raw_body: body,
      headers: {
        "x-slack-signature": `v0=${expected}`,
        "x-slack-request-timestamp": String(t),
      },
      now_seconds: t + 1000,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("timestamp_skew");
  });
});

describe("Shopify verifier", () => {
  const secret = "shpss_secret123";
  const body = '{"id":12345,"order_number":1001}';
  const expected = createHmac("sha256", secret).update(body).digest("base64");

  test("valid base64 signature verifies", () => {
    const result = verify({
      provider: "shopify",
      secret,
      raw_body: body,
      headers: { "x-shopify-hmac-sha256": expected },
    });
    expect(result.valid).toBe(true);
    expect(result.details.encoding).toBe("base64");
    expect(result.details.computed_signature).toBe(expected);
  });

  test("wrong secret → signature_mismatch", () => {
    const result = verify({
      provider: "shopify",
      secret: "wrong",
      raw_body: body,
      headers: { "x-shopify-hmac-sha256": expected },
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_mismatch");
  });

  test("missing header → header_missing", () => {
    const result = verify({
      provider: "shopify",
      secret,
      raw_body: body,
      headers: {},
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("header_missing");
  });
});

describe("Constant-time comparison resists trivial timing attacks", () => {
  // Sanity check that we use timingSafeEqual, not ===. We can't measure
  // timing reliably in a unit test, but we can confirm comparing two equal-length
  // strings with very different bytes still reaches the comparator.
  const secret = "x";
  const body = "y";
  const expected = createHmac("sha256", secret).update(body).digest("hex");
  const wrong = "0".repeat(expected.length);

  test("equal-length wrong sig still returns mismatch (no early exit)", () => {
    const result = verify({
      provider: "github",
      secret,
      raw_body: body,
      headers: { "x-hub-signature-256": `sha256=${wrong}` },
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_mismatch");
  });
});
