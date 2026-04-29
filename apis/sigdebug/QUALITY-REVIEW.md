# sigdebug Quality Review

**Date:** 2026-04-28  
**Reviewer:** automated code review agent  
**Test run:** 35 pass, 0 fail (22ms)

## Counts

| Severity | Count |
|----------|-------|
| Blocker  | 2     |
| Concerning | 5   |
| Nice-to-have | 6  |

## Verdict

**Ship-conditional.** Two blockers must be fixed before the product is useful: the "stripe valid" example button is broken (produces a mismatch, not a success demo), and the Stripe multi-`v1=` rotation case fails to verify when it should succeed. The hint engine is largely correct and the core HMAC logic passes all 35 tests including the official GitHub reference vector. Fix the two blockers; the rest can be follow-up work.

---

## Blockers (do not ship)

### B1. `stripe-valid` example button always shows "Invalid signature"

**File:** `/Users/vtx/conway/apis/sigdebug/landing.html:184`

**Problem:** The `EXAMPLES['stripe-valid']` object has `headers: 'Stripe-Signature: t=__NOW__,v1=__VALID__'`. The `loadExample()` function replaces `__NOW__` with the current timestamp but never computes an actual HMAC or replaces `__VALID__`. Clicking the button sends `v1=__VALID__` to `/check`, which produces a `signature_mismatch`. The primary demo button — the one a user clicks first — shows a failure verdict. This actively undermines trust at the worst moment (first contact).

**Fix:** Replace `__VALID__` with a pre-computed signature using a fixed timestamp, or compute it client-side with the Web Crypto API:

```javascript
// Option A: fixed timestamp + pre-computed sig (simplest)
'stripe-valid': {
  provider: 'stripe',
  secret: 'whsec_test_secret_for_demo_only_not_real',
  raw_body: '{"id":"evt_test","object":"event","type":"payment_intent.succeeded"}',
  // Pre-compute: echo -n "1700000000.{body}" | openssl dgst -sha256 -hmac "whsec_test_secret_for_demo_only_not_real"
  headers: 'Stripe-Signature: t=1700000000,v1=<pre-computed-hex>'
}
// Pair with now_seconds override in /check, or just note it'll be stale and the
// stripe-stale example covers that case — the stripe-valid case only needs to show "valid".
// Better: remove time tolerance for the demo. Use tolerance_seconds: 999999999 in the fetch payload.
```

Or simpler: add `tolerance_seconds: 999999999` to the `runCheck()` payload when an example is loaded, so stale timestamps don't block the demo.

---

### B2. Stripe webhook secret rotation: only last `v1=` entry is tried

**File:** `/Users/vtx/conway/shared/sig-verify.ts:163–173`

**Problem:** `parseStripeHeader` stores parsed values in a plain object. When Stripe sends a rotation-period header — `t=<ts>,v1=<sig-by-old-secret>,v1=<sig-by-new-secret>` — the second `v1=` overwrites the first. The verifier only tries the LAST `v1=` entry. If the user has the old secret and Stripe sends `[v1=old-sig, v1=new-sig]`, the verifier computes against `new-sig`, gets a mismatch, and produces a `signature_mismatch` error on an event that SHOULD verify.

Stripe's official SDK tries all `v1=` entries and accepts if any matches. This is documented behavior during the ~72-hour rotation window.

**Failure scenario:** Engineer rotates webhook secret, forgets to update the env var immediately. Stripe enters the rotation window and sends both signatures. Our tool says "signature_mismatch." Real Stripe verification succeeds. The tool gives wrong advice.

**Fix:**

```typescript
function parseStripeHeader(raw: string): { t?: string; v1?: string[]; v0?: string } {
  let t: string | undefined;
  let v0: string | undefined;
  const v1: string[] = [];
  for (const pair of raw.split(",")) {
    const idx = pair.indexOf("=");
    if (idx < 0) continue;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k === "t") t = v;
    else if (k === "v0") v0 = v;
    else if (k === "v1") v1.push(v);
  }
  return { t, v1: v1.length ? v1 : undefined, v0 };
}
```

Then in `verifyStripe`, iterate over `parts.v1` (now `string[]`) and return success if any entry matches.

---

## Concerning (ship, but follow up fast)

### C1. Slack `header_missing` hint is misleading when only the timestamp is absent

**File:** `/Users/vtx/conway/shared/sig-hints.ts:158–165` and `/Users/vtx/conway/shared/sig-verify.ts:247–248`

**Problem:** `verifySlack` returns `header_missing` if either `X-Slack-Signature` or `X-Slack-Request-Timestamp` is absent. `headerHints` then outputs: "The expected X-Slack-Signature (and X-Slack-Request-Timestamp) header is missing." If only the timestamp is absent, this says the signature is missing when it isn't. The user will look for a header that is already there.

**Fix:** Set `raw_header` in the `header_missing` failure details when the sig is present (even if timestamp is absent), so the hint can distinguish:

```typescript
if (!sig || !tsRaw) {
  return failure("slack", "header_missing", {
    hash_algo: "sha256",
    encoding: "hex",
    // surface whichever IS present so hints can be precise
    raw_header: sig ? `X-Slack-Request-Timestamp missing (X-Slack-Signature present)` : undefined,
  });
}
```

Then `headerHints` can key off `raw_header` presence to produce the right message.

---

### C2. `jq`-formatted body triggers the "JSON.stringify" hint incorrectly

**File:** `/Users/vtx/conway/shared/sig-hints.ts:130–134`

**Problem:** The trigger condition is `body.startsWith("{") && body.includes('": ')`. This fires for any JSON where keys are followed by `: ` — which is the output of `jq .` (the default `jq` pretty-printer) as well as any logging system that pretty-prints JSON (Datadog, CloudWatch, etc.). The hint text says "JSON.stringify() emits with 2-space indent" but jq output has `:` + space without the indent requirement. More importantly: this hint fires on a body copied from a log viewer, which IS an actionable case — but the hint attributes it to `JSON.stringify()` specifically, which may confuse an engineer who didn't call `JSON.stringify()` at all.

**Fix:** Broaden the hint text to cover log-viewer pretty-printing:

```
"Your body contains '": ' (key + colon + space), which appears in pretty-printed JSON — 
from JSON.stringify(obj, null, 2), jq, or a log viewer. Webhook senders (Stripe, GitHub, 
Shopify) send compact JSON with no spaces after colons. If you copied the body from a log 
viewer or debugger, make sure you're using the exact raw bytes from the wire."
```

This is a hint-quality issue, not a false-negative — the hint still fires on true positives — but the explanation would send engineers to the wrong place.

---

### C3. Negative or non-numeric `tolerance_seconds` from user input is not validated

**File:** `/Users/vtx/conway/apis/sigdebug/index.ts:97` and `/Users/vtx/conway/shared/sig-verify.ts:115`

**Problem:** `tolerance_seconds` is passed directly from the JSON body to `verify()`. If a user sends `tolerance_seconds: -1`, then `Math.abs(age) > -1` is always `true` (any non-negative number exceeds -1). A correctly signed, fresh event returns `timestamp_skew` instead of `valid`. Verified:

```
Math.abs(0) > -1  =>  true  (should be false)
```

**Fix:** Validate in `index.ts` before constructing `VerifyInput`:

```typescript
if (body.tolerance_seconds !== undefined) {
  if (typeof body.tolerance_seconds !== "number" || !Number.isFinite(body.tolerance_seconds) || body.tolerance_seconds < 0) {
    return c.json({ error: "tolerance_seconds must be a non-negative number" }, 400);
  }
}
```

---

### C4. SEO meta targets zero of the high-volume exact-match search terms

**File:** `/Users/vtx/conway/apis/sigdebug/landing.html:6–9`

**Problem:** The spec names the acquisition channel as "engineers Googling 'stripe webhook signature failed' at 11pm." The actual title and description contain none of the high-value terms:

| Term | In title | In description |
|------|----------|----------------|
| "stripe webhook signature verification failed" | no | no |
| "No signatures found matching expected signature for payload" | no | no |
| "webhook signature failed" | no | no |
| "x-hub-signature-256 verification" | no | no |

The current title is `stripesig — Stripe webhook signature debugger (also GitHub, Slack, Shopify)` and the description starts with "Paste your failing...". Neither phrase would rank for the exact-match queries Stripe error messages produce.

**Fix:** Rewrite title and description to include exact phrases from error messages:

```html
<title>Stripe webhook signature verification failed? Debug it here — stripesig</title>
<meta name="description" content="Paste your failing payload to find out why: wrong secret, stale timestamp, body re-parsed, proxy stripping headers. Stripe, GitHub, Slack, Shopify. Free, instant." />
```

Add a hidden `<h2>` or footer paragraph with the verbatim Stripe error string: "No signatures found matching the expected signature for payload." This exact string is what engineers copy-paste into Google.

---

### C5. Rate limiting also applies to `GET /` and `GET /health`

**File:** `/Users/vtx/conway/apis/sigdebug/index.ts:36–38`

**Problem:**
```typescript
app.use("*", rateLimit("sigdebug", 60, 60_000));       // hits ALL routes
app.use("/check", rateLimit("sigdebug-check", 60, 60_000)); // hits /check again
```

`GET /` (the landing page) and `GET /health` are rate-limited at 60/min per IP. A user who rapid-refreshes the landing page (or a monitoring system polling `/health` every second) will get rate-limited. The landing page isn't a resource concern. The double rate limit on `/check` (`sigdebug` + `sigdebug-check`) means two separate counters increment, both at 60/min — whichever fills first blocks the request.

**Fix:** Apply the `*` rate limiter only to non-trivial routes, or remove it from `*` and only rate-limit `/check`:

```typescript
app.use("/check", rateLimit("sigdebug-check", 60, 60_000));
// Remove the app.use("*", rateLimit(...)) line
```

---

## Nice-to-have

### N1. Response is missing `body_length` — hard to debug "did I send the right body?"

**File:** `/Users/vtx/conway/apis/sigdebug/index.ts:103–110`

A user who pastes a truncated body won't know it. Adding `body_length: input.raw_body.length` and `body_preview: input.raw_body.slice(0, 120)` to `details` lets them immediately see "I sent 0 bytes" or "I see my body was cut at char 120." Low implementation cost, high diagnostic value. Not in the spec, but the spec says "hint quality > everything else" and this directly supports body-shape debugging.

---

### N2. `sigPatternHints` has no hint for `first_diff_byte` values 1–4

**File:** `/Users/vtx/conway/shared/sig-hints.ts:207–218`

**Problem:**
```typescript
if (result.details.first_diff_byte === 0) {
  // "wrong secret entirely"
} else if ((result.details.first_diff_byte ?? 0) > 4) {
  // "suspicious early match"
}
// first_diff_byte 1, 2, 3, 4: no hint
```

Values 1–4 are silently dropped. The `GENERIC_RAW_BODY_HINT` fires as a fallback when `hints.length === 0`, so the user does get something — but it's the least specific hint possible. Statistically, first_diff_byte of 1 is almost as indicative of a wrong secret as 0 (only 6.25% chance first hex char matches by accident).

**Fix:** Unify the boundary:

```typescript
if ((result.details.first_diff_byte ?? 0) <= 1) {
  // "wrong secret entirely"
} else if ((result.details.first_diff_byte ?? 0) > 4) {
  // "suspicious early match — possible header truncation"
}
// 2-4 can be left to GENERIC, or fold into the wrong-secret hint
```

---

### N3. `firstDiffByte` reports hex-character index, not decoded-byte index; comment is misleading

**File:** `/Users/vtx/conway/shared/sig-verify.ts:28` and `379–385`

The type comment says "Index of first byte mismatch in hex/base64 representation." The field is named `first_diff_byte`. The function operates on string characters, so index 0 means the first hex character, which is the first nibble of byte 0. For the hints (which talk about "byte 0"), the distinction doesn't matter in practice, but the API surface exposes `first_diff_byte` to callers who might misinterpret it as a decoded-byte offset. Rename to `first_diff_char` or update the comment to say "character index in the hex/base64 string, not in the decoded byte array."

---

### N4. Body-shape `bodyShapeHints` hints fire regardless of provider, including for Slack

**File:** `/Users/vtx/conway/shared/sig-hints.ts:136–141`

The trailing-newline hint fires for all providers. For Slack, whose body is URL-encoded form data (`token=xxx&team_id=yyy`), a trailing `\n` would be unusual but not impossible (some form parsers). The hint says "Try verifying without the trailing newline" which is correct for Stripe/GitHub/Shopify but could be wrong for Slack if the original Slack payload genuinely ends in `\n` (however unlikely). Low risk in practice but worth scoping the hint to JSON-body providers if you want zero false-positive risk.

---

### N5. `body-parser` framing in `bodyShapeHints` is stale

**File:** `/Users/vtx/conway/shared/sig-hints.ts:125–127`

"Express's `body-parser` consumes the body — use the `verify` callback option to capture it first."

Since Express v4.16 (2018), `express.json()` and `express.urlencoded()` are built-in and `body-parser` is not typically a separate dependency in new Express apps. The hint is correct but names the package engineers won't recognize. Better:

```
"Express's json() middleware consumes the body stream before you can read it raw. 
Use express.raw({ type: '*/*' }) to capture it first, or pass a verify callback 
to express.json({ verify: (req, res, buf) => { req.rawBody = buf; } })."
```

---

### N6. Shopify header value with whitespace produces mismatch with no diagnostic hint

**File:** `/Users/vtx/conway/shared/sig-hints.ts` (missing hint)

If an engineer copies `X-Shopify-Hmac-Sha256: abc123== ` from a log with trailing whitespace, `constantTimeEqualString` compares lengths (differ by 1) and returns false immediately. `first_diff_byte` is not computed in this code path (Shopify uses `constantTimeEqualString` which doesn't set `first_diff_byte`). No length-mismatch hint fires for Shopify because the `computed.length !== provided.length` check in `sigPatternHints` only runs for `signature_mismatch` and Shopify DOES go through that path — but wait: `firstDiffByte("abc123==", "abc123== ")` returns `8` (the index of the space), and `computed.length` (8) vs `provided.length` (9) differ, so the length-mismatch hint DOES fire. This is actually handled. Mark as resolved.

Actually verified: the `sigPatternHints` check `if (computed.length !== provided.length)` would fire for the whitespace case, suggesting "wrong encoding." That's slightly wrong (it's actually extra whitespace), but actionable enough. No fix needed, though a header-value whitespace hint analogous to the secret-whitespace hint would be more precise.

---

## Test coverage gaps

The 35 tests are solid for the happy path and named failure modes. Missing cases:

| Gap | Why it matters |
|-----|---------------|
| Stripe multi-`v1=` (rotation) — see Blocker B2 | Currently fails; no test exists to catch it |
| `tolerance_seconds: -1` | Incorrectly returns `timestamp_skew` for valid fresh events |
| Slack: sig header present, timestamp missing | Misleading hint says sig is missing |
| Shopify: header value with trailing whitespace | Currently produces "wrong encoding" hint (slightly wrong) |
| Unicode in secret (e.g., `secret: "whsec_日本語"`) | `createHmac` accepts Buffer; string input is UTF-8 encoded — should work, but no test |
| Headers object with numeric values (`{ "stripe-signature": 123 }`) | The per-header `typeof v !== "string"` check in index.ts handles this, but no test |
| `tolerance_seconds: 0` with fresh event | Should pass; `Math.abs(0) > 0` is false, so it passes — but no test |
| `first_diff_byte` in the 1–4 range | No test confirms GENERIC fires as fallback |

---

## Framework hint accuracy (2026)

| Hint | Accurate? |
|------|-----------|
| Express `body-parser` `verify` callback | Correct but outdated naming — `express.json({ verify })` is preferred |
| `express.raw()` | Correct |
| Fastify rawBody plugin | Correct (`fastify-raw-body`, compatible with Fastify v4) |
| Hono `c.req.raw.text()` | Correct — reads the underlying Request before any Hono body caching |
| Bun `req.text()` | Correct |

---

## HMAC avalanche / "first byte differs" statistical soundness

The hint "differs from the very first byte → usually the wrong secret entirely" is statistically sound. For a correct HMAC with a different secret, each output bit is independently ~50% likely to differ. The probability that the first hex character (4 bits) matches by accident is 1/16 = 6.25%. The probability that the first 5 hex chars all match by accident (triggering the "suspicious early match" hint) is (1/16)^5 ≈ 0.0001%. Both hint thresholds are defensible. The "first byte" wording is slightly imprecise (it's actually the first hex character = first nibble), but not misleading for the audience.

---

## Privacy claim verification

The landing page states: "We don't log your secret or body." Verified against `/Users/vtx/conway/shared/logger.ts`: `apiLogger` logs `path`, `method`, `status`, `ms`, `clientIp`, `userAgent`, and payment metadata. It does not log request body or headers. The privacy claim is accurate.
