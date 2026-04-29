# Security Audit — sigdebug / stripesig

**Date:** 2026-04-28  
**Auditor:** Claude (security-review skill)  
**Scope:** `apis/sigdebug/index.ts`, `shared/sig-verify.ts`, `shared/sig-hints.ts`, `shared/logger.ts`, `apis/sigdebug/landing.html`  
**Trust boundary:** Anonymous internet POST, users pasting real production secrets and webhook payloads.

---

## VERDICT

**Deploy-blocker: YES — one HIGH finding must be fixed before production.**  
**Privacy claim "we don't log your secret or body": HOLDS.** No code path persists or re-emits the secret or raw_body. All other findings are Medium or lower.

---

## Summary by Severity

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 1 |
| Medium   | 2 |
| Low      | 2 |
| Info     | 3 |

---

## HIGH — Computed Signature Echoed in Response on Mismatch

**File:** `shared/sig-verify.ts` lines 125–136, 219–227, 279–290, 340–346  
**Blocks deploy:** YES

### What happens

On `signature_mismatch`, all four verifiers populate `result.details.computed_signature` with the full HMAC-SHA256 output. That value flows unchanged into the `/check` JSON response via `apis/sigdebug/index.ts` line 104–109:

```ts
return c.json({
  valid: result.valid,
  provider: result.provider,
  reason: result.reason,
  hints,
  details: result.details,   // <-- contains computed_signature
});
```

### Why this matters

`computed_signature` is a function of `(secret, body)`. An attacker who controls the body can use the oracle to recover the secret or to forge valid-looking diagnostics. More concretely:

1. **Chosen-plaintext oracle.** Send `POST /check` with a known body and any value for `secret`. The response always includes the HMAC of `(secret, body)`. This is by design for the "valid" path (showing the user what the correct signature looks like is the core UX). The problem is it also fires for the _mismatch_ path — where the user may have entered the wrong secret entirely, or where the caller is a malicious third party trying to probe the secret.

2. **The site claims "we don't log your secret or body"** — true, but returning `computed_signature` to the caller _is_ a form of secret-derived output that is unexpected to many users. They pasted `whsec_live_...` and the response contains `HMAC(whsec_live_..., their-prod-body)`. If they share their debug session URL or screenshot, they've inadvertently shared material that can confirm or deny guesses at the secret.

3. This is not a remote-code-execution class bug, but for a tool explicitly marketed to engineers pasting **live production secrets**, echoing HMAC output on failure is a meaningful privacy regression beyond the stated guarantee.

### Reproduction

```bash
curl -s -X POST https://stripesig.apimesh.xyz/check \
  -H 'content-type: application/json' \
  -d '{"provider":"github","secret":"mysecret","raw_body":"hello","headers":{"x-hub-signature-256":"sha256=aaaa"}}'
# => {"details":{"computed_signature":"<full HMAC of mysecret+hello>", ...}}
```

### Fix

Gate `computed_signature` and `provided_signature` behind a redaction flag, or omit them from the failure response entirely. The hints engine already explains the pattern mismatch in human terms without needing to echo the raw hash. A lightweight option: truncate to the first 8 hex chars (enough for the "first_diff_byte" diagnostic, useless for oracle purposes):

```ts
// In failure() helper or in the /check handler before returning:
function redactSig(sig: string | undefined): string | undefined {
  if (!sig) return sig;
  return sig.slice(0, 8) + "…[redacted]";
}
```

Apply `redactSig` to `computed_signature` and `provided_signature` in every `failure()` callsite, or strip them in the route handler before calling `c.json()`. Keep them in the `valid: true` success path — showing the correct signature is the core value.

**Alternative (preferred UX):** Keep `computed_signature` in the success response, remove it entirely from failure responses. The hints already surface all actionable information; the HMAC value adds nothing when the secret is likely wrong.

---

## MEDIUM — Double Rate-Limit on `/check` Creates a Wider Burst Window

**File:** `apis/sigdebug/index.ts` lines 36–37  
**Blocks deploy:** No

```ts
app.use("*", rateLimit("sigdebug", 60, 60_000));
app.use("/check", rateLimit("sigdebug-check", 60, 60_000));
```

A request to `POST /check` hits two independent in-memory buckets, each with a 60/min limit. Because they're separate zones, an IP that exhausted `sigdebug-check` is still within `sigdebug`. The wildcard middleware runs first and counts the hit; the path-specific middleware then separately counts it. Neither bucket blocks based on the other.

In practice this means a fresh IP can burst up to 60 `GET /` + 60 `POST /check` = 120 requests per minute, not 60. For a free HMAC-computation endpoint the blast radius is low (HMAC is O(n) in body length, capped at 100 KB), but the double-bucket design is confusing and doesn't match the stated "60/min/IP" claim in the landing page copy.

### Fix

Remove the duplicate `/check` middleware registration. The wildcard `"*"` already covers `/check`:

```ts
// Keep only one:
app.use("*", rateLimit("sigdebug", 60, 60_000));
```

If you later want a tighter limit specifically on `/check`, give the wildcard a higher limit and give `/check` the lower one. They're separate zones so the tighter one is the effective cap only if you code them to share state (they don't currently).

---

## MEDIUM — Stripe: Timestamp Checked After HMAC, Not Before

**File:** `shared/sig-verify.ts` lines 113–148  
**Blocks deploy:** No

Stripe's documentation specifies checking the timestamp **before** computing the HMAC, to avoid spending CPU on replayed payloads. The current flow:

1. Parse header
2. Compute HMAC
3. Compare
4. If match, check timestamp

On a mismatched signature, the timestamp is never checked — the function returns `signature_mismatch`. On a matched signature, if the timestamp is stale, it returns `timestamp_skew`. This is correct for the **diagnostic** use-case (you want to know that the signature would have been valid if fresh), but it means:

- An attacker sending high-rate requests with valid signatures but stale timestamps will consume full HMAC computation before being rejected.
- More importantly: for Stripe's replay-protection spec, a production verifier should reject stale timestamps first (before HMAC, not after). This tool is a **debugger** not a production verifier, but the landing page's "How it works" section describes the algorithm in a way that engineers may copy verbatim into their own code.

### Fix

Add a comment clarifying this is the **diagnostic** order (check signature first, then timestamp, so both problems are surfaced to the user) and is intentionally different from the **production** order (check timestamp first to reject replays cheaply). This protects against the copy-paste anti-pattern.

---

## LOW — `now_seconds` Override Exposed via Public API Surface

**File:** `shared/sig-verify.ts` line 55; `apis/sigdebug/index.ts` line 97  
**Blocks deploy:** No

`VerifyInput.now_seconds` is documented as "Optional override for 'now' — for testing" but `apis/sigdebug/index.ts` passes `body.tolerance_seconds` through from the request body without passing `now_seconds`. This means `now_seconds` is silently ignored from untrusted input, which is safe as-is. However:

- The `tolerance_seconds` field **is** accepted from the user (`body.tolerance_seconds` at line 97) with no bounds checking. A caller can send `tolerance_seconds: 999999999` to suppress all timestamp-skew errors. This is not a security issue (the tool is a debugger, not a gatekeeper), but it could lead to misleading "valid" results when a stale payload passes because of a user-supplied infinite tolerance.

### Fix

Cap `tolerance_seconds` at a reasonable maximum (e.g. 86400 seconds / 24 hours) to prevent the debugger from giving a misleading "valid" result on obviously-replayed payloads:

```ts
const MAX_TOLERANCE = 86_400;
const input: VerifyInput = {
  ...
  tolerance_seconds: typeof body.tolerance_seconds === "number"
    ? Math.min(body.tolerance_seconds, MAX_TOLERANCE)
    : undefined,
};
```

---

## LOW — Header Count Not Bounded

**File:** `apis/sigdebug/index.ts` lines 83–90  
**Blocks deploy:** No

Individual header values are capped at 4 KB, but there's no limit on the number of headers in the object. An attacker can send:

```json
{ "headers": { "h1": "v", "h2": "v", ..., "h100000": "v" } }
```

The `lowerKeys()` call in `sig-verify.ts` iterates all entries. With 100K keys each with 1-byte values this allocates a second object of similar size. Memory impact is bounded by the outer 100 KB JSON parse limit (Bun's default request body limit), so the real cap is the raw JSON size. This is a defense-in-depth gap, not an exploitable hole.

### Fix

Add an explicit header count check:

```ts
const MAX_HEADERS = 50;
if (Object.keys(body.headers).length > MAX_HEADERS) {
  return c.json({ error: `headers object must have at most ${MAX_HEADERS} keys` }, 413);
}
```

---

## INFO — Timing Side Channel Between `header_missing` and `signature_mismatch`

**File:** `shared/sig-verify.ts`  
**Blocks deploy:** No

Observable timing differences exist between early-return failure paths (e.g. `header_missing` returns before any HMAC work) and `signature_mismatch` (which runs full HMAC). This is not a secret-recovery oracle — the secret isn't being tested for correctness here, the signature is — and the tool is explicitly a debugger, not an auth gate. Flag for completeness: a timing oracle here would tell an attacker "does this provider's expected header exist", which is public knowledge. No action required.

---

## INFO — `constantTimeEqualString` Uses UTF-8 Encoding for Base64 Comparison (Shopify)

**File:** `shared/sig-verify.ts` lines 374–377  
**Blocks deploy:** No

```ts
function constantTimeEqualString(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}
```

This is called for Shopify base64 comparison. Base64 characters are all ASCII, so `utf8` and `ascii`/`latin1` produce identical bytes for valid base64. The length check before `timingSafeEqual` is correct (avoids the throw on unequal-length Buffers). This is safe. A minor style note: using `Buffer.from(a, "base64")` to decode both sides and comparing the raw bytes would be more semantically correct and would catch base64url vs base64 variants — though neither Shopify nor Node ships base64url here.

---

## INFO — CORS `origin: "*"` is Correct Here; No CSRF Risk

**File:** `apis/sigdebug/index.ts` lines 15–19  
**Blocks deploy:** No

With `origin: "*"`, the browser won't include cookies or auth credentials on cross-origin requests. This endpoint has no session, no auth, no cookies — the wildcard CORS policy is appropriate and does not create CSRF attack surface. CSRF requires credential-bearing same-origin cookies to be forwarded; none exist here. The privacy claim ("your secret never leaves your machine if you call the API client-side") is accurate precisely because CORS allows direct browser calls without a proxy.

---

## Crypto Correctness Verification

All four HMAC implementations match the upstream provider specifications:

| Provider | Spec | Implementation | Match |
|----------|------|----------------|-------|
| Stripe | `HMAC-SHA256(secret, "${t}.${body}")`, hex, `v1=` prefix | `createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")` | YES |
| GitHub | `HMAC-SHA256(secret, body)`, hex, `sha256=` prefix | `createHmac("sha256", secret).update(body).digest("hex")` | YES |
| Slack | `HMAC-SHA256(secret, "v0:${ts}:${body}")`, hex, `v0=` prefix | `createHmac("sha256", secret).update(`v0:${t}:${body}`).digest("hex")` | YES |
| Shopify | `HMAC-SHA256(secret, body)`, base64 | `createHmac("sha256", secret).update(body).digest("base64")` | YES |

`timingSafeEqual` usage is correct: the length check `a.length !== b.length` returns `false` before calling `timingSafeEqual`, preventing the throw that would occur on unequal-length Buffers. Constant-time comparison is preserved for equal-length inputs.

---

## Privacy Claim Verification — "We don't log your secret or body"

Tracing data flow from `POST /check` through all logging paths:

1. **`apiLogger`** (`shared/logger.ts`): logs `apiName`, `path`, `method`, `statusCode`, `responseTimeMs`, `paid`, `amount`, `clientIp`, `payerWallet`, `userId`, `apiKeyId`, `userAgent`. No `body`, no `secret`, no `raw_body`.

2. **`logRequest`** (`shared/db.ts` line 36–55): parameters match above — no body or secret columns in schema.

3. **`sig-verify.ts`**: pure function, no I/O, no logging.

4. **`sig-hints.ts`**: pure function, no I/O. Reads `input.secret` only for prefix detection (does not emit the secret into hint strings — hints say "starts with 'pk_'" not "your secret is `pk_live_xyz`"). Reads `input.raw_body` only for shape detection (does not echo body content into hints).

5. **`index.ts` error messages**: size-cap errors echo the field name and limit, not the value.

**Verdict: Privacy claim holds.** The one caveat is the HIGH finding above — `computed_signature` is HMAC-derived output from the secret and is included in the response, which is a weaker but still meaningful form of secret-derived disclosure.

---

## Recommended Action Order

1. **Before deploy (HIGH):** Strip `computed_signature` and `provided_signature` from `failure()` results, or truncate to first 8 chars. Keep full values only in the `valid: true` success path.
2. **Before deploy (cleanup):** Remove the duplicate `/check` rate-limit registration.
3. **Post-deploy (LOW):** Cap `tolerance_seconds` at 86400. Add header-count guard (`MAX_HEADERS = 50`).
4. **Post-deploy (INFO):** Add an inline comment in `verifyStripe`/`verifySlack` noting that the timestamp-after-HMAC order is intentional for the diagnostic use case and should not be copied into production auth code.
