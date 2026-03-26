---
phase: 11-platform-analytics-security
verified: 2026-03-26T05:00:00Z
status: passed
score: 10/10 must-haves verified
re_verification: false
human_verification:
  - test: "API key paid request logs paid=true in requests table at runtime"
    expected: "Row in requests table has paid=1 and amount_usd matching the API price"
    why_human: "Cannot query live SQLite DB without running the stack; static analysis confirms the path is wired but runtime row insertion requires a real paid request"
  - test: "Caddy header stripping takes effect on production and staging"
    expected: "curl -H 'X-APIMesh-Paid: 999' https://check.apimesh.xyz/health shows no spoofed paid flag in logs"
    why_human: "Caddyfile changes require a reload on the VPS to take effect; static file is correct but deployment state cannot be verified programmatically"
---

# Phase 11: Platform Analytics & Security Verification Report

**Phase Goal:** Platform Analytics & Security Hardening — fix API key revenue logging, unverified account enumeration, and internal header spoofing
**Verified:** 2026-03-26T05:00:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | API key authenticated paid requests are logged with paid=true and correct amount_usd | VERIFIED | `logger.ts:20-25`: reads `x-apimesh-paid` header, sets `paid = x402Paid \|\| apiKeyPaid`, `amount = apiKeyAmount` |
| 2 | logRevenue() is called for API key payments with network='credits' | VERIFIED | `logger.ts:52-54`: `else if (apiKeyPaid) { logRevenue(apiName, amount, "", "credits", undefined); }` |
| 3 | getRevenueByApi and getTotalRevenue include API key revenue | VERIFIED | Both query the `revenue` table; logRevenue now writes API key rows to that same table with `network='credits'`; no query changes required |
| 4 | Free endpoints (preview, health) are NOT logged as paid | VERIFIED | `api-key-auth.ts:72-89`: free path does NOT set `X-APIMesh-Paid`; logger only sets `apiKeyPaid=true` when header is present |
| 5 | Correct password on unverified account returns HTTP 401 (not 200) | VERIFIED | `dashboard/index.ts:728-731`: `c.json({ error: "email_not_verified", redirect: ... }, 401)` — status 401 explicitly present |
| 6 | Response body still contains error='email_not_verified' and redirect URL | VERIFIED | Same line: both `error` and `redirect` keys remain in the JSON body |
| 7 | Frontend login form still redirects to /verify on unverified account | VERIFIED | Plan confirms `apis/landing/auth.js` checks `result.data.error === "email_not_verified"` — body-driven, not status-driven; no auth.js change needed |
| 8 | External requests cannot spoof X-APIMesh-User-Id header | VERIFIED | `Caddyfile:116`: `header_up -X-APIMesh-User-Id` in `*.apimesh.xyz` block; `Caddyfile:237`: same in `*.staging.apimesh.xyz` |
| 9 | External requests cannot spoof X-APIMesh-Key-Id header | VERIFIED | `Caddyfile:117,238`: `header_up -X-APIMesh-Key-Id` in both wildcard blocks |
| 10 | External requests cannot spoof X-APIMesh-Paid header | VERIFIED | `Caddyfile:118,239`: `header_up -X-APIMesh-Paid` in both wildcard blocks |

**Score:** 10/10 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `shared/api-key-auth.ts` | X-APIMesh-Paid header on paid forwarded requests | VERIFIED | Line 121: `forwardHeaders.set("X-APIMesh-Paid", String(cost / 100_000))` — present only in paid path (after credit deduction at line 100), absent from free path (lines 72-89) |
| `shared/logger.ts` | API key paid detection and revenue logging | VERIFIED | Lines 19-25: dual detection (x402 + API key); lines 52-54: `logRevenue` called with `"credits"` network |
| `apis/dashboard/index.ts` | Login endpoint with consistent 401 for unverified accounts | VERIFIED | Line 731: `, 401` argument present; `email_not_verified` string present at line 729 |
| `caddy/Caddyfile` | Header stripping for all X-APIMesh-* internal headers | VERIFIED | `grep -c "header_up -X-APIMesh" Caddyfile` returns 8 (4 headers × 2 blocks as specified) |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `shared/api-key-auth.ts` | `shared/logger.ts` | X-APIMesh-Paid request header | VERIFIED | auth sets header at line 121; logger reads it at line 20 via `c.req.header("x-apimesh-paid")` |
| `shared/logger.ts` | `shared/db.ts logRevenue()` | logRevenue call with network='credits' | VERIFIED | `logger.ts:54`: `logRevenue(apiName, amount, "", "credits", undefined)` — import at line 2 |
| `apis/dashboard/index.ts` | `apis/landing/auth.js` | JSON body check for email_not_verified redirect | VERIFIED | Body keys `error` and `redirect` preserved; frontend checks body not status; no breakage |
| `caddy/Caddyfile *.apimesh.xyz` | `shared/logger.ts` | Stripped headers prevent log pollution | VERIFIED | Production block (lines 112-119): 4 `header_up -X-APIMesh-*` directives |
| `caddy/Caddyfile *.staging.apimesh.xyz` | `shared/logger.ts` | Stripped headers prevent log pollution (staging) | VERIFIED | Staging block (lines 233-240): identical 4 directives, port 3011 |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `shared/logger.ts` | `apiKeyPaidHeader` / `apiKeyAmount` | `c.req.header("x-apimesh-paid")` → set by `api-key-auth.ts:121` | Yes — value is `cost / 100_000` derived from `API_PRICES[subdomain]` (non-empty map, line 12-33) | FLOWING |
| `shared/logger.ts` | `paid`, `amount` | Computed from `x402Paid \|\| apiKeyPaid` | Yes — both paths produce real boolean/numeric values | FLOWING |
| `apis/dashboard/index.ts` | `email_not_verified` response | User row from DB lookup (upstream of the verified block) | Yes — user is fetched from DB before this code path is reached | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| X-APIMesh-Paid set only in paid path | `grep -n "X-APIMesh-Paid" shared/api-key-auth.ts` | Line 121 only (inside paid block after line 115 comment) | PASS |
| logger reads x-apimesh-paid | `grep "x-apimesh-paid" shared/logger.ts` | Line 20: `c.req.header("x-apimesh-paid")` | PASS |
| logRevenue called with 'credits' | `grep "credits" shared/logger.ts` | Lines 53-54 | PASS |
| dashboard returns 401 for unverified | `grep -A 4 "email_not_verified" apis/dashboard/index.ts` | `, 401` on line 731 | PASS |
| Caddyfile header strip count | `grep -c "header_up -X-APIMesh" caddy/Caddyfile` | 8 | PASS |
| All 4 commits present in git | `git log --oneline 1e1451f 101e97a c6eed91 f36c649` | All 4 found | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| INT-08 | 11-01, 11-02, 11-03 | API key usage logged in requests table (user_id + api_key_id columns) | SATISFIED (extended) | Phase 11 extends INT-08 beyond basic column logging: adds revenue table population, security hardening for logged data, and enumeration fix. Core INT-08 (column presence) was completed in Phase 9; Phase 11 closes the gap where revenue was invisible. |

**Traceability table note:** REQUIREMENTS.md maps INT-08 to Phase 9 (Complete). This is accurate for the base requirement (user_id + api_key_id columns). Phase 11 is an extension of INT-08's intent rather than a new requirement. No orphaned requirements found — all three plans claim the same INT-08 ID and the work is additive. The traceability table does not need updating for Phase 11 (no new requirement IDs were introduced).

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| None | — | — | — | — |

No stubs, placeholders, TODO comments, or hardcoded empty returns found in the four modified files. All implementations are substantive.

### Human Verification Required

#### 1. API Key Paid Request Runtime Logging

**Test:** Make a paid API call with a valid `sk_live_` key to any paid endpoint (e.g., `GET https://check.apimesh.xyz/` with a valid Bearer token and sufficient credits). Then query the SQLite DB: `SELECT paid, amount_usd, user_id, api_key_id FROM requests ORDER BY id DESC LIMIT 1;` and also `SELECT * FROM revenue ORDER BY id DESC LIMIT 1;`.
**Expected:** The requests row has `paid=1` and `amount_usd` matching the API price; the revenue row has `network='credits'` and a matching amount.
**Why human:** Cannot query live SQLite without running the stack. Static analysis confirms the code path is correctly wired, but runtime row insertion requires an actual paid request against the live or staging environment.

#### 2. Caddy Header Stripping in Production/Staging

**Test:** After deploying/reloading Caddy, run: `curl -s -H "X-APIMesh-Paid: 999" -H "X-APIMesh-User-Id: fake-user" https://check.apimesh.xyz/health`. Then check request logs to confirm the fake headers do not appear as user attribution or paid signals.
**Expected:** Logs show no `user_id` or `paid=true` from the spoofed headers; Caddy stripped them before the request reached Bun.
**Why human:** Caddyfile changes are correct in the file, but production Caddy must be reloaded (`caddy reload`) for changes to take effect. The deployment state of the remote server cannot be verified programmatically.

### Gaps Summary

No gaps. All 10 observable truths are verified at all four levels (exists, substantive, wired, data flowing). All four commits are confirmed in git history. The two items in human verification are confirmation checks, not blockers — the code is correct.

---

_Verified: 2026-03-26T05:00:00Z_
_Verifier: Claude (gsd-verifier)_
