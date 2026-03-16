---
phase: 02-signup-login
plan: 01
subsystem: auth
tags: [hibp, k-anonymity, signup, email-verification, hmac, argon2id, zxcvbn]

# Dependency graph
requires:
  - phase: 01-foundation
    provides: "hashPassword, logAuthEvent, validateEmail, validatePassword, normalizeEmail, sendVerificationCode, initBalance, checkAuthRateLimit"
provides:
  - "HIBP k-anonymity password breach check module (shared/hibp.ts)"
  - "POST /auth/signup route with full validation pipeline"
  - "POST /auth/verify route with attempt-limited code verification"
  - "POST /auth/resend-code route with dual rate limiting"
affects: [02-signup-login, 03-api-keys, 04-billing]

# Tech tracking
tech-stack:
  added: []
  patterns: [HMAC-SHA256 code hashing, k-anonymity breach checking, anti-enumeration responses]

key-files:
  created: [shared/hibp.ts, tests/hibp.test.ts]
  modified: [apis/dashboard/index.ts]

key-decisions:
  - "HMAC-SHA256 for verification code hashing (not bcrypt) for speed on 6-digit codes"
  - "Fail-open on HIBP API errors to avoid blocking signups"
  - "Unverified re-signup deletes old user to avoid stuck accounts"
  - "Anti-enumeration: resend-code returns generic success even for unknown emails"

patterns-established:
  - "Verification code pattern: generate -> HMAC hash -> store hash -> compare on verify"
  - "Auth route placement: before bearerAuth middleware for public access"

requirements-completed: [AUTH-01, AUTH-02, AUTH-03, AUTH-04, AUTH-05]

# Metrics
duration: 3min
completed: 2026-03-16
---

# Phase 2 Plan 1: Signup & Email Verification Summary

**Signup with HIBP breach check + zxcvbn validation, email verification with HMAC-hashed 6-digit codes, and rate-limited code resend**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-16T15:51:13Z
- **Completed:** 2026-03-16T15:53:46Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- HIBP k-anonymity module with SHA-1 prefix lookup, 5s timeout, and fail-open semantics (5 tests passing)
- POST /auth/signup with full validation pipeline: email normalization, zxcvbn strength check, HIBP breach detection, user creation, credit balance init, verification code email
- POST /auth/verify with HMAC-SHA256 code comparison, 3-attempt limit, 10-minute expiry, atomic attempt increment
- POST /auth/resend-code with dual rate limiting (1/60s per email, 5/hr per IP) and anti-enumeration responses

## Task Commits

Each task was committed atomically:

1. **Task 1: HIBP k-anonymity breach check module (TDD)** - `65fb8d5` (test), `917589f` (feat)
2. **Task 2: Signup, verify, and resend-code API routes** - `020238c` (feat)

## Files Created/Modified
- `shared/hibp.ts` - HIBP k-anonymity password breach check via range API
- `tests/hibp.test.ts` - 5 unit tests for HIBP module (real API + mocked error cases)
- `apis/dashboard/index.ts` - Added 3 auth routes, verification code helpers, HMAC hashing

## Decisions Made
- Used HMAC-SHA256 for verification code hashing (fast for 6-digit codes, secret-keyed)
- Fail-open on HIBP API errors: signup should not be blocked by external service failure
- Unverified re-signup deletes the old user record to prevent stuck accounts from blocking re-registration
- Anti-enumeration on resend-code: always returns success regardless of whether user exists

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required. VERIFICATION_CODE_SECRET has a dev-only default; must be set in production.

## Next Phase Readiness
- Signup and email verification complete, ready for Plan 02-02 (Login/Logout)
- All shared modules (auth, validation, email, credits, rate-limit, hibp) integrated and working

---
*Phase: 02-signup-login*
*Completed: 2026-03-16*
