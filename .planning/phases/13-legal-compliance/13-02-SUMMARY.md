---
phase: 13-legal-compliance
plan: 02
subsystem: auth
tags: [tos, consent, stripe, signup, legal, migration]

requires:
  - phase: 13-legal-compliance/01
    provides: "Legal page HTML files (ToS, Privacy, Refund) and route registration"
provides:
  - "ToS consent checkbox in signup form with client+server enforcement"
  - "tos_accepted_at column on users table (migration 007)"
  - "Stripe Checkout refund policy acknowledgment text"
  - "Consent and Stripe artifact tests"
affects: [auth, payments, onboarding]

tech-stack:
  added: []
  patterns: ["custom_text on Stripe Checkout for policy acknowledgment"]

key-files:
  created:
    - data/migrations/007_tos_accepted.sql
    - tests/legal-consent.test.ts
  modified:
    - apis/dashboard/index.ts
    - apis/landing/signup.html
    - apis/landing/auth.js
    - shared/stripe.ts

key-decisions:
  - "Existing users grandfathered with NULL tos_accepted_at"
  - "Plain URL in Stripe custom_text instead of Markdown link for rendering safety"

patterns-established:
  - "Consent gate: client checkbox + server 400 rejection for legal agreements"

requirements-completed: [LEGAL-08, LEGAL-09]

duration: 2min
completed: 2026-04-07
---

# Phase 13 Plan 02: Consent & Stripe Policy Summary

**ToS consent gate on signup (client checkbox + server 400 enforcement) with tos_accepted_at migration and Stripe Checkout refund acknowledgment text**

## Performance

- **Duration:** 2 min
- **Started:** 2026-04-07T19:59:20Z
- **Completed:** 2026-04-07T20:01:02Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments
- Signup form requires ToS/Privacy Policy checkbox before account creation
- Server rejects signup POST without tos_agree=true (400 status)
- tos_accepted_at timestamp stored in users table on successful signup
- Stripe Checkout shows non-refundable credits acknowledgment before payment
- 5 tests covering LEGAL-08 and LEGAL-09 requirements

## Task Commits

Each task was committed atomically:

1. **Task 1: Add ToS consent to signup flow with migration and server enforcement** - `964f96b` (feat)
2. **Task 2: Add Stripe Checkout refund policy text and write consent/Stripe tests** - `ed24f9f` (feat)

## Files Created/Modified
- `data/migrations/007_tos_accepted.sql` - Adds tos_accepted_at TEXT column to users table
- `apis/dashboard/index.ts` - Signup handler enforces tos_agree, stores tos_accepted_at
- `apis/landing/signup.html` - ToS consent checkbox before submit button
- `apis/landing/auth.js` - Client-side consent validation and tos_agree in POST body
- `shared/stripe.ts` - Refund policy acknowledgment via custom_text on Checkout
- `tests/legal-consent.test.ts` - 5 tests for consent and Stripe refund text artifacts

## Decisions Made
- Existing users grandfathered with NULL tos_accepted_at (per STATE.md blocker decision)
- Plain URL in Stripe custom_text instead of Markdown link syntax for rendering safety

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Legal compliance phase complete (both plans done)
- All 6 legal pages served, consent enforced, Stripe policy text active
- Ready for next milestone phases (brain improvements)

---
*Phase: 13-legal-compliance*
*Completed: 2026-04-07*
