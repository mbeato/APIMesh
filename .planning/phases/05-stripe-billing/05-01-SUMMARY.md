---
phase: 05-stripe-billing
plan: 01
subsystem: billing
tags: [stripe, checkout, billing-routes, credit-tiers]

# Dependency graph
requires:
  - phase: 02-signup-login
    provides: "Session auth for billing routes"
provides:
  - "Stripe Checkout session creation via REST API"
  - "Billing routes: POST /billing/checkout, GET /billing/balance, GET /billing/tiers"
affects: [05-02, 05-03, 06-credits-dashboard]

# Tech tracking
tech-stack:
  added: []
  patterns: ["Stripe REST API via fetch with form-encoded bodies"]

key-files:
  created: [shared/stripe.ts]
  modified: [apis/dashboard/index.ts]

key-decisions:
  - "No Stripe SDK -- all interaction via fetch() with form-encoded bodies"
  - "Checkout session metadata includes user_id, tier, credits_amount"

patterns-established:
  - "Stripe API pattern: fetch with form-encoded body, metadata for webhook context"

requirements-completed: [BILL-01, BILL-02]

# Metrics
duration: ~4min
completed: 2026-03-18
---

# Plan 05-01 Summary: Stripe Checkout Session Creation and Billing Routes

**Completed:** 2026-03-18
**Duration:** ~4min

## What Was Done

### Task 1: Created shared/stripe.ts
- New module with CREDIT_TIERS config (4 tiers: starter $5/500K/0%, builder $20/2.2M/10%, pro $50/6M/20%, scale $100/13M/30%)
- `createCheckoutSession()` calls Stripe REST API via fetch() with form-encoded body
- Environment variable guards: STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET (fatal in production if missing)
- CreditTier interface exported for type safety

### Task 2: Added billing routes to dashboard
- `POST /billing/checkout` — session-protected, validates tier, creates Stripe Checkout session, returns `{ checkout_url }`
- `GET /billing/balance` — session-protected, returns `{ balance_microdollars }` via getBalance()
- `GET /billing/tiers` — public, returns tier info array with display formatting

## Artifacts
- `shared/stripe.ts` — new file
- `apis/dashboard/index.ts` — imports added, 3 billing routes added before bearer auth middleware

## Decisions
- No Stripe SDK: all interaction via fetch() with form-encoded bodies
- Checkout session metadata includes user_id, tier, credits_amount for webhook processing
- Auth event "checkout_initiated" logged on successful checkout creation
