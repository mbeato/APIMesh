---
phase: 05-stripe-billing
plan: 02
subsystem: billing
tags: [stripe, webhook, idempotency, signature-verification]

# Dependency graph
requires:
  - phase: 05-stripe-billing
    plan: 01
    provides: "shared/stripe.ts with Stripe API helpers"
provides:
  - "Webhook signature verification with timing-safe comparison"
  - "Idempotent credit granting via UNIQUE constraint on stripe_payment_intent"
affects: [05-03, 06-credits-dashboard]

# Tech tracking
tech-stack:
  added: []
  patterns: ["HMAC-SHA256 webhook signature verification", "idempotent upsert via UNIQUE constraint"]

key-files:
  created: []
  modified: [shared/stripe.ts, apis/dashboard/index.ts]

key-decisions:
  - "Webhook route placed before all middleware for raw body access"
  - "Always returns 200 to Stripe to prevent unnecessary retries"
  - "User existence verified before credit granting"

patterns-established:
  - "Webhook-first credit granting: never on client redirect"
  - "5-minute event age limit for replay protection"

requirements-completed: [BILL-03, BILL-04, BILL-05]

# Metrics
duration: ~4min
completed: 2026-03-18
---

# Plan 05-02 Summary: Webhook Handler with Idempotency and Signature Verification

**Completed:** 2026-03-18
**Duration:** ~4min

## What Was Done

### Task 1: Added verifyWebhookSignature() to shared/stripe.ts
- HMAC-SHA256 signature verification using crypto.createHmac + crypto.timingSafeEqual
- Parses Stripe-Signature header (t=timestamp,v1=signature format)
- Rejects events older than 5 minutes (age > 300 seconds)
- Timing-safe buffer comparison prevents side-channel attacks
- Graceful error handling (returns false on any parsing failure)

### Task 2: Added POST /billing/webhook route to dashboard
- Registered at line 41 (after health check, before all other routes and middleware)
- No auth required — Stripe authenticates via signature
- Reads raw body via c.req.text() before any JSON parsing (critical for signature verification)
- Handles checkout.session.completed events:
  - Extracts user_id, tier, credits_amount from session metadata
  - Verifies user exists in database before granting
  - Calls addCredits() which handles idempotency via UNIQUE constraint on stripe_payment_intent
  - Logs auth event "credit_purchase" on successful grant
  - Silently skips duplicates (no error, no double-grant)
- Returns 200 for all valid requests (including unhandled event types)

## Artifacts
- `shared/stripe.ts` — added verifyWebhookSignature(), STRIPE_WEBHOOK_SECRET export
- `apis/dashboard/index.ts` — webhook route added early (line 41), before CSP/auth/body-parsing middleware

## Decisions
- Webhook route placed before all middleware to ensure raw body access
- User existence verified before credit granting (handles deleted accounts between checkout and webhook)
- Always returns 200 to Stripe (even for errors) to prevent unnecessary retries for unrecoverable issues
