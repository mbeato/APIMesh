---
phase: 05-stripe-billing
plan: 03
subsystem: billing-frontend
tags: [billing, frontend, tier-cards, dark-theme]

# Dependency graph
requires:
  - phase: 05-stripe-billing
    plan: 01
    provides: "GET /billing/tiers, POST /billing/checkout, GET /billing/balance routes"
provides:
  - "Billing page at /account/billing with tier cards and balance display"
  - "initBilling() function in auth.js"
affects: [06-credits-dashboard]

# Tech tracking
tech-stack:
  added: []
  patterns: ["server-rendered HTML with vanilla JS", "dark theme with Space Grotesk + JetBrains Mono"]

key-files:
  created: [apis/landing/billing.html]
  modified: [apis/landing/auth.js, apis/dashboard/index.ts]

key-decisions:
  - "Billing page max-width 720px for 2-column tier grid layout"
  - "Balance displayed as dollars (microdollars / 100000)"

patterns-established:
  - "Tier card UI pattern: name, price, credit count, effective rate, buy button"

requirements-completed: [FE-06]

# Metrics
duration: ~4min
completed: 2026-03-18
---

# Plan 05-03 Summary: Billing Page with Tier Cards

**Completed:** 2026-03-18
**Duration:** ~4min

## What Was Done

### Task 1: Created billing.html
- New page at apis/landing/billing.html with dark theme matching existing pages
- CSS variables: --bg, --surface, --border, --accent, --text, --text-secondary, --mono, --font
- Space Grotesk + JetBrains Mono fonts, canvas mesh background
- Balance section at top with large accent-colored dollar amount
- 4 tier cards in responsive 2x2 grid (1-column on mobile):
  - Starter: $5 / 500,000 credits
  - Builder: $20 / 2,200,000 credits (+10% badge)
  - Pro: $50 / 6,000,000 credits (+20% badge)
  - Scale: $100 / 13,000,000 credits (+30% badge)
- Each card shows: name, price, credit count, effective rate, Buy button
- Volume bonus badges positioned absolutely in card top-right
- Success/cancel feedback message areas (hidden by default)
- Navigation links to Account and Settings pages

### Task 2: Added initBilling() to auth.js
- Loads balance from GET /billing/balance on page load
- Displays balance as formatted dollar amount (microdollars / 100000)
- Checks URL params for billing=success or billing=cancelled feedback
- Buy button click handlers: POST to /billing/checkout, redirect to Stripe checkout_url
- Loading state on buttons during checkout creation
- Error handling for network failures and API errors

### Task 3: Added GET /account/billing route to dashboard
- Session-protected with redirect to /login for unauthenticated users
- Serves billing.html with same CSP and security headers as other account pages
- No-store cache control to prevent stale balance display

## Artifacts
- `apis/landing/billing.html` — new file
- `apis/landing/auth.js` — initBilling() added, page detection added in DOMContentLoaded
- `apis/dashboard/index.ts` — GET /account/billing route added

## Decisions
- Billing page max-width 720px (wider than settings 560px) to accommodate 2-column tier grid
- Balance displayed as dollars (converted from microdollars) for user-friendly display
- Effective rate per 1,000 credits shown on each card for easy comparison
