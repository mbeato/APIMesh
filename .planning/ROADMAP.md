# Roadmap: APIMesh Stripe Billing & User Accounts

## Overview

This roadmap delivers traditional Stripe billing alongside the existing x402 crypto payment flow. It starts with database foundation and shared modules, builds auth flows, adds Stripe billing and API key management, integrates API key auth across all 21 APIs, and finishes with MCP server support and landing page updates. The dependency chain ensures the existing x402 flow remains untouched until Phase 7, where the branching middleware is carefully inserted.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Foundation** - Migration runner, database schema, shared modules, email domain setup
- [x] **Phase 2: Signup & Login** - User registration, email verification, login, logout, session cookies (completed 2026-03-17)
- [x] **Phase 3: Auth Hardening & Sessions** - Lockout, password reset, password change, session management UI (completed 2026-03-17)
- [x] **Phase 4: API Keys** - Key creation, display, revocation, management page (completed 2026-03-18)
- [x] **Phase 5: Stripe Billing** - Checkout integration, webhook handler, credit purchases (completed 2026-03-18)
- [x] **Phase 6: Credits & Account Dashboard** - Balance display, transaction history, low-balance alerts, account overview (completed 2026-03-18)
- [x] **Phase 7: API Key Auth Middleware** - Branching middleware across all 21 APIs, credit deduction, Caddy routes (completed 2026-03-18)
- [x] **Phase 8: MCP & Landing Page** - MCP server API key support, landing page signup CTA (completed 2026-03-18)
- [x] **Phase 9: Bug Fixes & Code Gaps** - Fix SESS-02 cookie, INT-08 request logging, INFRA-04 Caddy webhook (completed 2026-03-23)
- [ ] **Phase 10: Verification & Traceability** - VERIFICATION.md for phases 1/4/5/7, traceability updates

## Phase Details

### Phase 1: Foundation
**Goal**: All database tables, migration infrastructure, and shared modules exist and are independently testable
**Depends on**: Nothing (first phase)
**Requirements**: INFRA-01, INFRA-02, INFRA-05, INFRA-06, SESS-01, SESS-07, BILL-06, KEY-02, KEY-04
**Success Criteria** (what must be TRUE):
  1. Running the migration runner creates all 7 new tables and 2 ALTER TABLE changes without errors on a fresh database
  2. Auth module can hash a password with Argon2id and verify it round-trips correctly
  3. Credits module can atomically deduct from a balance and reject when insufficient (unit test passes)
  4. API key module can generate a key, store only its hash, and look it up by hash
  5. Resend domain verification is complete (SPF, DKIM, DMARC records propagated for apimesh.xyz)
**Plans**: TBD

Plans:
- [x] 01-01: Migration runner and database schema
- [x] 01-02: Shared modules (auth, credits, api-key, email, validation)
- [x] 01-03: Resend domain verification and auth rate limiters

### Phase 2: Signup & Login
**Goal**: Users can create an account, verify their email, log in, and log out
**Depends on**: Phase 1
**Requirements**: AUTH-01, AUTH-02, AUTH-03, AUTH-04, AUTH-05, AUTH-06, AUTH-08, SESS-02, SESS-03, FE-01, FE-02, FE-08, FE-09
**Success Criteria** (what must be TRUE):
  1. User can sign up with email and password, receives a 6-digit verification code via email, and can verify their account
  2. User with a weak password (zxcvbn < 3) or breached password (HIBP) is rejected at signup with a clear message
  3. User can log in and their session persists across browser restarts (httpOnly Secure cookie, 30-day sliding window)
  4. User can log out and the session is destroyed (cookie cleared, server-side record deleted)
  5. Signup and login pages render with the existing dark theme (Space Grotesk, JetBrains Mono) and work without JavaScript frameworks
**Plans**: TBD

Plans:
- [ ] 02-01: Signup flow (registration, HIBP check, zxcvbn, email verification)
- [ ] 02-02: Login, logout, and session cookie management
- [ ] 02-03: Auth frontend pages (signup.html, login.html, verify.html)

### Phase 3: Auth Hardening & Sessions
**Goal**: Account security features and session management are complete
**Depends on**: Phase 2
**Requirements**: AUTH-07, AUTH-09, AUTH-10, AUTH-11, SESS-04, SESS-05, SESS-06, FE-03, FE-07
**Success Criteria** (what must be TRUE):
  1. After 5 failed login attempts, the account is locked for 15 minutes (progressive: 10 -> 1hr, 20 -> 24hr)
  2. User can reset their password via a 6-digit email code, and all existing sessions are invalidated afterward
  3. User can change their password from settings (requires current password) and continue their session
  4. User can view active sessions (showing IP, user agent, created date) and revoke any individual session or all sessions
  5. Creating an 11th session auto-revokes the oldest session (max 10 active)
**Plans**: 3 plans

Plans:
- [x] 03-01: Progressive lockout and session limit enforcement (AUTH-07, SESS-04)
- [x] 03-02: Password reset/change flows and forgot-password page (AUTH-09, AUTH-10, AUTH-11, FE-03)
- [ ] 03-03: Session management UI and settings page (SESS-05, SESS-06, FE-07)

### Phase 4: API Keys
**Goal**: Users can create and manage API keys for programmatic access
**Depends on**: Phase 2
**Requirements**: KEY-01, KEY-03, KEY-05, KEY-06, KEY-07, FE-05
**Success Criteria** (what must be TRUE):
  1. User can create an API key with a custom label and sees the full key exactly once (with copy button and never-shown-again warning)
  2. User can list their keys showing prefix (sk_live_...), label, last used date, and status
  3. User can revoke a key and it immediately stops working for API calls
  4. Maximum 5 active keys per account is enforced; creating a 6th is rejected
**Plans**: TBD

Plans:
- [x] 04-01: API key CRUD routes (POST/GET/DELETE /auth/keys, session-protected, event logging)
- [x] 04-02: Key management page (/account/keys) with create, list, copy, revoke UI

### Phase 5: Stripe Billing
**Goal**: Users can purchase credits via Stripe Checkout with webhook-confirmed grants
**Depends on**: Phase 2
**Requirements**: BILL-01, BILL-02, BILL-03, BILL-04, BILL-05, INFRA-04, FE-06
**Success Criteria** (what must be TRUE):
  1. User can click a tier card ($5/$20/$50/$100) and complete purchase through Stripe Checkout
  2. Volume bonuses are applied correctly (0%/10%/20%/30% per tier) and shown before purchase
  3. Credits appear in the user's balance only after webhook confirmation (never on client redirect)
  4. Processing the same Stripe payment_intent twice does not double-grant credits
  5. Webhook signature is verified with timing-safe comparison and events older than 5 minutes are rejected
**Plans**: 3 plans

Plans:
- [x] 05-01: Stripe Checkout session creation and billing routes
- [x] 05-02: Webhook handler with idempotency and signature verification
- [x] 05-03: Billing page (/account/billing) with tier cards

### Phase 6: Credits & Account Dashboard
**Goal**: Users have full visibility into their credit balance, usage, and account status
**Depends on**: Phase 5
**Requirements**: BILL-07, BILL-08, BILL-09, FE-04
**Success Criteria** (what must be TRUE):
  1. User can view their credit balance prominently on the account overview page
  2. User can browse transaction history showing purchases, usage deductions, and timestamps
  3. User receives an email alert when credits drop below their configured threshold
  4. Account overview page shows balance, usage chart, quick-buy button, and active key count
**Plans**: 2 plans

Plans:
- [x] 06-01: Transaction history API, billing page extension, alert threshold migration
- [x] 06-02: Low-balance alert integration in deductAndRecord, account overview dashboard

### Phase 7: API Key Auth Middleware
**Goal**: All 21 APIs accept API key authentication as an alternative to x402, with atomic credit deduction
**Depends on**: Phase 4, Phase 6
**Requirements**: INT-01, INT-02, INT-03, INT-04, INT-05, INT-06, INT-07, INT-08, INFRA-03
**Success Criteria** (what must be TRUE):
  1. Sending Authorization: Bearer sk_live_... to any of the 21 APIs deducts credits and returns the response
  2. Sending a request with no Bearer header falls through to the existing x402 flow (zero breaking changes verified)
  3. Insufficient credits returns 402 with balance info; invalid/revoked key returns 401
  4. API responses include X-Credits-Remaining header when authenticated via API key
  5. The middleware is inserted at one place in the router (not 21 separate insertions)
**Plans**: 3 plans

Plans:
- [x] 07-01: API key auth middleware module and x402 payment bypass (shared/api-key-auth.ts, shared/x402.ts)
- [x] 07-02: Router integration and request logging (apis/router.ts, shared/db.ts)
- [x] 07-03: Caddy route configuration for auth/account/billing paths (caddy/Caddyfile)

### Phase 8: MCP & Landing Page
**Goal**: MCP server supports API key auth and landing page drives signups
**Depends on**: Phase 7
**Requirements**: MCP-01, MCP-02, MCP-03, FE-10
**Success Criteria** (what must be TRUE):
  1. Setting APIMESH_API_KEY env var causes the MCP server to pass it as Authorization: Bearer on all API calls
  2. MCP server without APIMESH_API_KEY continues to work via x402/free previews (no regression)
  3. Landing page at apimesh.xyz has a visible "Sign Up" CTA that links to /signup
**Plans**: 2 plans

Plans:
- [x] 08-01: MCP server API key support (APIMESH_API_KEY env var, callApi() header injection, version bump to 1.5.0)
- [x] 08-02: Landing page update with signup CTA (nav links, hero button, copy reframing)

### Phase 9: Bug Fixes & Code Gaps
**Goal**: Fix all code and config bugs identified in milestone audit
**Depends on**: Phase 7
**Requirements**: SESS-02, INT-08, INFRA-04
**Gap Closure:** Closes gaps from v1.0 audit
**Success Criteria** (what must be TRUE):
  1. `/auth/verify` auto-login cookie uses `sameSite: "Strict"` and `maxAge: 30 * 24 * 60 * 60` (matching `/auth/login`)
  2. API key calls populate `requests.user_id` and `requests.api_key_id` columns (no longer NULL)
  3. Caddy has a dedicated `handle /billing/webhook` block before `@auth_paths` with no CSP headers
**Plans**: TBD

Plans:
- [x] 09-01: Fix SESS-02 cookie bug, INT-08 request logging, INFRA-04 Caddy webhook block

### Phase 10: Verification & Traceability
**Goal**: Create VERIFICATION.md for unverified phases and update all traceability checkboxes
**Depends on**: Phase 9
**Requirements**: BILL-01, BILL-02, BILL-03, BILL-04, BILL-05, FE-06, KEY-01, KEY-03, KEY-05, KEY-06, KEY-07, FE-05, INT-01, INT-02, INT-03, INT-04, INT-05, INT-06, INT-07, SESS-01, SESS-07, KEY-02, KEY-04, BILL-06, INFRA-01, INFRA-02, INFRA-03, INFRA-06
**Gap Closure:** Closes gaps from v1.0 audit
**Success Criteria** (what must be TRUE):
  1. Phases 1, 4, 5, 7 each have a VERIFICATION.md confirming requirements satisfied
  2. Phase 5 summaries have YAML frontmatter with `requirements-completed` field
  3. All 61 requirements in REQUIREMENTS.md have correct checkbox status
  4. All ROADMAP.md phase checkboxes reflect actual completion status
**Plans**: TBD

Plans:
- [ ] 10-01: Verify phases 1, 4, 5, 7 and update all traceability

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10
Note: Phases 3, 4, and 5 all depend on Phase 2 but are independent of each other.
Phase 9 fixes code bugs from audit. Phase 10 creates verification artifacts and updates traceability.

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation | 3/3 | Complete | 2026-03-16 |
| 2. Signup & Login | 3/3 | Complete   | 2026-03-17 |
| 3. Auth Hardening & Sessions | 3/3 | Complete   | 2026-03-17 |
| 4. API Keys | 2/2 | Complete | 2026-03-18 |
| 5. Stripe Billing | 3/3 | Complete | 2026-03-18 |
| 6. Credits & Account Dashboard | 2/2 | Complete | 2026-03-18 |
| 7. API Key Auth Middleware | 3/3 | Complete | 2026-03-18 |
| 8. MCP & Landing Page | 2/2 | Complete | 2026-03-18 |
| 9. Bug Fixes & Code Gaps | 1/1 | Complete | 2026-03-23 |
| 10. Verification & Traceability | 0/1 | Not started | - |
