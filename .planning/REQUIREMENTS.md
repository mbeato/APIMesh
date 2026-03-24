# Requirements: APIMesh Stripe Billing & User Accounts

**Defined:** 2026-03-15
**Core Value:** Developers and AI agents can access web analysis APIs through a single account with one credit pool, paying with credit card or crypto.

## v1 Requirements

### Authentication

- [x] **AUTH-01**: User can sign up with email and password (Argon2id, min 12 chars, zxcvbn >= 3)
- [x] **AUTH-02**: User password is checked against HaveIBeenPwned at signup (k-anonymity)
- [x] **AUTH-03**: User receives 6-digit verification code via email after signup
- [x] **AUTH-04**: User can verify email by entering 6-digit code (expires 10min, 3 attempts max)
- [x] **AUTH-05**: User can resend verification code (1 per 60s per email, 5 per IP per hour)
- [x] **AUTH-06**: User can log in with email and password (constant-time, no email enumeration)
- [x] **AUTH-07**: Failed logins trigger progressive lockout (5 -> 15min, 10 -> 1hr, 20 -> 24hr)
- [x] **AUTH-08**: User can log out and have session destroyed
- [x] **AUTH-09**: User can request password reset via 6-digit email code
- [x] **AUTH-10**: Password reset invalidates all existing sessions
- [x] **AUTH-11**: User can change password from settings (current + new required)

### Sessions

- [x] **SESS-01**: Sessions stored server-side in SQLite with crypto-random 256-bit IDs
- [x] **SESS-02**: Session cookie is httpOnly, Secure, SameSite=Strict, 30-day expiry
- [x] **SESS-03**: Session expiry uses sliding window (refreshed on each authenticated request)
- [x] **SESS-04**: Maximum 10 active sessions per user (oldest auto-revoked on new login)
- [x] **SESS-05**: User can view active sessions (IP, user agent, created date)
- [x] **SESS-06**: User can revoke individual sessions or all sessions
- [x] **SESS-07**: All auth events logged to audit table (signup, login, failed, logout, password change/reset, key create/revoke)

### API Keys

- [ ] **KEY-01**: User can create API keys with custom labels (max 5 active per account)
- [x] **KEY-02**: API key format is sk_live_ + 32 bytes hex (256-bit entropy)
- [ ] **KEY-03**: API key shown exactly once at creation with copy button and warning
- [x] **KEY-04**: API keys stored as SHA-256 hash only (plaintext never persisted)
- [ ] **KEY-05**: User can list keys showing prefix, label, last used, status
- [ ] **KEY-06**: User can revoke keys (soft delete, preserves audit trail)
- [ ] **KEY-07**: Per-key last_used_at tracking updated on each API call

### Credits & Billing

- [x] **BILL-01**: User can purchase credits via Stripe Checkout at 4 tiers ($5/$20/$50/$100)
- [x] **BILL-02**: Volume bonuses applied: 0%/10%/20%/30% per tier
- [x] **BILL-03**: Credits granted only on Stripe webhook confirmation (never on client redirect)
- [x] **BILL-04**: Webhook handler is idempotent (UNIQUE constraint on stripe_payment_intent)
- [x] **BILL-05**: Webhook signature verified with timing-safe comparison, reject events >5min old
- [x] **BILL-06**: Credit balance stored in integer microdollars (no floating point)
- [x] **BILL-07**: User can view transaction history (purchases, usage, refunds) in dashboard
- [x] **BILL-08**: User receives email alert when credits drop below configurable threshold
- [x] **BILL-09**: Credit balance visible in account overview dashboard

### API Key Auth Integration

- [x] **INT-01**: APIs accept Authorization: Bearer sk_live_... as alternative to x402 payment
- [x] **INT-02**: API key auth middleware branches at router level (one place, all 21 APIs)
- [x] **INT-03**: Credit deduction is atomic (BEGIN IMMEDIATE + UPDATE WHERE balance_cents >= cost)
- [x] **INT-04**: Insufficient credits returns 402 with balance info
- [x] **INT-05**: Invalid or revoked key returns 401
- [x] **INT-06**: No Bearer header falls through to existing x402 flow (zero breaking changes)
- [x] **INT-07**: API responses include X-Credits-Remaining header for API key users
- [x] **INT-08**: API key usage logged in requests table (user_id + api_key_id columns)

### MCP Integration

- [x] **MCP-01**: MCP server reads APIMESH_API_KEY from environment variable
- [x] **MCP-02**: MCP server passes API key as Authorization: Bearer header on all API calls
- [x] **MCP-03**: MCP server works without API key (falls back to x402/free previews as today)

### Frontend

- [x] **FE-01**: Signup page at /signup with email + password form
- [x] **FE-02**: Login page at /login with email + password form
- [x] **FE-03**: Password reset page at /forgot-password
- [x] **FE-04**: Account overview at /account (balance, usage chart, quick buy, active keys)
- [ ] **FE-05**: API key management at /account/keys (create, list, revoke)
- [x] **FE-06**: Billing page at /account/billing (balance, tier cards, transaction history)
- [x] **FE-07**: Settings page at /account/settings (change password, active sessions, logout all)
- [x] **FE-08**: All account pages use server-rendered HTML + vanilla JS (no React)
- [x] **FE-09**: Design matches existing landing page (Space Grotesk, JetBrains Mono, dark theme)
- [x] **FE-10**: Landing page updated with "Sign Up" CTA and reframed copy

### Infrastructure

- [x] **INFRA-01**: Proper DB migration runner (replaces existing try/catch ALTER TABLE pattern)
- [x] **INFRA-02**: 7 new SQLite tables + 2 ALTER TABLE on requests + indexes
- [x] **INFRA-03**: Caddy route blocks for /auth/*, /account*, /billing/* with Cache-Control: no-store
- [x] **INFRA-04**: Webhook route with separate handler (no CSP, larger body limit)
- [x] **INFRA-05**: Auth-specific rate limiters separate from API rate limits
- [x] **INFRA-06**: Resend domain verification (SPF, DKIM, DMARC for apimesh.xyz)

## v2 Requirements

### Authentication Enhancements

- **AUTH-V2-01**: Two-factor authentication (TOTP)
- **AUTH-V2-02**: OAuth social login (Google, GitHub)
- **AUTH-V2-03**: Email change with re-verification
- **AUTH-V2-04**: Self-service account deletion

### Billing Enhancements

- **BILL-V2-01**: Subscription tiers with included calls + overage
- **BILL-V2-02**: Usage-based auto-top-up
- **BILL-V2-03**: Team accounts with shared credit pool
- **BILL-V2-04**: Invoice PDF generation

### Security Enhancements

- **SEC-V2-01**: CAPTCHA on signup (Cloudflare Turnstile)
- **SEC-V2-02**: IP allowlisting per API key
- **SEC-V2-03**: Admin impersonation for support

## Out of Scope

| Feature | Reason |
|---------|--------|
| OAuth / social login | Unnecessary complexity for v1, email+password sufficient |
| 2FA / TOTP | Meaningful security lift, defer to v2 |
| Subscriptions | Need usage patterns first, pre-paid credits simpler |
| CAPTCHA | Rate limits + email verification sufficient for launch |
| Mobile app | Web-first, responsive pages sufficient |
| Credit expiration | Recommend no expiration for v1 (research finding) |
| Refund self-service | Business decision, handle manually |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| AUTH-01 | Phase 2 | Complete |
| AUTH-02 | Phase 2 | Complete |
| AUTH-03 | Phase 2 | Complete |
| AUTH-04 | Phase 2 | Complete |
| AUTH-05 | Phase 2 | Complete |
| AUTH-06 | Phase 2 | Complete |
| AUTH-07 | Phase 3 | Complete |
| AUTH-08 | Phase 2 | Complete |
| AUTH-09 | Phase 3 | Complete |
| AUTH-10 | Phase 3 | Complete |
| AUTH-11 | Phase 3 | Complete |
| SESS-01 | Phase 1 | Complete |
| SESS-02 | Phase 9 | Complete |
| SESS-03 | Phase 2 | Complete |
| SESS-04 | Phase 3 | Complete |
| SESS-05 | Phase 3 | Complete |
| SESS-06 | Phase 3 | Complete |
| SESS-07 | Phase 1 | Complete |
| KEY-01 | Phase 4 | Pending |
| KEY-02 | Phase 1 | Complete |
| KEY-03 | Phase 4 | Pending |
| KEY-04 | Phase 1 | Complete |
| KEY-05 | Phase 4 | Pending |
| KEY-06 | Phase 4 | Pending |
| KEY-07 | Phase 4 | Pending |
| BILL-01 | Phase 5 | Complete |
| BILL-02 | Phase 5 | Complete |
| BILL-03 | Phase 5 | Complete |
| BILL-04 | Phase 5 | Complete |
| BILL-05 | Phase 5 | Complete |
| BILL-06 | Phase 1 | Complete |
| BILL-07 | Phase 6 | Complete |
| BILL-08 | Phase 6 | Complete |
| BILL-09 | Phase 6 | Complete |
| INT-01 | Phase 7 | Complete |
| INT-02 | Phase 7 | Complete |
| INT-03 | Phase 7 | Complete |
| INT-04 | Phase 7 | Complete |
| INT-05 | Phase 7 | Complete |
| INT-06 | Phase 7 | Complete |
| INT-07 | Phase 7 | Complete |
| INT-08 | Phase 9 | Complete |
| MCP-01 | Phase 8 | Complete |
| MCP-02 | Phase 8 | Complete |
| MCP-03 | Phase 8 | Complete |
| FE-01 | Phase 2 | Complete |
| FE-02 | Phase 2 | Complete |
| FE-03 | Phase 3 | Complete |
| FE-04 | Phase 6 | Complete |
| FE-05 | Phase 4 | Pending |
| FE-06 | Phase 5 | Complete |
| FE-07 | Phase 3 | Complete |
| FE-08 | Phase 2 | Complete |
| FE-09 | Phase 2 | Complete |
| FE-10 | Phase 8 | Complete |
| INFRA-01 | Phase 1 | Complete |
| INFRA-02 | Phase 1 | Complete |
| INFRA-03 | Phase 10 | Complete |
| INFRA-04 | Phase 9 | Complete |
| INFRA-05 | Phase 1 | Complete |
| INFRA-06 | Phase 1 | Complete |

**Coverage:**
- v1 requirements: 61 total
- Mapped to phases: 61
- Unmapped: 0

---
*Requirements defined: 2026-03-15*
*Last updated: 2026-03-15 after roadmap creation*
