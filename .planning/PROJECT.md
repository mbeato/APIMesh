# APIMesh — Stripe Billing & User Accounts

## What This Is

APIMesh is a suite of 21 x402-payable web analysis APIs (SEO, security headers, Core Web Vitals, tech stack detection, etc.) plus a 16-tool MCP server for AI agents. Currently monetized only via x402 crypto payments (USDC on Base). This milestone adds traditional Stripe billing — user accounts, API keys, and pre-paid credits — alongside the existing x402 flow, opening the product to developers who pay with credit cards.

## Core Value

Developers and AI agents can access a unified suite of web analysis APIs through a single account with one credit pool, paying with either credit card or crypto — whichever they prefer.

## Requirements

### Validated

- ✓ 21 web analysis APIs operational on subdomains — existing
- ✓ x402 payment protocol working on all endpoints — existing
- ✓ MCP server with 16 tools published on npm — existing
- ✓ Free preview endpoints on all APIs — existing
- ✓ Per-wallet spend caps and audit logging — existing
- ✓ Admin dashboard with analytics — existing
- ✓ Landing page at apimesh.xyz — existing
- ✓ Rate limiting per IP per zone — existing
- ✓ SSRF protection on URL-fetching APIs — existing

### Active

- [ ] User accounts with email + password (Argon2id)
- [ ] Email verification via 6-digit code (Resend)
- [ ] Server-side sessions in SQLite (httpOnly Secure SameSite=Strict cookies)
- [ ] Password reset flow with session invalidation
- [ ] Multiple API keys per account with labels
- [ ] API key auth as alternative payment path (alongside x402)
- [ ] Pre-paid credit system with unified pool (human + agent)
- [ ] Stripe Checkout for credit purchases ($5/$20/$50/$100 tiers)
- [ ] Webhook-confirmed credit grants (idempotent)
- [ ] Credit deduction per API call (atomic SQLite transactions)
- [ ] Account dashboard (balance, keys, billing, settings)
- [ ] MCP server support for API key auth (APIMESH_API_KEY env var)
- [ ] Security hardening (progressive lockout, constant-time, HIBP check, auth event logging)
- [ ] Landing page update (reframe as "Web Analysis API Suite", add signup CTA)

### Out of Scope

- OAuth / social login — unnecessary complexity for v1, email+password sufficient
- 2FA / TOTP — meaningful security lift, add in v2
- Email change — complex re-verification flow, handle manually for now
- Account deletion — handle manually, add self-service later
- Subscriptions — add after understanding usage patterns, pre-paid credits first
- CAPTCHA — rate limits + email verification sufficient, add if abuse detected
- Admin impersonation — not needed for solo operator
- IP allowlisting per API key — enterprise feature, defer

## Context

- Stack: Bun, Hono, SQLite (WAL mode), Caddy reverse proxy
- Current identity model is stateless — wallets (0x addresses) are identity, no user accounts
- Payment: x402 protocol via Coinbase CDP facilitator, USDC on Base
- Public wallet endpoints exist (no auth) — anyone can query/set spend caps
- Each API is an independent Hono app, routed by subdomain via registry
- MCP server currently calls public API endpoints with no auth
- The design doc with full schema, flows, middleware, and testing strategy is at `docs/plans/2026-03-15-stripe-billing-design.md`
- Feedback from Reddit and x402 community: tools are valuable, but x402-only monetization is too high friction

## Constraints

- **Tech stack**: Must use Bun, Hono, SQLite — consistent with existing codebase
- **Zero breaking changes**: x402 flow must remain fully functional
- **Single dependency**: Only zxcvbn added — everything else via Bun built-ins + fetch()
- **No Stripe SDK**: All Stripe interaction via fetch() to keep deps minimal
- **No React**: Account pages use server-rendered HTML + vanilla JS (matches existing pattern)
- **Security**: OWASP best practices — Argon2id, constant-time responses, no email enumeration, append-only ledger

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Argon2id over bcrypt | OWASP recommendation, Bun native support, memory-hard | — Pending |
| Server-side sessions over JWT | Instant revocation, no token refresh complexity, SQLite already in use | — Pending |
| Pre-paid credits over subscriptions | Simpler to build, no failed payment headaches, matches pay-per-call model | — Pending |
| 6-digit code over magic link | Simpler to implement, no redirect URLs, harder to phish | — Pending |
| Resend over SES | Developer-friendly, free tier sufficient, single fetch() call | — Pending |
| Multiple API keys per account | Minimal extra work, developers expect it, enables per-key usage tracking | — Pending |
| Unified credit pool (human + agent) | Strong differentiator, clean MCP story, no split wallet confusion | — Pending |
| No Stripe SDK | Keep deps minimal, all Stripe ops are simple REST calls | — Pending |

---
*Last updated: 2026-03-15 after initialization*
