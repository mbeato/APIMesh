# APIMesh

## What This Is

APIMesh is a suite of 21 web analysis APIs (SEO, security headers, Core Web Vitals, tech stack detection, email verification, etc.) with a 16-tool MCP server for AI agents. Monetized via dual payment paths: pre-paid credit card billing through Stripe and per-request crypto payments via x402 (USDC on Base).

## Core Value

Developers and AI agents can access a unified suite of web analysis APIs through a single account with one credit pool, paying with either credit card or crypto — whichever they prefer.

## Current State

**Shipped:** v1.0 Stripe Billing & User Accounts (2026-03-26)

- Full auth system with Argon2id, HIBP breach check, email verification, progressive lockout
- API key management with SHA-256 hash-only storage and per-key usage tracking
- Stripe Checkout credit purchases at 4 tiers with volume bonuses
- Dual payment middleware across all 21 APIs (API key + x402, zero breaking changes)
- Account dashboard with balance, transaction history, key management, session management
- MCP server v1.5.0 with API key support

**Stack:** Bun, Hono, SQLite (WAL mode), Caddy reverse proxy
**Codebase:** ~164K TypeScript, 166 files
**npm:** @mbeato/apimesh-mcp-server (v1.5.0)
**Site:** apimesh.xyz

## Requirements

### Validated

- ✓ User accounts with email + password (Argon2id) — v1.0
- ✓ Email verification via 6-digit code (Resend) — v1.0
- ✓ Server-side sessions in SQLite (httpOnly Secure cookies) — v1.0
- ✓ Password reset flow with session invalidation — v1.0
- ✓ Multiple API keys per account with labels — v1.0
- ✓ API key auth as alternative payment path (alongside x402) — v1.0
- ✓ Pre-paid credit system with unified pool (human + agent) — v1.0
- ✓ Stripe Checkout for credit purchases ($5/$20/$50/$100 tiers) — v1.0
- ✓ Webhook-confirmed credit grants (idempotent) — v1.0
- ✓ Credit deduction per API call (atomic SQLite transactions) — v1.0
- ✓ Account dashboard (balance, keys, billing, settings) — v1.0
- ✓ MCP server support for API key auth (APIMESH_API_KEY env var) — v1.0
- ✓ Security hardening (progressive lockout, constant-time, HIBP check, auth event logging) — v1.0
- ✓ Landing page update (reframe as "Web Analysis API Suite", add signup CTA) — v1.0
- ✓ 21 web analysis APIs operational on subdomains — pre-existing
- ✓ x402 payment protocol working on all endpoints — pre-existing
- ✓ MCP server with 16 tools published on npm — pre-existing
- ✓ Free preview endpoints on all APIs — pre-existing
- ✓ Per-wallet spend caps and audit logging — pre-existing
- ✓ Admin dashboard with analytics — pre-existing
- ✓ Rate limiting per IP per zone — pre-existing
- ✓ SSRF protection on URL-fetching APIs — pre-existing

### Active

(Next milestone — define with `/gsd:new-milestone`)

### Out of Scope

- OAuth / social login — unnecessary complexity, email+password sufficient
- 2FA / TOTP — meaningful security lift, add when needed
- Email change — complex re-verification flow, handle manually
- Account deletion — handle manually, add self-service later
- Subscriptions — add after understanding usage patterns
- CAPTCHA — rate limits + email verification sufficient
- Credit expiration — no expiration (research-backed decision)
- Mobile app — web-first, responsive pages sufficient

## Constraints

- **Tech stack**: Bun, Hono, SQLite — consistent with existing codebase
- **Zero breaking changes**: x402 flow must remain fully functional
- **Minimal deps**: Only zxcvbn added — everything else via Bun built-ins + fetch()
- **No Stripe SDK**: All Stripe interaction via fetch()
- **No React**: Account pages use server-rendered HTML + vanilla JS
- **Security**: OWASP best practices throughout

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Argon2id over bcrypt | OWASP recommendation, Bun native support, memory-hard | ✓ Good |
| Server-side sessions over JWT | Instant revocation, no token refresh complexity | ✓ Good |
| Pre-paid credits over subscriptions | Simpler, no failed payment headaches, matches pay-per-call | ✓ Good |
| 6-digit code over magic link | Simpler, no redirect URLs, harder to phish | ✓ Good |
| Resend over SES | Developer-friendly, free tier sufficient | ✓ Good |
| Multiple API keys per account | Minimal extra work, enables per-key tracking | ✓ Good |
| Unified credit pool (human + agent) | Strong differentiator, clean MCP story | ✓ Good |
| No Stripe SDK | Keeps deps minimal, all Stripe ops are simple REST | ✓ Good |
| SameSite=Lax over Strict | Required for Stripe Checkout redirect back to /account/billing | ✓ Good |
| SQLite-backed rate limiters | Survives process restarts (vs in-memory Map) | ✓ Good |
| Single-point middleware insertion | One apiKeyAuth() call in router catch-all covers all 21 APIs | ✓ Good |
| Internal headers for user attribution | X-APIMesh-User-Id/Key-Id propagate auth context to logger | ✓ Good |

---
*Last updated: 2026-03-26 after v1.0 milestone*
