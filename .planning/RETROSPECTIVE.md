# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v1.0 — Stripe Billing & User Accounts

**Shipped:** 2026-03-26
**Phases:** 12 | **Plans:** 29

### What Was Built
- Full auth system (signup, email verification, login, lockout, password reset/change, session management)
- API key management with SHA-256 hash-only storage and per-key usage tracking
- Stripe Checkout credit purchases at 4 tiers with webhook-confirmed idempotent grants
- Dual payment middleware — API key auth alongside x402 across all 21 APIs
- Account dashboard (balance, transactions, keys, sessions, billing, settings)
- MCP server v1.5.0 with API key support

### What Worked
- Single-point middleware insertion pattern — one apiKeyAuth() call in router catch-all covers all 21 APIs without touching individual API files
- Dependency chain planning — putting INFRA-06 (Resend domain verification) in Phase 1 gave DNS propagation time before Phase 2 needed email
- Phases 3/4/5 parallelizable after Phase 2 — good dependency analysis reduced critical path
- Server-rendered HTML + vanilla JS — fast to build, no framework overhead, matches existing pattern
- SQLite for everything (sessions, rate limiters, credits) — single data store, atomic transactions, no external dependencies
- Milestone audit before completion caught real issues (SESS-02 cookie, INT-08 logging, verification doc errors)

### What Was Inefficient
- Phases 9-12 were remediation/verification work discovered late — earlier verification during execution would have caught issues sooner
- Phase 1 plan summaries lacked YAML frontmatter — had to backfill in Phase 12
- SESS-02 requirement specified SameSite=Strict but SameSite=Lax was architecturally correct (Stripe redirect) — requirement was wrong, not the code
- Revenue analytics join complexity — revenue table lacks user_id/api_key_id columns, requiring join through credit_transactions

### Patterns Established
- Internal headers (X-APIMesh-User-Id, Key-Id, Paid) for propagating auth context through middleware chain
- Constant-time anti-enumeration on all auth endpoints (pre-computed dummy hash, generic error messages)
- HMAC-SHA256 for short-lived verification codes (fast, secret-keyed, sufficient for 6-digit codes)
- SQLite-backed rate limiters that survive process restarts
- Webhook-first payment confirmation (never trust client redirect)

### Key Lessons
1. Run milestone audit earlier — verification phases (9-12) added 4 phases of cleanup that could have been caught during execution
2. Requirements should account for cross-feature interactions — SESS-02 (SameSite=Strict) conflicted with BILL-01 (Stripe Checkout redirect)
3. YAML frontmatter in SUMMARY files should be enforced from Phase 1 — backfilling is tedious
4. Single-point middleware insertion is worth the design effort — touching 21 files vs 1 is a massive maintenance win

### Cost Observations
- Timeline: 26 days for 12 phases, 29 plans
- Phases 1-8 (core build): 3 days
- Phases 9-12 (verification/cleanup): 8 days
- Notable: Core implementation was fast; verification and audit remediation took longer than building

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Phases | Plans | Key Change |
|-----------|--------|-------|------------|
| v1.0 | 12 | 29 | First milestone — established audit-before-complete pattern |

### Top Lessons (Verified Across Milestones)

1. Run verification continuously, not as a separate phase at the end
2. Requirements must account for cross-feature interactions (auth + billing)
