# Milestones

## v1.0 Stripe Billing & User Accounts (Shipped: 2026-03-26)

**Phases:** 12 | **Plans:** 29 | **Tasks:** 61
**Timeline:** 26 days (2026-02-28 → 2026-03-26)
**Commits:** 123 | **LOC added:** ~29K

**Delivered:** Traditional Stripe billing alongside x402 crypto payments — user accounts, API keys, and pre-paid credits for all 21 web analysis APIs and 16-tool MCP server.

**Key accomplishments:**

1. Full auth system — Argon2id passwords, HIBP breach check, email verification, progressive lockout, constant-time anti-enumeration
2. Session management — server-side SQLite sessions, 30-day sliding window, max 10 per user, individual/bulk revocation
3. API key system — SHA-256 hash-only storage, per-key usage tracking, max 5 active per account
4. Stripe billing — 4-tier credit purchases ($5/$20/$50/$100) with volume bonuses, webhook-confirmed idempotent grants
5. Dual payment middleware — single-point API key auth insertion across all 21 APIs, zero breaking changes to x402 flow
6. MCP server v1.5.0 — APIMESH_API_KEY env var for agent auth with full backward compatibility

**Tech debt carried forward:**
- Revenue table lacks user_id/api_key_id columns (per-user revenue requires join through credit_transactions)
- Phase 1 plan summaries lack requirements-completed YAML frontmatter (verified satisfied in 01-VERIFICATION.md)

**Archives:** [ROADMAP](milestones/v1.0-ROADMAP.md) | [REQUIREMENTS](milestones/v1.0-REQUIREMENTS.md) | [AUDIT](milestones/v1.0-MILESTONE-AUDIT.md)

---
