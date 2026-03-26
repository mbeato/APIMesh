# External Integrations

**Analysis Date:** 2026-03-15

## APIs & External Services

**Blockchain / Payments:**
- x402 Protocol - Per-call USDC micropayment layer for all 21 paid API endpoints
  - SDK/Client: `@x402/hono`, `@x402/evm`, `@x402/core`, `@x402/extensions`
  - Implementation: `shared/x402.ts` — configures `resourceServer`, `paymentMiddleware`, `paidRoute()`
  - Mainnet: Base (chain ID `eip155:8453`) — requires CDP credentials
  - Testnet: Base Sepolia (`eip155:84532`) — uses public `https://www.x402.org/facilitator`

- Coinbase Developer Platform (CDP) - Mainnet x402 payment facilitation
  - SDK/Client: `@coinbase/cdp-sdk` (specifically `@coinbase/cdp-sdk/auth` for JWT generation)
  - Auth: `CDP_API_KEY_ID` + `CDP_API_KEY_SECRET` env vars
  - Endpoint: `https://api.cdp.coinbase.com/platform/v2/x402`
  - Configured in: `shared/x402.ts` (`buildCdpFacilitator()`)
  - Fallback: when both vars omitted, uses public testnet facilitator instead

**Web Analysis:**
- Google PageSpeed Insights API v5 - Core Web Vitals checks
  - Endpoint: `https://www.googleapis.com/pagespeedonline/v5/runPagespeed`
  - Auth: `PSI_API_KEY` env var (optional; works without key at lower quota)
  - Client: raw `fetch()` in `apis/core-web-vitals/analyzer.ts`
  - Timeout: 60 seconds (PSI is slow)

**DNS:**
- System DNS resolver - Used for MX record lookups in `apis/email-verify/checker.ts` and `apis/email-security/`
  - Client: Bun's built-in DNS resolution (no external SDK)

## Data Storage

**Databases:**
- SQLite via `bun:sqlite` (built-in, no external package)
  - File: `data/agent.db` (WAL mode, busy_timeout=5000ms, foreign_keys=ON)
  - Schema: `api_registry`, `requests`, `revenue`, `spend_caps`, `backlog` tables
  - Client module: `shared/db.ts` — exports all query functions
  - Persisted to `/opt/conway-agent/data/agent.db` on production server

**File Storage:**
- Local filesystem only
  - Static files: `public/` (llms.txt, `.well-known/x402`)
  - Dashboard HTML/JS: `apis/dashboard/dashboard.html`, `apis/dashboard/dashboard.js`
  - Landing HTML/JS: `apis/landing/landing.html`, `apis/landing/landing.js`
  - Read via `Bun.file()` in `apis/dashboard/index.ts`

**Caching:**
- In-memory only — rate limit buckets in `shared/rate-limit.ts` (Map-based, per-zone IP buckets, auto-cleanup every 60s)
- No Redis, no external cache

## Authentication & Identity

**Dashboard API:**
- Bearer token auth via `hono/bearer-auth`
- Token: `DASHBOARD_TOKEN` env var (minimum 32 characters)
- Applied to all `/api/*` routes in `apis/dashboard/index.ts`
- CORS restricted to `CORS_ORIGIN` env var (defaults to `https://apimesh.xyz`)

**x402 Payment Identity:**
- Payer wallet extracted from `X-PAYMENT` header post-settlement
- Middleware: `shared/x402-wallet.ts` (`extractPayerWallet()`)
- EVM address (`0x...`) stored as `payer_wallet` in `requests` and `revenue` tables

**User Auth (Phase 01 — Foundation):**
- Argon2id password hashing via `shared/auth.ts`
- 256-bit session tokens, SHA-256 hashed in DB
- Auth event logging (login, register, password reset)
- Auth rate limiting via `shared/auth-rate-limit.ts` (login: 5/15min, register: 3/hr, reset: 3/hr per IP)

**Transactional Email:**
- Resend — verification emails, password resets
  - SDK/Client: `resend` npm package
  - Auth: `RESEND_API_KEY` env var (required in production)
  - Implementation: `shared/email.ts`
  - Domain: `apimesh.xyz` (requires DNS verification in Resend dashboard)

## Monitoring & Observability

**Error Tracking:**
- None (no Sentry, Datadog, etc.)

**Logs:**
- `console.log` / `console.error` to stdout/stderr only
- Request logging to SQLite via `apiLogger()` middleware in `shared/logger.ts`
- Revenue logging to SQLite on successful x402 settlement
- Log sanitization: control characters stripped, fields capped at 512 chars (`sanitizeLogField()`)

**Dashboard Metrics:**
- Self-hosted analytics via SQLite queries in `apis/dashboard/index.ts`
- Endpoints: `/api/stats`, `/api/audit-log`, `/api/wallets`, `/api/spend-caps`
- Charts: daily revenue (7d/30d), daily requests, hourly requests

## CI/CD & Deployment

**Hosting:**
- Hetzner CAX11 ARM64 VPS (Ubuntu 24.04)
- Deploy script: `scripts/deploy.sh` (local only, not committed)
- Process: direct `bun` invocation (no container, no PM2)
- Server path: `/opt/conway-agent/`

**TLS / DNS:**
- Caddy with `caddy-dns/cloudflare` plugin for automatic wildcard TLS (`*.apimesh.xyz`)
- Cloudflare DNS challenge: `CF_API_TOKEN` env var (set in Caddy environment)
- Config: `caddy/Caddyfile`

**CI Pipeline:**
- None (no GitHub Actions, no automated tests)

## MCP Distribution

**npm Package:**
- `@mbeato/apimesh-mcp-server` v1.4.0 — published to npm
- Entry: `mcp-server/index.ts` (stdio transport)
- Consumers install with: `npx @mbeato/apimesh-mcp-server`
- Registered on: MCP Registry (`io.github.mbeato/apimesh`), Smithery, Glama.ai, mcp.so, PulseMCP

**MCP Registry Config:**
- `mcp-server/server.json` — MCP Registry schema metadata
- `glama.json` — Glama.ai maintainer registration

## Webhooks & Callbacks

**Incoming:**
- None — no inbound webhooks

**Outgoing:**
- x402 settlement calls to facilitator (`https://api.cdp.coinbase.com/platform/v2/x402` or `https://www.x402.org/facilitator`) — triggered per paid API call

## x402 Discovery

**Well-Known:**
- `public/.well-known/x402` — static JSON listing all 21 paid resource URLs
- Served at `https://apimesh.xyz/.well-known/x402`
- Per-subdomain discovery via `GET /.well-known/x402` on each API subdomain (handled in `apis/router.ts`)

**AI Documentation:**
- `public/llms.txt` — machine-readable API docs for LLM consumption
- Served at `https://apimesh.xyz/llms.txt`

## Environment Configuration

**Required env vars:**
- `WALLET_ADDRESS` - EVM address to receive USDC payments (e.g. `0x...`)
- `DASHBOARD_TOKEN` - Bearer token for dashboard API (min 32 chars)
- `CF_API_TOKEN` - Cloudflare API token for Caddy wildcard TLS DNS challenge
- `RESEND_API_KEY` - Resend API key for transactional email (required in production)

**Optional env vars:**
- `CDP_API_KEY_ID` + `CDP_API_KEY_SECRET` - Coinbase CDP credentials (both required together for mainnet; omit both for testnet)
- `PSI_API_KEY` - Google PageSpeed Insights API key (raises quota limit; works without it)
- `CORS_ORIGIN` - Dashboard CORS origin (defaults to `https://apimesh.xyz`)

**Secrets location:**
- `/opt/conway-agent/.env` on production server (`chmod 600`, never committed to git)

---

*Integration audit: 2026-03-15*
