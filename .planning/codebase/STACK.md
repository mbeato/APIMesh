# Technology Stack

**Analysis Date:** 2026-03-15

## Languages

**Primary:**
- TypeScript 5.x - All server-side code (`apis/`, `shared/`, `mcp-server/`, `scripts/`)

**Secondary:**
- HTML/JavaScript - Frontend dashboard and landing page (`apis/dashboard/dashboard.html`, `apis/dashboard/dashboard.js`, `apis/landing/landing.html`, `apis/landing/landing.js`)

## Runtime

**Environment:**
- Bun (latest) - Primary runtime. All files run with `bun <file>`. No Node.js.

**Package Manager:**
- Bun (built-in). Lockfile: `bun.lock` (present and committed).

## Frameworks

**Core:**
- Hono 4.12.3 - HTTP framework for all API handlers. Used via `Hono` class from `hono`, middleware from `hono/cors` and `hono/bearer-auth`.

**Testing:**
- `bun test` - No dedicated test framework beyond Bun's built-in test runner. No test files currently present in codebase.

**Build/Dev:**
- No build step. Bun runs TypeScript directly (`bun <file.ts>`).
- TypeScript config: `tsconfig.json` — strict mode, ESNext target, bundler module resolution, `noEmit: true`.

## Key Dependencies

**Critical:**
- `hono` 4.12.3 - HTTP routing and middleware for all 21 API services
- `@x402/hono` 2.5.0 - x402 payment middleware for Hono (`paymentMiddleware`, `x402ResourceServer`)
- `@x402/evm` 2.5.0 - EVM payment scheme implementation (`ExactEvmScheme`)
- `@x402/core` 2.5.0 - x402 facilitator client (`HTTPFacilitatorClient`)
- `@x402/extensions` 2.5.0 - x402 discovery protocol (`declareDiscoveryExtension`)
- `@coinbase/cdp-sdk` 1.44.1 - Coinbase Developer Platform SDK for mainnet facilitator JWT auth
- `@modelcontextprotocol/sdk` 1.27.1 - MCP server SDK (used in `mcp-server/`)
- `cheerio` 1.2.0 - HTML parsing for web-analysis APIs (used in `apis/seo-audit/`, `apis/brand-assets/`, `apis/tech-stack/`, etc.)

**Infrastructure:**
- `bun:sqlite` (built-in) - SQLite database accessed via `Database` from `bun:sqlite`. Client in `shared/db.ts`.
- `zod` 3.24.0 - Input validation in `mcp-server/server.ts`

## Configuration

**TypeScript:**
- `tsconfig.json` - strict, ESNext, bundler module resolution, no emit, react-jsx

**Reverse Proxy:**
- `caddy/Caddyfile` - Caddy handles TLS, subdomain routing, and security headers
  - `apimesh.xyz` → `localhost:3000` (dashboard/landing)
  - `*.apimesh.xyz` → `localhost:3001` (API router)
  - `mcp.apimesh.xyz` → `localhost:3002` (MCP HTTP transport)
  - Wildcard TLS via Cloudflare DNS challenge (`CF_API_TOKEN`)

**Environment (runtime, loaded automatically by Bun):**
- `.env` file at `/opt/conway-agent/.env` on server (not committed, `chmod 600`)
- Key vars: `WALLET_ADDRESS`, `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET`, `DASHBOARD_TOKEN`, `PSI_API_KEY`, `CF_API_TOKEN`, `CORS_ORIGIN`

**Build:**
- No build step. Bun runs `.ts` files directly in production.

## Port Layout

- `3000` - Dashboard + landing page (`apis/dashboard/index.ts`)
- `3001` - API router (all 21 APIs by subdomain) (`apis/router.ts`)
- `3002` - MCP HTTP server (if running HTTP transport)

## Platform Requirements

**Development:**
- Bun runtime
- TypeScript 5.x (peer dependency)

**Production:**
- Hetzner CAX11 (ARM64, Ubuntu 24.04) — 2 vCPU, 4GB RAM
- Caddy with `caddy-dns/cloudflare` plugin for wildcard TLS
- Bun as process runtime (no PM2, no Docker — direct process management)
- Data persisted to `data/agent.db` (SQLite WAL mode)

---

*Stack analysis: 2026-03-15*
