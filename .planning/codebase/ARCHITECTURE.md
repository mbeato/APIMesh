# Architecture

**Analysis Date:** 2026-03-15

## Pattern Overview

**Overall:** Subdomain-routed microservice monorepo with x402 payment middleware

**Key Characteristics:**
- Single Bun process per service, all bound to `127.0.0.1`; Caddy terminates TLS and reverse-proxies
- Every paid API is a self-contained Hono app exported from `apis/{name}/index.ts`
- A central router (`apis/router.ts`) dispatches requests by subdomain using a static registry (`apis/registry.ts`)
- Shared middleware stack (rate limiting, SSRF protection, wallet extraction, spend-cap enforcement, logging) is consumed identically by every API
- Payment is enforced at the route level via `@x402/hono`'s `paymentMiddleware` — unpaid requests receive HTTP 402 with payment details

## Layers

**Reverse Proxy (Caddy):**
- Purpose: TLS termination, subdomain routing, request body size limits, `X-Real-IP` injection
- Location: `caddy/Caddyfile`
- Contains: Virtual host blocks for `apimesh.xyz`, `mcp.apimesh.xyz`, `*.apimesh.xyz`
- Depends on: Nothing upstream
- Used by: All public traffic

**API Router:**
- Purpose: Dispatch inbound requests to the correct Hono sub-app by subdomain
- Location: `apis/router.ts`
- Contains: Subdomain extraction, `.well-known/x402` discovery per subdomain, catch-all `subApp.fetch(req)`
- Depends on: `apis/registry.ts`
- Used by: Caddy (`*.apimesh.xyz` → `localhost:3001`)

**API Registry:**
- Purpose: Static map of subdomain string → Hono app instance
- Location: `apis/registry.ts`
- Contains: Named imports of every API module, `Record<string, Hono>` export
- Depends on: All `apis/*/index.ts` modules
- Used by: `apis/router.ts`

**Individual API Modules:**
- Purpose: Implement one paid (and optionally free preview) endpoint per subdomain
- Location: `apis/{api-name}/index.ts` (entry), `apis/{api-name}/{logic}.ts` (implementation)
- Contains: Hono app with middleware stack, `/preview` free route, `/check` (or `/analyze`, `/generate`, `/validate`) paid route
- Depends on: `shared/*` middleware, local `{logic}.ts` file
- Used by: `apis/registry.ts`

**Shared Middleware:**
- Purpose: Cross-cutting concerns reused by every API
- Location: `shared/`
- Contains: `x402.ts` (payment config), `logger.ts` (request+revenue logging), `rate-limit.ts` (in-process token bucket), `ssrf.ts` (URL validation + safe fetch), `x402-wallet.ts` (payer wallet extraction), `spend-cap.ts` (per-wallet daily/monthly limits), `db.ts` (SQLite singleton + all query functions), `mcp.ts` (JSON-RPC client for brain automation)
- Depends on: `bun:sqlite`, `@x402/hono`, `@x402/evm`, `@coinbase/cdp-sdk`
- Used by: All API modules, `apis/dashboard/index.ts`

**Dashboard:**
- Purpose: Admin UI + REST API for metrics, audit logs, spend caps, wallet summaries; also serves landing page
- Location: `apis/dashboard/index.ts`, `apis/dashboard/dashboard.html`, `apis/dashboard/dashboard.js`
- Contains: Bearer-auth protected `/api/*` routes, public `/wallet/:address` routes, static file serving for HTML/JS
- Depends on: `shared/db.ts`, `shared/x402.ts`, `shared/rate-limit.ts`
- Used by: Caddy (`apimesh.xyz` → `localhost:3000`)

**MCP Server:**
- Purpose: Expose all 21 APIs as MCP tools for use by LLM clients
- Location: `mcp-server/server.ts` (tool definitions), `mcp-server/index.ts` (stdio transport), `mcp-server/http.ts` (HTTP/SSE transport on `localhost:3002`)
- Contains: One MCP tool per API, wallet management tools (`wallet_usage`, `wallet_set_cap`)
- Depends on: `@modelcontextprotocol/sdk`, fetches API endpoints over HTTP
- Used by: Caddy (`mcp.apimesh.xyz` → `localhost:3002`), stdio clients

**Brain (Automation):**
- Purpose: Autonomous loop that monitors revenue, scouts new API ideas, builds new APIs, and registers them
- Location: `scripts/brain/index.ts`, `scripts/brain/monitor.ts`, `scripts/brain/scout.ts`, `scripts/brain/build.ts`, `scripts/brain/list.ts`, `scripts/brain/prune.ts`
- Contains: Orchestration across 5 steps (monitor → scout → build → list → prune)
- Depends on: `shared/mcp.ts` (calls `conway-terminal` MCP server), `shared/db.ts`
- Used by: Cron / manual invocation

**Data Layer:**
- Purpose: Persistent storage for requests, revenue, API registry, spend caps, backlog
- Location: `shared/db.ts` (all queries), `data/agent.db` (SQLite file)
- Contains: Tables `requests`, `revenue`, `api_registry`, `spend_caps`, `backlog`; typed query functions
- Depends on: `bun:sqlite`
- Used by: `shared/logger.ts`, `apis/dashboard/index.ts`, `shared/spend-cap.ts`, `scripts/brain/*`

## Data Flow

**Paid API Request:**

1. Client sends `GET *.apimesh.xyz/check` with `X-PAYMENT` header
2. Caddy terminates TLS, injects `X-Real-IP`, forwards to `localhost:3001`
3. `apis/router.ts` extracts subdomain, looks up `registry[subdomain]`, calls `subApp.fetch(req)`
4. Hono middleware stack runs in order:
   - `cors()` — adds CORS headers
   - `rateLimit()` — checks in-process token bucket per IP
   - `extractPayerWallet()` — parses EVM address from `X-PAYMENT` header, stores in `c.set("payerWallet", ...)`
   - `apiLogger()` — wraps request; logs after response, records revenue if paid
   - `spendCapMiddleware()` — checks daily/monthly cap against SQLite before payment; returns 429 if exceeded
   - `paymentMiddleware()` — validates x402 payment with Coinbase CDP facilitator or x402.org testnet; returns 402 if missing
5. Route handler executes business logic (via local `{logic}.ts` module)
6. Response returned with `PAYMENT-RESPONSE` header
7. `apiLogger` detects paid status, writes `revenue` row with `tx_hash`

**Free Preview Request:**

1. Steps 1–3 same as above
2. Hono routes to `/preview` before `paymentMiddleware` is registered
3. Rate limit applies, no payment check
4. Subset of business logic runs (e.g., single TLD check, headers-only, syntax-only)

**Dashboard API Stats:**

1. Request hits `apimesh.xyz/api/stats` with `Authorization: Bearer <token>`
2. Caddy forwards to `localhost:3000`
3. `bearerAuth` middleware validates token
4. Handler calls `shared/db.ts` query functions, returns aggregated JSON

**State Management:**
- All persistent state in SQLite at `data/agent.db`
- In-process state: rate limit buckets (`shared/rate-limit.ts`), wallet TOCTOU locks (`shared/spend-cap.ts`)
- No external cache layer; everything fits in SQLite with WAL mode

## Key Abstractions

**`paidRoute` / `paidRouteWithDiscovery`:**
- Purpose: Declare an x402-payable route with price, network, and wallet; `WithDiscovery` variant adds Bazaar extension metadata for LLM discovery
- Examples: `shared/x402.ts` (definitions), used in every `apis/*/index.ts`
- Pattern: `paymentMiddleware({ "GET /check": paidRouteWithDiscovery("$0.003", "...", { input, inputSchema }) }, resourceServer)`

**Hono Sub-App per API:**
- Purpose: Each API is an isolated `new Hono()` instance exported as `{ app }`; the router delegates entire requests to it
- Examples: `apis/seo-audit/index.ts`, `apis/web-checker/index.ts`
- Pattern: `export { app }; export default { port, hostname: "127.0.0.1", fetch: app.fetch }`

**Logic Module separation:**
- Purpose: Business logic split into a separate file from the Hono wiring
- Examples: `apis/seo-audit/auditor.ts`, `apis/web-checker/checker.ts`, `apis/email-verify/checker.ts`, `apis/tech-stack/detector.ts`
- Pattern: Named exports `auditFull`/`auditPreview`, `checkPresence`/`checkDns`, etc.

**`validateExternalUrl` + `safeFetch`:**
- Purpose: SSRF-safe URL validation and fetching with redirect-following, timeout, and body-size cap
- Examples: `shared/ssrf.ts` — used by all URL-fetching APIs
- Pattern: `const check = validateExternalUrl(raw); if ("error" in check) return c.json({ error: check.error }, 400)`

## Entry Points

**API Router (primary API entry):**
- Location: `apis/router.ts`
- Triggers: Caddy forwards `*.apimesh.xyz` to `localhost:3001`
- Responsibilities: Subdomain extraction, registry lookup, sub-app delegation, `.well-known/x402` discovery

**Dashboard (admin + landing):**
- Location: `apis/dashboard/index.ts`
- Triggers: Caddy forwards `apimesh.xyz` to `localhost:3000`
- Responsibilities: Serve landing HTML, serve dashboard UI, expose `/api/*` stats endpoints, public `/wallet/:address` endpoints

**MCP HTTP Server:**
- Location: `mcp-server/http.ts`
- Triggers: Caddy forwards `mcp.apimesh.xyz` to `localhost:3002`
- Responsibilities: Stateful HTTP/SSE MCP sessions, tool dispatch to API endpoints

**MCP Stdio Server:**
- Location: `mcp-server/index.ts`
- Triggers: Spawned by LLM client or `scripts/brain/` via `conway-terminal`
- Responsibilities: Stdio JSON-RPC transport for MCP tools

**Brain Automation:**
- Location: `scripts/brain/index.ts`
- Triggers: Cron or manual `bun scripts/brain/index.ts`
- Responsibilities: Monitor health → scout backlog → build new API → register listing → prune stale entries

## Error Handling

**Strategy:** Let x402 `HTTPException` pass through; catch all other errors and return sanitized JSON

**Patterns:**
- x402 payment errors pass through via `if ("getResponse" in err) return err.getResponse()`
- Application errors: `console.error(...)` with ISO timestamp, then `c.json({ error: "..." }, 5xx)`
- User-facing error messages are sanitized — internal details not leaked (see `sanitizeError()` in API modules)
- Fatal startup validation: `process.exit(1)` if required env vars missing or malformed (`WALLET_ADDRESS`, `DASHBOARD_TOKEN`, `CDP_API_KEY_*`)

## Cross-Cutting Concerns

**Logging:** `shared/logger.ts` — `apiLogger(apiName, priceUsd)` middleware writes every request to `requests` table; writes `revenue` row on successful payment. ISO timestamp prefix on console errors.

**Validation:** URL-fetching APIs use `validateExternalUrl()` from `shared/ssrf.ts`. Input length limits (URL: 2048, body: 4096) enforced inline in each handler. EVM address format validated via regex.

**Authentication:** Dashboard `/api/*` routes protected by `hono/bearer-auth` with `DASHBOARD_TOKEN`. API payment enforced by `paymentMiddleware` from `@x402/hono`. No user sessions.

**Rate Limiting:** `shared/rate-limit.ts` — in-process sliding window per named zone + IP. Requires `X-Real-IP` header (set by Caddy); direct access without proxy header returns 403.

**Spend Caps:** `shared/spend-cap.ts` — per-wallet daily/monthly USDC limits enforced pre-settlement. Uses wallet-level lock to prevent TOCTOU race.

---

*Architecture analysis: 2026-03-15*
