# Codebase Structure

**Analysis Date:** 2026-03-15

## Directory Layout

```
conway/                          # Project root
├── apis/                        # All API modules + routing
│   ├── registry.ts              # Subdomain → Hono app map
│   ├── router.ts                # Main HTTP entry point (port 3001)
│   ├── brand-assets/            # API: brand asset detection
│   ├── core-web-vitals/         # API: Core Web Vitals check
│   ├── dashboard/               # Admin UI, landing page, metrics API (port 3000)
│   ├── email-security/          # API: SPF/DKIM/DMARC checks
│   ├── email-verify/            # API: email address validation
│   ├── favicon-checker/         # API: favicon presence/format check
│   ├── http-status-checker/     # API: HTTP status code lookup
│   ├── indexability/            # API: page indexability audit
│   ├── landing/                 # Landing page HTML + JS (served by dashboard)
│   ├── microservice-health-check/ # API: POST-based health check
│   ├── mock-jwt-generator/      # API: JWT generation
│   ├── redirect-chain/          # API: redirect chain tracer
│   ├── regex-builder/           # API: regex build + test
│   ├── robots-txt-parser/       # API: robots.txt parser
│   ├── security-headers/        # API: HTTP security headers audit
│   ├── seo-audit/               # API: on-page SEO audit
│   ├── status-code-checker/     # API: status code info lookup
│   ├── swagger-docs-creator/    # API: OpenAPI/Swagger doc generator
│   ├── tech-stack/              # API: technology stack detector
│   ├── user-agent-analyzer/     # API: user-agent string parser
│   ├── web-checker/             # API: brand/domain name availability
│   └── yaml-validator/          # API: YAML validation
├── shared/                      # Shared middleware and utilities
│   ├── db.ts                    # SQLite singleton + all query functions
│   ├── hono-types.d.ts          # Hono context type augmentation
│   ├── logger.ts                # apiLogger middleware
│   ├── mcp.ts                   # JSON-RPC client for conway-terminal
│   ├── rate-limit.ts            # In-process token bucket rate limiter
│   ├── spend-cap.ts             # Per-wallet spend cap enforcement middleware
│   ├── ssrf.ts                  # URL validation + safeFetch + readBodyCapped
│   ├── x402-wallet.ts           # Payer wallet extraction middleware
│   └── x402.ts                  # x402 config, paymentMiddleware, paidRoute helpers
├── mcp-server/                  # MCP server (separate npm package)
│   ├── server.ts                # Tool definitions (all 16 tools)
│   ├── index.ts                 # Stdio transport entry point
│   ├── http.ts                  # HTTP/SSE transport (port 3002)
│   ├── package.json             # @mbeato/apimesh-mcp-server package
│   └── bun.lock
├── scripts/                     # Operational scripts
│   ├── brain/                   # Autonomous API builder
│   │   ├── index.ts             # Orchestrator (monitor→scout→build→list→prune)
│   │   ├── monitor.ts           # Revenue/health monitoring
│   │   ├── scout.ts             # Backlog idea generation via LLM
│   │   ├── build.ts             # New API code generation via LLM
│   │   ├── list.ts              # Post-build registration
│   │   └── prune.ts             # Stale entry pruning
│   ├── conway-deploy-restart.sh # Production restart script
│   ├── deploy.sh                # Local deploy helper
│   ├── harden-server.sh         # Server hardening
│   └── install-services.sh      # Systemd service installation
├── caddy/
│   └── Caddyfile                # Reverse proxy config (TLS, subdomain routing)
├── data/
│   └── agent.db                 # SQLite database (WAL mode)
├── public/
│   ├── llms.txt                 # LLM discovery file
│   └── .well-known/             # x402 and other discovery files
├── docs/
│   └── plans/                   # Architecture / planning docs
├── package.json                 # Root package (bun, hono, x402, cheerio)
├── tsconfig.json                # TypeScript config (strict, bundler mode)
├── CLAUDE.md                    # Dev instructions (Bun-first)
└── AGENTS.md                    # Agent usage instructions
```

## Directory Purposes

**`apis/`:**
- Purpose: All API modules plus the routing layer
- Contains: One subdirectory per API, plus `registry.ts` and `router.ts`
- Key files: `apis/registry.ts`, `apis/router.ts`

**`apis/{api-name}/`:**
- Purpose: One isolated Hono app per paid API
- Contains: `index.ts` (Hono wiring + middleware stack), one or two logic files (`checker.ts`, `auditor.ts`, `detector.ts`, etc.)
- Key pattern: `index.ts` exports `{ app }` and a default `{ port, hostname, fetch }` for standalone running

**`apis/dashboard/`:**
- Purpose: Serves landing page, dashboard UI, and protected `/api/*` metrics endpoints
- Contains: `index.ts`, `dashboard.html`, `dashboard.js`
- Key files: `apis/dashboard/index.ts`

**`apis/landing/`:**
- Purpose: Landing page static assets only (no Hono app)
- Contains: `landing.html`, `landing.js`
- Key files: Referenced by `apis/dashboard/index.ts` via `Bun.file(...)`

**`shared/`:**
- Purpose: Cross-cutting middleware and utilities consumed by every API
- Contains: TypeScript modules only; no framework setup here — pure utility functions and middleware factories
- Key files: `shared/db.ts`, `shared/x402.ts`, `shared/ssrf.ts`

**`mcp-server/`:**
- Purpose: Standalone npm package exposing all APIs as MCP tools
- Contains: Independent `package.json`, own `bun.lock`, TypeScript source
- Key files: `mcp-server/server.ts` (all tool definitions), `mcp-server/http.ts` (HTTP entry)

**`scripts/brain/`:**
- Purpose: Autonomous pipeline that monitors, generates, and deploys new APIs
- Contains: Five pipeline stage modules
- Key files: `scripts/brain/index.ts` (orchestrator)

**`data/`:**
- Purpose: SQLite database persistence
- Contains: `agent.db` (WAL + shared-memory files)
- Generated: Yes (by `shared/db.ts` on first run)
- Committed: No (in `.gitignore`)

**`public/`:**
- Purpose: Static discovery files served at root domain
- Contains: `llms.txt`, `.well-known/x402`
- Committed: Yes

**`caddy/`:**
- Purpose: Production Caddy configuration
- Contains: `Caddyfile` with three virtual hosts
- Committed: Yes

## Key File Locations

**Entry Points:**
- `apis/router.ts`: Main API router, port 3001, all `*.apimesh.xyz` traffic
- `apis/dashboard/index.ts`: Dashboard + landing, port 3000, `apimesh.xyz` traffic
- `mcp-server/index.ts`: MCP stdio entry point
- `mcp-server/http.ts`: MCP HTTP entry point, port 3002
- `scripts/brain/index.ts`: Brain automation orchestrator

**Configuration:**
- `caddy/Caddyfile`: Reverse proxy, TLS, subdomain routing
- `tsconfig.json`: TypeScript compiler options
- `package.json`: Root dependencies
- `mcp-server/package.json`: MCP server package config
- `.mcp.json`: MCP server connection config for Claude

**Core Logic:**
- `shared/db.ts`: All database schema, migrations, and query functions
- `shared/x402.ts`: Payment configuration, `paidRoute`, `paidRouteWithDiscovery` helpers
- `shared/ssrf.ts`: `validateExternalUrl`, `safeFetch`, `readBodyCapped`
- `apis/registry.ts`: Subdomain-to-app mapping

**Testing:**
- No test files detected in the codebase

## Naming Conventions

**Files:**
- Hono entry: `index.ts` in every `apis/{name}/` directory
- Business logic: descriptive noun — `checker.ts`, `auditor.ts`, `detector.ts`, `parser.ts`
- Shared utilities: noun or noun-noun — `db.ts`, `rate-limit.ts`, `spend-cap.ts`, `x402-wallet.ts`
- Scripts: verb or verb-noun — `monitor.ts`, `scout.ts`, `build.ts`, `prune.ts`
- Static assets: `{name}.html`, `{name}.js` collocated with serving module

**Directories:**
- API modules: kebab-case matching subdomain — `seo-audit`, `email-verify`, `tech-stack`
- Shared utilities: single word — `shared`
- Scripts by function: `brain` for autonomous pipeline

**Variables and constants:**
- Constants: `SCREAMING_SNAKE_CASE` — `WALLET_ADDRESS`, `API_NAME`, `PRICE`
- Functions: `camelCase` — `apiLogger`, `rateLimit`, `paidRoute`, `safeFetch`
- Types/interfaces: `PascalCase` — `SpendCap`, `AuditLogEntry`, `BacklogItem`

## Where to Add New Code

**New API:**
1. Create `apis/{kebab-name}/` directory
2. Create `apis/{kebab-name}/index.ts` — copy structure from `apis/seo-audit/index.ts` (includes full middleware stack)
3. Create `apis/{kebab-name}/{logic}.ts` — implement `{verb}Full()` and `{verb}Preview()` exports
4. Add import and registry entry in `apis/registry.ts`
5. Add subdomain routes entry in `apis/router.ts` `subdomainRoutes` map
6. Add MCP tool in `mcp-server/server.ts`
7. Update `public/llms.txt` and `public/.well-known/x402`

**New Shared Middleware:**
- Implementation: `shared/{noun}.ts`
- Export factory function returning `MiddlewareHandler`
- Import type from `hono` — `import type { MiddlewareHandler } from "hono"`

**New Dashboard Endpoint:**
- Protected admin: add route under `/api/*` in `apis/dashboard/index.ts` (covered by `bearerAuth`)
- Public wallet endpoint: add route using `walletLimit` rate limiter before the `app.use("*", bearerAuth(...))` line

**New Brain Pipeline Step:**
- Add module in `scripts/brain/{verb}.ts`
- Import and call in `scripts/brain/index.ts` orchestrator

**Database Schema Changes:**
- Add `CREATE TABLE IF NOT EXISTS` or `ALTER TABLE` to `shared/db.ts`
- Wrap `ALTER TABLE` in `try { ... } catch {}` for safe idempotent migration
- Add typed query functions at bottom of `shared/db.ts`

## Special Directories

**`data/`:**
- Purpose: SQLite persistent storage
- Generated: Yes (auto-created by `shared/db.ts`)
- Committed: No

**`node_modules/`:**
- Purpose: Root-level dependencies (hono, x402, cheerio, cdp-sdk)
- Generated: Yes (`bun install`)
- Committed: No

**`mcp-server/node_modules/`:**
- Purpose: MCP server package dependencies
- Generated: Yes (separate `bun install` inside `mcp-server/`)
- Committed: No

**`.planning/`:**
- Purpose: GSD planning documents and codebase analysis
- Contains: Phase plans, codebase maps
- Committed: Yes

**`public/.well-known/`:**
- Purpose: x402 protocol discovery endpoint for API scanners
- Contains: `x402` file listing paid routes
- Committed: Yes

---

*Structure analysis: 2026-03-15*
