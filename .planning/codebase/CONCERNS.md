# Codebase Concerns

**Analysis Date:** 2026-03-15

---

## Tech Debt

**Regex /test endpoint: Post-execution timing check for ReDoS**
- Issue: Catastrophic backtracking detection relies on measuring elapsed time after `input.match(re)` completes. If the regex hangs the event loop, the timer never fires — Node's single-threaded execution means the process stalls before the check can trigger.
- Files: `apis/regex-builder/index.ts` lines 218–236
- Impact: A crafted pattern + input could hang the Bun process serving all APIs routed through port 3001, causing a full outage of 20 APIs simultaneously.
- Fix approach: Run regex execution in a `Worker` thread with a hard wall-clock timeout so the main event loop is not blocked. Alternatively, pre-screen patterns with a static analysis library (e.g., `safe-regex` or `vuln-regex-detector`).

**Core Web Vitals: Strategy hardcoded to `"mobile"` only**
- Issue: `callPSI` in `apis/core-web-vitals/analyzer.ts` line 101 always sets `strategy=mobile`. The `FullReport` type includes a `strategy` field, but callers cannot request desktop analysis.
- Files: `apis/core-web-vitals/analyzer.ts`
- Impact: Paid callers paying $0.005 receive only mobile scores. Desktop analysis silently never runs.
- Fix approach: Accept optional `strategy` parameter in `analyzeFullReport()` and thread it through to `callPSI`.

**PSI_API_KEY is optional without warning**
- Issue: `apis/core-web-vitals/analyzer.ts` line 106 silently calls the Google PageSpeed API without an API key when `PSI_API_KEY` is not set. The unauthenticated quota is 1 req/100s per IP, which will cause production 429 failures under load without any startup warning.
- Files: `apis/core-web-vitals/analyzer.ts`
- Impact: Silent quota exhaustion errors surface to paying customers as opaque 502s.
- Fix approach: Emit a `console.warn` at startup if `PSI_API_KEY` is absent, matching the startup-check pattern used by `shared/x402.ts` and `apis/dashboard/index.ts`.

**`llms.txt` served using CWD-relative path**
- Issue: `apis/dashboard/index.ts` line 30 reads `Bun.file("public/llms.txt")` — a path relative to the process working directory, not to the file's location. If the service is started from a directory other than the project root (e.g., `cd /opt/conway-agent/apis/dashboard && bun index.ts`), the file is silently not found and a 404 is returned.
- Files: `apis/dashboard/index.ts`
- Impact: `llms.txt` returns 404, breaking AI agent discovery of the platform.
- Fix approach: Replace with `Bun.file(join(import.meta.dir, "../../public/llms.txt"))`, consistent with how other static files in the same file are resolved.

**Duplicate entry in ROLE_ADDRESSES Set**
- Issue: `apis/email-verify/checker.ts` line 60 contains `"noc"` twice in the `ROLE_ADDRESSES` Set literal. JavaScript `Set` deduplicates silently so there is no functional bug, but it indicates the list was constructed carelessly.
- Files: `apis/email-verify/checker.ts`
- Impact: Low — functional no-op. Code quality / review signal.
- Fix approach: Remove the duplicate `"noc"` entry.

**Migration via bare try/catch `{}` pattern**
- Issue: `shared/db.ts` lines 74–75 run `ALTER TABLE` migrations via `try { db.exec(...) } catch {}`. This silently swallows any error, including cases where a migration fails for reasons other than the column already existing (e.g., disk full, corrupt schema).
- Files: `shared/db.ts`
- Impact: Schema migration failures are invisible; the DB continues running with old schema, causing silent data loss on `payer_wallet` columns.
- Fix approach: Narrow the catch to SQLite error code `SQLITE_ERROR` with message containing `"duplicate column"`, or use `PRAGMA table_info` to check column existence before the `ALTER TABLE`.

---

## Security Considerations

**SSRF: No post-resolution IP check (DNS rebinding gap)**
- Risk: `shared/ssrf.ts` validates the hostname string against a blocklist before fetching. It does not re-validate the resolved IP address after DNS lookup. An attacker can serve a public hostname that resolves to `127.0.0.1` at fetch time (DNS rebinding) and bypass the check entirely.
- Files: `shared/ssrf.ts`
- Current mitigation: Hostname string check blocks obvious direct usage of `localhost`, `10.x.x.x`, etc.
- Recommendations: After DNS resolution (which Bun exposes via `Bun.dns.lookup`), validate each resolved IP address through `isPrivateHost()` before the actual fetch. This is critical for all 18 URL-fetching APIs.

**MCP HTTP server: No timeout on `callApi` fetch calls**
- Risk: `mcp-server/server.ts` `callApi()` function calls `fetch(url, options)` with no timeout or `AbortSignal`. A slow upstream API (e.g., a paid API endpoint that hangs) will hold the MCP HTTP connection open indefinitely.
- Files: `mcp-server/server.ts` lines 12–13
- Current mitigation: None.
- Recommendations: Add `signal: AbortSignal.timeout(30_000)` to the `fetch` call in `callApi`.

**MCP HTTP server: `transports` Map has no upper bound or TTL**
- Risk: `mcp-server/http.ts` line 8 creates an in-process `Map<string, WebStandardStreamableHTTPServerTransport>`. Sessions are added on every new `POST /mcp` connection and only deleted when the transport fires `onclose`. If a client opens many sessions without closing them (or a crash prevents `onclose` from firing), the map grows without limit.
- Files: `mcp-server/http.ts`
- Current mitigation: None.
- Recommendations: Cap maximum concurrent sessions (e.g., 1000) and evict sessions that have been idle beyond a TTL (e.g., 30 minutes).

**Public wallet endpoint has no authentication**
- Risk: `apis/dashboard/index.ts` `/wallet/:address` (GET), `/wallet/:address/history` (GET), and `/wallet/:address/cap` (PUT) are fully public with only rate limiting (30/min/IP). Any party knowing a wallet address can view its full transaction history and set (or overwrite) spend caps.
- Files: `apis/dashboard/index.ts` lines 120–210
- Current mitigation: Rate limited to 30/min/IP; wallet address must be known.
- Recommendations: For the PUT `/wallet/:address/cap` endpoint, require either a signed message proving wallet ownership, or restrict to the admin bearer token. Read-only GET endpoints are acceptable public (wallet holders can self-serve), but the write endpoint is a higher-risk surface.

**`unsafe-inline` in CSP for dashboard and landing scripts**
- Risk: `caddy/Caddyfile` line 19 sets `script-src 'self' 'unsafe-inline'` for the dashboard block. The Hono-served dashboard HTML also sets `script-src 'self'` (good), but the Caddy block overrides with the weaker policy for `/` and `/dashboard` paths.
- Files: `caddy/Caddyfile`, `apis/dashboard/index.ts` lines 61, 77
- Current mitigation: Application-level CSP headers are also set, but Caddy's headers may override or merge.
- Recommendations: Remove `'unsafe-inline'` from `script-src` in `dashboard_headers` snippet; move any inline scripts in landing/dashboard HTML to external `.js` files (already partially done — `landing.js` and `dashboard.js` are served as external scripts).

---

## Performance Bottlenecks

**`/api/stats` endpoint: N+1 SQLite queries per active API**
- Problem: `apis/dashboard/index.ts` lines 258–265 call `getRequestCount()`, `getErrorRate()`, and `getApiRevenue()` once per active API inside an `.map()`. Each call issues a separate SQLite query. With 21 active APIs this is 63 sequential queries per `/api/stats` call.
- Files: `apis/dashboard/index.ts`, `shared/db.ts`
- Cause: Per-API stats functions are designed for single-API use; the dashboard iterates them.
- Improvement path: Add a single batch query that returns all per-API stats in one `GROUP BY api_name` query. Alternatively, cache the stats result for 60 seconds in memory since the dashboard is for monitoring, not real-time.

**`seo-audit`: Link checking in paid response path adds up to ~15s latency**
- Problem: `apis/seo-audit/auditor.ts` `checkLinks()` (line 312) fetches up to 20 links in batches of 5, each with a 3-second timeout. In the worst case this adds 12 seconds to the paid `/check` response time. There is no overall budget on the link-checking phase.
- Files: `apis/seo-audit/auditor.ts`
- Cause: Sequential batching of external HEAD requests with full timeout expiry per batch.
- Improvement path: Set an overall 8-second budget for link checking (matching `safeFetch` default), abort remaining checks if the budget is exceeded, and mark unverified links as `status: null`.

**`getAuditLog`: Correlated subquery per row for tx_hash join**
- Problem: `shared/db.ts` lines 425–438 use a correlated subquery `(SELECT rev.tx_hash ...)` per row in the main audit log query. For large result sets this can be O(rows × revenue_table_size).
- Files: `shared/db.ts`
- Cause: The `requests` table has no direct `tx_hash` column; the join approximates the match by timestamp proximity within 1.728 seconds (`julianday` delta < 0.00002).
- Improvement path: Add a `tx_hash` column to the `requests` table and populate it at log time in `shared/logger.ts`. The timestamp approximation is also semantically fragile (see Known Bugs).

---

## Fragile Areas

**`shared/x402.ts`: Top-level `await` at module init**
- Files: `shared/x402.ts` lines 66–76
- Why fragile: `buildCdpFacilitator()` is `await`-ed at module load time. If the CDP SDK throws asynchronously after the import completes (e.g., a network error during JWT pre-fetch), `process.exit(1)` is called — bringing down every API in the monorepo that imports this module, since they all share the same Bun process via `apis/router.ts`.
- Safe modification: Wrap CDP initialization in a retry loop with exponential backoff rather than a hard exit; or move initialization into a lazy getter so individual API failures do not cascade.
- Test coverage: None — no tests exist in the codebase.

**`shared/rate-limit.ts`: In-process only; resets on each service restart**
- Files: `shared/rate-limit.ts`
- Why fragile: Rate limit state lives in a `Map` in process memory. Each service restart (deploy, crash, restart) resets all counters. This means a burst of requests can slip through rate limiting during rolling restarts. It also means the router and dashboard maintain separate rate limit state since they run in separate Bun processes.
- Safe modification: Acceptable for current single-server deployment. Will need Redis-backed rate limiting before horizontal scaling.
- Test coverage: None.

**`apis/router.ts`: All 20 APIs loaded in one process**
- Files: `apis/router.ts`, `apis/registry.ts`
- Why fragile: All API modules are imported at startup. A startup error in any single API (e.g., bad x402 config, import failure) crashes the router and takes all 20 APIs offline. The single `PORT=3001` means all APIs share the same Bun process and memory space.
- Safe modification: Each API module should validate its own required env vars at startup and emit a warning (rather than `process.exit`) when non-fatal. The router should skip registering APIs that fail initialization.
- Test coverage: None.

**Audit log tx_hash join by timestamp approximation (1.728s window)**
- Files: `shared/db.ts` line 432
- Why fragile: The correlated subquery matches a `requests` row to a `revenue` row if their `created_at` values differ by less than 1.728 seconds (`julianday` delta 0.00002 days). Under concurrent load, two requests from different wallets within the same 1.7-second window could match the wrong `tx_hash`.
- Safe modification: Add a `tx_hash` column to the `requests` table and write it directly in `shared/logger.ts` when `paid === true`.
- Test coverage: None.

---

## Scaling Limits

**Single SQLite database file**
- Current capacity: Single file at `data/agent.db` (WAL mode). Handles concurrent reads well; writes serialize.
- Limit: Under sustained high write load (many simultaneous paid API calls logging to `requests` + `revenue`), WAL write contention causes `SQLITE_BUSY` errors. `PRAGMA busy_timeout=5000` provides 5s of retry but does not eliminate the limit.
- Scaling path: Move to Postgres (`Bun.sql`) for write-heavy production scenarios. Rate-limiting and the serialized wallet lock in `spend-cap.ts` help but do not fully mitigate.

**In-process rate limiting**
- Current capacity: Per-zone `Map` capped at 10,000 IPs per zone.
- Limit: 10,000 unique IPs per rate limit zone before new requests are blanket-rejected with 429 (see `shared/rate-limit.ts` line 51).
- Scaling path: Replace with Redis-backed rate limiting if traffic from more than 10,000 unique IPs per minute is anticipated.

---

## Dependencies at Risk

**`@x402/hono`, `@x402/core`, `@x402/evm`, `@x402/extensions` at `^2.5.0`**
- Risk: The x402 protocol is actively evolving (pre-1.0). Breaking changes in payment header format, facilitator API, or scheme names would require coordinated updates across all 20 API `index.ts` files, `shared/x402.ts`, `shared/x402-wallet.ts`, and `shared/spend-cap.ts`.
- Impact: Payment verification fails silently or APIs return 402 errors without accepting valid payments.
- Migration plan: Pin exact versions (remove `^`) and test against each minor version upgrade before deploying. Monitor x402 changelog actively.

**`cheerio` at `^1.2.0` — used only in seo-audit**
- Risk: `cheerio` is a moderately heavy dependency (~1MB) used exclusively by `apis/seo-audit/auditor.ts`. If the seo-audit API is deprecated or replaced, it would remain in `package.json` as unused weight.
- Impact: Low. Minimal security surface.
- Migration plan: When/if seo-audit is rewritten, evaluate whether a lighter HTML parser suffices.

---

## Test Coverage Gaps

**No tests exist anywhere in the codebase**
- What's not tested: Every API handler, all shared middleware (`rate-limit.ts`, `spend-cap.ts`, `x402-wallet.ts`, `logger.ts`, `ssrf.ts`), all analyzer/checker modules, the database schema and queries, the router subdomain dispatch.
- Files: Entire `apis/`, `shared/`, `mcp-server/` directories.
- Risk: Regressions in payment handling, SSRF protection, rate limiting, or spend cap enforcement go undetected until production. Security-critical code (SSRF blocklist, wallet extraction, spend cap serialization) is entirely untested.
- Priority: High. The following should be prioritized first:
  1. `shared/ssrf.ts` — SSRF blocklist edge cases (IPv6 variants, encoded addresses, CNAME chains)
  2. `shared/spend-cap.ts` — TOCTOU lock correctness under concurrent requests
  3. `shared/rate-limit.ts` — window expiry and IP cap behavior
  4. `shared/x402-wallet.ts` — malformed payment header parsing
  5. `apis/regex-builder/index.ts` — ReDoS timing check behavior

---

*Concerns audit: 2026-03-15*
