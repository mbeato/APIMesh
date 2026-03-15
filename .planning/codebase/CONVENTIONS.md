# Coding Conventions

**Analysis Date:** 2026-03-15

## Naming Patterns

**Files:**
- Kebab-case for directories and files: `seo-audit/`, `security-headers/`, `email-verify/`
- Two-file pattern per API: `index.ts` (HTTP handler/routes) + descriptive second file (`auditor.ts`, `checker.ts`, `analyzer.ts`, `detector.ts`, `parser.ts`, `tracer.ts`)
- Shared utilities live in `shared/` with single-purpose names: `ssrf.ts`, `rate-limit.ts`, `spend-cap.ts`, `x402-wallet.ts`

**Functions:**
- camelCase for all functions: `auditFull`, `auditPreview`, `validateExternalUrl`, `safeFetch`, `getRevenueByApi`
- Factory/constructor functions use verb prefix: `buildCdpFacilitator`, `buildTestnetFacilitator`
- Middleware factory functions named as `nounMiddleware()` or `verbNoun()`: `spendCapMiddleware()`, `extractPayerWallet()`, `apiLogger()`, `rateLimit()`
- DB helpers use verb+noun: `logRequest`, `logRevenue`, `getRevenueByApi`, `insertBacklogItem`
- Boolean-returning functions use `is`/`has` prefix: `isPrivateHost`, `isValidIp`, `backlogItemExists`

**Variables:**
- camelCase for locals: `rawUrl`, `payerWallet`, `txHash`, `clientIp`
- SCREAMING_SNAKE_CASE for module-level constants: `API_NAME`, `PORT`, `PRICE`, `WALLET_ADDRESS`, `CDP_KEY_ID`
- Numeric literals use underscore separators for readability: `60_000`, `10_000`, `100_000`, `3_000`

**Types/Interfaces:**
- PascalCase for all interfaces and types: `BacklogItem`, `SpendCap`, `AuditLogEntry`, `EmailVerifyResult`
- Interface names are domain-nouns, not `I`-prefixed
- Return type unions use discriminated object pattern: `{ url: URL } | { error: string }`

## Code Style

**Formatting:**
- No formatter config detected (no `.prettierrc`, `biome.json`, or ESLint config at root)
- Consistent 2-space indentation throughout
- Double quotes for strings in imports and object keys
- Trailing commas in multi-line objects and function arguments

**Linting:**
- No ESLint/Biome config detected
- TypeScript strict mode enabled (`strict: true` in `tsconfig.json`)
- Additional strict flags active: `noFallthroughCasesInSwitch`, `noUncheckedIndexedAccess`, `noImplicitOverride`
- `noUnusedLocals` and `noUnusedParameters` are deliberately disabled

## Import Organization

**Order (observed pattern):**
1. Node built-ins (`node:dns/promises`, `path`)
2. Third-party packages (`hono`, `hono/cors`, `cheerio`)
3. Shared internal (`../../shared/x402`, `../../shared/logger`, `../../shared/ssrf`)
4. Local module files (`./auditor`, `./checker`, `./analyzer`)

**Path Aliases:**
- None — relative paths only (e.g., `../../shared/x402`)
- `verbatimModuleSyntax` is enabled; use `import type` for type-only imports

**Type imports:**
- `import type { ... }` for type-only imports: `import type { MiddlewareHandler } from "hono"`

## Error Handling

**Strategy:**
- Errors are caught at route handler level; middleware propagates via `next()`
- x402 `HTTPException` objects must be passed through via `"getResponse" in err` check — this pattern appears in every API's `onError` handler

**Patterns:**
```typescript
// Standard onError handler — required in every API module
app.onError((err, c) => {
  if (typeof err === "object" && err !== null && "getResponse" in err) {
    return (err as any).getResponse();
  }
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

// Standard catch in route handlers
try {
  const result = await auditFull(check.url.toString());
  return c.json(result);
} catch (e: any) {
  if (typeof e === "object" && e !== null && "getResponse" in e) {
    return (e as any).getResponse();
  }
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, e?.message ?? e);
  return c.json({ error: sanitizeError(e) }, 502);
}
```

**Error sanitization:**
- Public-facing error messages use a `sanitizeError()` function that whitelists known safe error strings; all other errors collapse to a generic message
- Pattern used in: `apis/seo-audit/index.ts`, `apis/redirect-chain/index.ts`

**Discriminated unions for result types:**
```typescript
// Functions in shared/ssrf.ts use this pattern
export function validateExternalUrl(raw: string): { url: URL } | { error: string }
// Callers check: if ("error" in check) { ... }
```

**Fatal startup errors:**
- Env var validation runs at module load time with `process.exit(1)` on failure
- Pattern used in `shared/x402.ts`, `apis/dashboard/index.ts`

## Logging

**Pattern:**
- `console.error()` with ISO timestamp prefix: `console.error(\`[\${new Date().toISOString()}] \${API_NAME} error:\`, ...)`
- `console.log()` for startup confirmation: `console.log(\`x402: ...\`)`
- Structured request/revenue logging goes through `shared/db.ts` functions (not console)
- Log fields sanitized via `sanitizeLogField()` in `shared/logger.ts` (strips control chars, limits to 512 chars)

## Comments

**When to Comment:**
- Section separators use `// ─── Section Name ───` style (with Unicode box-drawing chars) in longer files
- Inline comments explain non-obvious constraints: `// x402 sets PAYMENT-RESPONSE header after successful settlement`
- Middleware ordering comments are mandatory: `// 1. CORS`, `// 2. Health check BEFORE rate limiter`, etc.
- Security-critical sections are marked: `// CRITICAL error handler - must pass through x402 HTTPExceptions`
- Defensive limits explained: `// Cap tracked IPs per zone to prevent memory exhaustion`

**JSDoc/TSDoc:**
- Used selectively on exported utility functions in `shared/`: `/** Validate a user-provided URL is safe to fetch (no SSRF). */`
- Not used on route handlers

## Function Design

**Size:**
- Business logic extracted to dedicated `checker.ts`/`auditor.ts`/`analyzer.ts` files; `index.ts` contains only routing and middleware wiring
- Shared utilities (`shared/ssrf.ts`, `shared/rate-limit.ts`) are single-responsibility

**Parameters:**
- Optional parameters use TypeScript default values: `days: number = 7`, `limit: number = 20`
- Nullable optional params typed as `param?: string` (not `param: string | undefined`)

**Return Values:**
- Async route handlers return `Response` or `c.json(...)` directly
- DB query functions always cast their return: `.get() as TypeName | null`, `.all() as TypeName[]`
- Utility functions prefer discriminated unions over throw for expected error paths

## Module Design

**Exports:**
- Each API module exports `{ app }` (named) plus a default `{ port, hostname, fetch: app.fetch }` for `Bun.serve()`
- Shared modules use named exports only (no default for utilities)
- `shared/db.ts` uses `export default db` for the database instance alongside named function exports

**Barrel Files:**
- `apis/registry.ts` acts as a barrel/registry — imports all `app` instances and re-exports as a `Record<string, Hono>`
- No index barrel files in `shared/` — import each file directly

## API Module Structure

**Mandatory ordering within every `apis/*/index.ts`:**
1. CORS middleware
2. Health check route (before rate limiter)
3. Rate limit middleware + `extractPayerWallet()` + `apiLogger()`
4. Info endpoint (`GET /`)
5. Free preview route(s)
6. `spendCapMiddleware()` + `paymentMiddleware()`
7. Paid routes
8. `app.onError()` handler
9. `app.notFound()` handler
10. `export { app }` and default export

**Constants at top of each API module:**
```typescript
const API_NAME = "api-slug";         // matches directory name
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.003";              // string for paymentMiddleware
```

---

*Convention analysis: 2026-03-15*
