# Testing Patterns

**Analysis Date:** 2026-03-15

## Test Framework

**Runner:**
- Bun's built-in test runner (`bun test`)
- No separate jest/vitest config file present
- `@types/bun` is the only dev dependency (includes `bun:test` types)

**Assertion Library:**
- `bun:test` built-ins (`expect`, `test`, `describe`)

**Run Commands:**
```bash
bun test              # Run all tests
bun test --watch      # Watch mode
bun test --coverage   # Coverage report
```

## Test File Organization

**Current State:**
- No test files (`.test.ts` or `.spec.ts`) exist in the codebase at the time of analysis
- The project has no automated test suite

**Intended Location (by convention):**
- Co-located with source: `apis/seo-audit/auditor.test.ts` alongside `apis/seo-audit/auditor.ts`
- Or in a `tests/` directory mirroring `apis/` structure

**Naming (Bun convention):**
- `*.test.ts` — unit and integration tests
- `*.spec.ts` — alternative spec-style naming

## Test Structure

**Bun test pattern:**
```typescript
import { test, expect, describe, beforeEach, afterEach } from "bun:test";

describe("ModuleName", () => {
  test("description of behavior", () => {
    expect(result).toBe(expected);
  });

  test("async behavior", async () => {
    const result = await asyncFunction();
    expect(result).toEqual({ key: "value" });
  });
});
```

## Mocking

**Framework:** `bun:test` built-in mock utilities (`mock`, `spyOn`, `jest` compatibility layer)

**Patterns for this codebase:**

```typescript
import { mock } from "bun:test";

// Mock fetch for SSRF-protected API calls
const mockFetch = mock(async (url: string) => {
  return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
});
globalThis.fetch = mockFetch;

// Mock bun:sqlite db to avoid filesystem side effects
mock.module("../../shared/db", () => ({
  default: { run: mock(() => {}), query: mock(() => ({ get: () => null, all: () => [] })) },
  logRequest: mock(() => {}),
  logRevenue: mock(() => {}),
}));
```

**What to Mock:**
- `fetch` calls — all outbound HTTP in checkers/analyzers uses `safeFetch()` from `shared/ssrf.ts`
- `bun:sqlite` database — `shared/db.ts` opens a real file on import
- `process.env` values — many modules validate env vars at load time and call `process.exit(1)` on failure

**What NOT to Mock:**
- Pure parsing/analysis functions in `checker.ts`/`auditor.ts`/`analyzer.ts` — these are pure or near-pure and should be tested directly
- URL validation logic in `shared/ssrf.ts` — test with real inputs

## Fixtures and Factories

**Test Data (recommended pattern for this codebase):**
```typescript
// For URL-based APIs
const fixtures = {
  validUrl: "https://example.com",
  privateUrl: "http://192.168.1.1",
  localUrl: "http://localhost:8080",
  invalidUrl: "not-a-url",
};

// For checker result types — use the exported interfaces directly
import type { EmailVerifyResult } from "./checker";
const mockEmailResult: EmailVerifyResult = { ... };
```

**Location:**
- No fixture directory exists — would be created at `tests/fixtures/` or co-located as `*.fixtures.ts`

## Coverage

**Requirements:** None enforced (no coverage thresholds in config)

**View Coverage:**
```bash
bun test --coverage
```

## Test Types

**Unit Tests (highest priority for this codebase):**
- Scope: Pure logic functions in `checker.ts`, `auditor.ts`, `analyzer.ts`, `detector.ts` files
- Key candidates:
  - `shared/ssrf.ts` — `validateExternalUrl()`, `isPrivateHost()` with edge cases
  - `shared/rate-limit.ts` — rate limiting logic, IP validation
  - `shared/spend-cap.ts` — lock serialization, cap enforcement
  - `apis/email-verify/checker.ts` — `validateSyntax()`, disposable detection
  - `apis/security-headers/analyzer.ts` — header grading logic
  - `apis/seo-audit/auditor.ts` — scoring and issue detection

**Integration Tests:**
- Scope: Full Hono app routing using `app.request()` (no real HTTP server needed)
- Pattern:
  ```typescript
  import { app } from "./index";
  const res = await app.request("/health");
  expect(res.status).toBe(200);
  ```
- Mock `shared/db.ts` and `fetch` to isolate from I/O

**E2E Tests:**
- Not applicable — no E2E framework configured

## Common Patterns

**Async Testing:**
```typescript
test("fetches and analyzes URL", async () => {
  const mockFetch = mock(async () => new Response("<html>...</html>", { status: 200 }));
  globalThis.fetch = mockFetch;
  const result = await auditFull("https://example.com");
  expect(result.score).toBeGreaterThan(0);
});
```

**Error Testing:**
```typescript
test("rejects private IP addresses", () => {
  const result = validateExternalUrl("http://192.168.1.1/");
  expect("error" in result).toBe(true);
  if ("error" in result) {
    expect(result.error).toMatch(/Private/);
  }
});

test("handles fetch errors gracefully", async () => {
  globalThis.fetch = mock(async () => { throw new Error("ECONNREFUSED"); });
  const res = await app.request("/check?url=https://example.com");
  expect(res.status).toBe(502);
});
```

**Testing x402 payment middleware bypass:**
```typescript
// Middleware ordering means preview routes are tested without payment headers
test("preview endpoint returns partial data without payment", async () => {
  const res = await app.request("/preview?url=https://example.com");
  expect(res.status).toBe(200);
  // Should NOT contain full paid-only fields
});
```

**Environment variable handling:**
```typescript
// Modules that call process.exit(1) on missing env vars must be loaded
// AFTER setting the env var in tests
test("requires WALLET_ADDRESS env var", () => {
  // Set required env vars before importing module
  process.env.WALLET_ADDRESS = "0xabcdef1234567890abcdef1234567890abcdef12";
  // ... import and test
});
```

## Key Testable Pure Functions

These functions have no I/O and are ideal first test targets:

| Function | File | Notes |
|---|---|---|
| `validateExternalUrl()` | `shared/ssrf.ts` | Tests private IP ranges, protocol checks |
| `isPrivateHost()` | `shared/ssrf.ts` | IPv4/IPv6 private range detection |
| `validateSyntax()` | `apis/email-verify/checker.ts` | RFC 5321 email validation |
| `sanitizeLogField()` | `shared/logger.ts` | Control char stripping |
| `sanitizeError()` | `apis/seo-audit/index.ts` | Whitelist-based error message filtering |
| `extractSubdomain()` | `apis/router.ts` | Subdomain routing logic |
| `tryParseJSON()` | `mcp-server/server.ts` | JSON parse with fallback |

---

*Testing analysis: 2026-03-15*
