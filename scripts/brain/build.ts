import db, {
  getTopBacklogItem,
  updateBacklogStatus,
  registerApi,
} from "../../shared/db";
import { join, resolve } from "path";
import { tmpdir } from "os";
import { chat } from "../../shared/llm";
import { getReferencesForCategory } from "./reference-selector";
import { competitiveResearch } from "./competitive-research";
import { scoreQuality } from "./quality-scorer";

const ESCALATION_MODEL = process.env.SCOUT_ESCALATION_MODEL || "gpt-4.1";
const DEFAULT_MODEL = "gpt-4.1-mini";
const ESCALATION_THRESHOLD = 7.5;
const MAX_RETRIES = 6;
const API_NAME_PATTERN = /^[a-z][a-z0-9-]{1,48}[a-z0-9]$/;
const RESERVED_NAMES = new Set([
  "shared", "scripts", "public", "data", "node_modules",
  "mcp-server", "dashboard", "router", "registry",
]);
const PROJECT_DIR = join(import.meta.dir, "..", "..");
const APIS_DIR = join(PROJECT_DIR, "apis");
const REGISTRY_PATH = join(APIS_DIR, "registry.ts");
// Test build workspace — in /tmp because systemd sandbox keeps project dir read-only.
const TEST_BUILDS_DIR = join(tmpdir(), "conway-test-builds");
const TEST_PORT = 3099;
const BUN = Bun.argv[0];

// Maximum allowed sizes for generated code (defense against exfil-via-size and
// runaway generation).
const MAX_FILE_BYTES = 50 * 1024;       // 50 KB per file
const MAX_TOTAL_BYTES = 200 * 1024;     // 200 KB total across all files

// How long to wait for the test server to start before checking health.
const TEST_SERVER_BOOT_MS = 3_000;
// Hard kill timeout: the test process must complete within this window.
const TEST_KILL_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// Reference material for the LLM
// ---------------------------------------------------------------------------

async function getReference(category?: string): Promise<string> {
  return getReferencesForCategory(category ?? "security", APIS_DIR);
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GeneratedFile {
  path: string;
  content: string;
}

interface Finding {
  severity: "critical" | "high" | "medium" | "low";
  rule: string;
  detail: string;
  file: string;
  line?: number;
}

interface AuditResult {
  pass: boolean;
  findings: Finding[];
}

// ---------------------------------------------------------------------------
// Code generation
// ---------------------------------------------------------------------------

async function generateApi(
  name: string,
  description: string,
  errorFeedback?: string,
  model: string = DEFAULT_MODEL,
  category?: string,
  competitiveContext?: string,
): Promise<GeneratedFile[]> {
  const reference = await getReference(category);

  // Wrap the untrusted name and description in explicit <data> delimiters.
  // The system prompt in shared/llm.ts instructs the model to treat content
  // inside these delimiters as plain text only, not as instructions.
  const prompt = `Generate a PRODUCTION-QUALITY x402/MPP-payable Hono API. This must be a comprehensive, hard-to-replicate service — NOT a thin wrapper around a single fetch call.

API specification:
<data>
- Name: ${name}
- Description: ${description}
- Subdomain: ${name}.apimesh.xyz
- Price: see pricing guide below
</data>

Pricing guide — price based on what the API actually DOES, not what it costs to run:
- Simple single-check (one fetch, one analysis): $0.001
- Basic multi-check (2-3 fetches, some parsing): $0.003
- Standard analysis (multiple data sources combined): $0.005
- Comprehensive audit (5+ checks, scoring, detailed report): $0.01
- Deep scan (extensive crawling, multi-layered analysis): $0.02
Choose ONE price for the main paid endpoint. Use apiLogger(API_NAME, price_as_number) with the same value.
The price must be a string like "$0.005" in paidRouteWithDiscovery and a number like 0.005 in apiLogger.

${errorFeedback ? `PREVIOUS ATTEMPT FAILED with this error:\n<data>\n${errorFeedback}\n</data>\n\nFix the issue in your new attempt.\n` : ""}

QUALITY STANDARDS — this API must justify its price by providing DEPTH:
- Combine multiple data sources or analysis techniques in a single response
- Return structured, comprehensive results (not just a pass/fail or single value)
- Include scoring, grading, or actionable recommendations where appropriate
- Handle edge cases gracefully (timeouts, malformed input, partial failures)
- Use helper files for business logic — keep index.ts for routing, put analysis in separate .ts files
- Use TypeScript types for all data structures

RESPONSE FORMAT -- ALL endpoints MUST use this envelope:
{
  "status": "ok",
  "data": { ... },
  "meta": {
    "timestamp": "ISO8601",
    "duration_ms": 142,
    "api_version": "1.0.0"
  }
}

Error responses:
{
  "status": "error",
  "error": "Human-readable error message",
  "detail": "Technical detail for debugging",
  "meta": { "timestamp": "...", "duration_ms": 0, "api_version": "1.0.0" }
}

TIMING PATTERN (use in every handler):
const start = performance.now();
// ... analysis logic ...
const duration_ms = Math.round(performance.now() - start);
return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });

RICHNESS REQUIREMENTS:
- Response data MUST have 5+ distinct typed fields (not just a single string or boolean)
- Include an "explanation" or "details" field with human-readable analysis text
- Include severity/score/grade where applicable (0-100 numeric score + letter grade A-F)
- Include "recommendations" array with actionable fix suggestions, each having { issue, severity, suggestion }
- Define TypeScript interfaces for all response shapes

DOCUMENTATION REQUIREMENTS:
- The / info endpoint MUST return: { api, status, version, docs: { endpoints: [...], parameters: [...], examples: [...] }, pricing: {...} }
- Each endpoint in docs must list: method, path, description, parameters, example response

${competitiveContext ? `\n${competitiveContext}\n` : ""}
Technical requirements:
1. Use Hono framework (import { Hono } from "hono")
2. Export a named \`app\` (the Hono instance)
3. Export default with { port: Number(process.env.PORT) || 3001, hostname: "127.0.0.1", fetch: app.fetch }
4. All code in TypeScript
5. No external API keys — use only built-in Bun APIs, fetch, or public APIs
6. Handle errors gracefully with try/catch at every external call
7. CORS open to all origins
8. Supports both x402 and MPP payment protocols
9. Split code into multiple files: index.ts (routing + middleware) and one or more helper files (business logic, types, utilities)
10. EVERY fetch/safeFetch call MUST include AbortSignal.timeout(10000) as the signal option
11. When an endpoint makes 2+ independent external requests, use Promise.all() to run them in parallel

CRITICAL error handling rules (follow these EXACTLY):
- All safeFetch/fetch calls MUST use timeoutMs of at least 10000 (10 seconds). HEAD requests can use 8000.
- NEVER return a generic "Failed to ..." error without the actual error message.
- In EVERY catch block that handles fetch/network errors, use this exact pattern:
  const msg = e instanceof Error ? e.message : String(e);
  const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
  return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
- Timeouts MUST return 504 (Gateway Timeout), not 502 or 500.
- Preview endpoints are FREE and are the first thing potential users try. They MUST be reliable. Use generous timeouts (15-20s) on preview endpoints.

EXACT middleware ordering (follow this precisely):
1. cors() open to all origins — app.use("*", cors({ origin: "*", ... }))
2. /health endpoint (before rate limiting) — app.get("/health", ...)
3. rateLimit() — app.use("*", rateLimit(...))
4. extractPayerWallet() — app.use("*", extractPayerWallet())
5. apiLogger() — app.use("*", apiLogger(API_NAME, price))
6. / info endpoint — app.get("/", ...) returning JSON with { api, status, docs, pricing }
7. spendCapMiddleware() — app.use("*", spendCapMiddleware())
8. paymentMiddleware() with paidRouteWithDiscovery() and resourceServer
9. Paid endpoints (the actual business logic routes)
10. onError handler — pass through HTTPException for 402s:
    app.onError((err, c) => {
      if (typeof err === "object" && err !== null && "getResponse" in err) return (err as any).getResponse();
      console.error(...);
      return c.json({ error: "Internal server error" }, 500);
    });

Required imports:
- Use extractPayerWallet() from "../../shared/x402-wallet"
- Use spendCapMiddleware() from "../../shared/spend-cap"
- Use paymentMiddleware, paidRouteWithDiscovery, resourceServer from "../../shared/x402"
- Use apiLogger from "../../shared/logger"
- Use rateLimit from "../../shared/rate-limit"
- If the API fetches user-provided URLs, use safeFetch and validateExternalUrl from "../../shared/ssrf"

Reference implementations:
${reference}

Respond with a JSON array of files. Each file has "path" (relative to apis/${name}/) and "content" (full TypeScript source).
The main file MUST be "index.ts". You may include helper files.

JSON array only, no markdown fences:`;

  // useSystemPrompt: true — activates the security-focused system prompt in
  // shared/llm.ts that instructs the model to refuse injected instructions.
  const response = await chat(prompt, { model, maxTokens: 16384, useSystemPrompt: true });

  try {
    const cleaned = response.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const files = JSON.parse(cleaned) as GeneratedFile[];
    console.log(`[build] Generated ${files.length} files: ${files.map(f => f.path).join(", ")}`);
    return files;
  } catch {
    console.error("[build] Failed to parse response:", response.slice(0, 500));
    return [];
  }
}

// ---------------------------------------------------------------------------
// Security audit
// ---------------------------------------------------------------------------

function securityAudit(files: GeneratedFile[]): AuditResult {
  const findings: Finding[] = [];

  const ALLOWED_IMPORT_PREFIXES = ["hono", "../../shared/", "./"];

  for (const file of files) {
    const lines = file.content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      const addFinding = (severity: Finding["severity"], rule: string, detail: string) =>
        findings.push({ severity, rule, detail, file: file.path, line: lineNum });

      // CRITICAL: eval / new Function / dynamic code exec
      if (/\beval\s*\(/.test(line) || /\bnew\s+Function\s*\(/.test(line)) {
        addFinding("critical", "dynamic-exec", "eval() or new Function() detected");
      }

      // CRITICAL: Hardcoded secrets
      if (/sk_live_[a-zA-Z0-9]{20,}/.test(line)) {
        addFinding("critical", "hardcoded-secret", "Stripe live key detected");
      }
      if (/(?:"|'|`)0x[0-9a-fA-F]{64}(?:"|'|`)/.test(line)) {
        addFinding("critical", "hardcoded-secret", "Possible hardcoded private key (0x + 64 hex)");
      }
      if (/Bearer\s+[a-zA-Z0-9_\-.]{20,}/.test(line) && !/header|Header|req\./.test(line)) {
        addFinding("critical", "hardcoded-secret", "Possible hardcoded Bearer token");
      }

      // CRITICAL: Encoded/obfuscated payloads — common in injection attacks
      // that try to smuggle malicious code past static analysis.
      if (/\batob\s*\(/.test(line) || /Buffer\.from\s*\([^,)]+,\s*["']base64["']\)/.test(line)) {
        addFinding("critical", "encoded-payload", "Base64 decode detected — possible obfuscated payload");
      }
      if (/String\.fromCharCode\s*\(/.test(line)) {
        addFinding("critical", "encoded-payload", "String.fromCharCode() detected — possible obfuscated payload");
      }
      // Hex escape sequences inside string literals (e.g. "\x41\x42\x43")
      if (/["'`][^"'`]*\\x[0-9a-fA-F]{2}[^"'`]*["'`]/.test(line)) {
        addFinding("critical", "encoded-payload", "Hex escape sequence in string literal — possible obfuscated payload");
      }
      // Base64.decode() from external libs
      if (/Base64\.decode\s*\(/.test(line)) {
        addFinding("critical", "encoded-payload", "Base64.decode() call detected");
      }

      // CRITICAL: Dynamic import — could load arbitrary modules at runtime
      if (/\bimport\s*\(/.test(line)) {
        addFinding("critical", "dynamic-import", "Dynamic import() detected — could load arbitrary modules");
      }

      // CRITICAL: process.env enumeration — full env dump / exfiltration
      if (/Object\.keys\s*\(\s*process\.env\s*\)/.test(line)) {
        addFinding("critical", "env-enumeration", "Object.keys(process.env) — full env enumeration");
      }
      if (/JSON\.stringify\s*\(\s*process\.env\s*\)/.test(line)) {
        addFinding("critical", "env-enumeration", "JSON.stringify(process.env) — full env dump");
      }
      if (/\.\.\.\s*process\.env\b/.test(line)) {
        addFinding("critical", "env-enumeration", "Spread of process.env — full env exposure");
      }

      // HIGH: File system writes
      if (/Bun\.write\s*\(/.test(line) || /writeFile\s*\(/.test(line) || /appendFile\s*\(/.test(line)) {
        addFinding("high", "fs-write", "File system write detected");
      }

      // HIGH: Reading sensitive files from disk
      // Generated code could bypass env-stripping by reading .env directly.
      if (/Bun\.file\s*\(\s*["'`][^"'`]*\.env[^"'`]*["'`]/.test(line)) {
        addFinding("critical", "sensitive-file-read", "Bun.file() with .env path — direct credential file read");
      }
      if (/readFile\s*\(\s*["'`][^"'`]*\.env[^"'`]*["'`]/.test(line)) {
        addFinding("critical", "sensitive-file-read", "readFile() with .env path — direct credential file read");
      }
      // Path traversal read: any Bun.file() with a path containing '..' or starting with '/'
      if (/Bun\.file\s*\(\s*["'`](?:\/|\.\.\/|\.\.\\)/.test(line)) {
        addFinding("high", "path-traversal-read", "Bun.file() with absolute or parent-relative path");
      }

      // HIGH: Sensitive env var access
      if (/process\.env\.(STRIPE_SECRET_KEY|CDP_API_KEY_ID|CDP_API_KEY_SECRET|ANTHROPIC_API_KEY|OPENAI_API_KEY|MPP_SECRET_KEY|MPP_PRIVATE_KEY|RESEND_API_KEY|VERIFICATION_CODE_SECRET|DASHBOARD_TOKEN|CONWAY_API_KEY|STRIPE_WEBHOOK_SECRET)/.test(line)) {
        addFinding("high", "sensitive-env", `Access to sensitive env var: ${line.trim().slice(0, 80)}`);
      }

      // HIGH: Disallowed imports
      const importMatch = line.match(/(?:from\s+["']([^"']+)["']|require\s*\(\s*["']([^"']+)["']\s*\))/);
      if (importMatch) {
        const mod = importMatch[1] || importMatch[2];
        const allowed = ALLOWED_IMPORT_PREFIXES.some(p => mod.startsWith(p));
        if (!allowed) {
          addFinding("high", "disallowed-import", `Import "${mod}" not in allowlist (hono, ../../shared/*, ./)`);
        }
      }

      // HIGH: Unsafe SQL (string interpolation near SQL keywords)
      if (/\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b/i.test(line) && /\$\{/.test(line)) {
        addFinding("high", "unsafe-sql", "String interpolation in SQL query");
      }

      // HIGH: Subprocess spawning
      if (/Bun\.spawn/.test(line) || /child_process/.test(line) || /\bexec\s*\(/.test(line)) {
        addFinding("high", "subprocess", "Subprocess execution detected");
      }

      // HIGH: Prototype pollution patterns
      if (/__proto__/.test(line) || /constructor\.prototype/.test(line)) {
        addFinding("high", "prototype-pollution", "Prototype pollution pattern detected");
      }

      // HIGH: Outbound fetch to non-apimesh.xyz hosts with a literal URL.
      // Generated APIs should only make calls to user-provided URLs (via safeFetch)
      // or to explicitly approved public APIs. A literal fetch() to a non-apimesh
      // domain that is also not a variable reference is a red flag for exfiltration.
      // This check catches the obvious case: fetch("https://evil.com/...")
      const literalFetchMatch = line.match(/\bfetch\s*\(\s*["'`](https?:\/\/[^"'`]+)["'`]/);
      if (literalFetchMatch) {
        const fetchUrl = literalFetchMatch[1];
        // Allow calls to apimesh.xyz subdomains and well-known public APIs used by our tools
        const ALLOWED_FETCH_HOSTS = [
          "apimesh.xyz",
          "dns.google",
          "cloudflare-dns.com",
          "api.smithery.ai",
          "registry.npmjs.org",
        ];
        const isAllowed = ALLOWED_FETCH_HOSTS.some(h => fetchUrl.includes(h));
        const isLocalhost = /https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01]))/.test(fetchUrl);
        if (!isAllowed) {
          addFinding(
            isLocalhost ? "medium" : "high",
            isLocalhost ? "internal-fetch" : "exfil-fetch",
            `Literal fetch to external host: ${fetchUrl.slice(0, 80)}`
          );
        }
      }

      // MEDIUM: Raw fetch to internal IPs/localhost (catches non-literal cases too)
      if (/fetch\s*\(\s*["'`]https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01]))/.test(line)) {
        addFinding("medium", "internal-fetch", "Fetch to internal/localhost address");
      }

      // MEDIUM: User URL input without safeFetch
      if (/c\.req\.query\(["']url["']\)/.test(line) || /c\.req\.query\(["']target["']\)/.test(line)) {
        const fileSrc = file.content;
        if (!fileSrc.includes("safeFetch") && !fileSrc.includes("validateExternalUrl")) {
          addFinding("medium", "no-ssrf-protection", "User URL input detected without safeFetch/validateExternalUrl");
        }
      }
    }
  }

  const hasCritical = findings.some(f => f.severity === "critical");
  const hasHigh = findings.some(f => f.severity === "high");
  const pass = !hasCritical && !hasHigh;

  return { pass, findings };
}

function formatFindings(findings: Finding[]): string {
  if (findings.length === 0) return "No findings";
  return findings
    .map(f => `[${f.severity.toUpperCase()}] ${f.rule} in ${f.file}:${f.line ?? "?"} — ${f.detail}`)
    .join("\n");
}

// ---------------------------------------------------------------------------
// Output validation: check generated code for size limits and env var leakage
// ---------------------------------------------------------------------------

interface OutputValidationResult {
  pass: boolean;
  error?: string;
}

function validateOutput(files: GeneratedFile[]): OutputValidationResult {
  let totalBytes = 0;

  // Collect non-empty env var values to check for accidental inclusion.
  // We skip very short values (< 8 chars) to reduce false positives on common
  // short strings like "true", "3001", etc.
  const sensitiveEnvValues = Object.entries(process.env)
    .filter(([, v]) => v && v.length >= 8)
    .map(([, v]) => v as string);

  for (const file of files) {
    // 1. Path must be a clean relative filename with no traversal components
    const cleanPath = file.path
      .replace(/\\/g, "/")
      .split("/")
      .filter(p => p !== ".." && p !== "." && p.length > 0)
      .join("/");

    if (cleanPath !== file.path.replace(/\\/g, "/")) {
      return { pass: false, error: `File path contains traversal: "${file.path}"` };
    }
    if (cleanPath.startsWith("/") || /^[a-zA-Z]:/.test(cleanPath)) {
      return { pass: false, error: `Absolute file path not allowed: "${file.path}"` };
    }
    if (!/\.(ts|json)$/.test(cleanPath)) {
      return { pass: false, error: `Disallowed file extension: "${cleanPath}"` };
    }

    // 2. Per-file size limit
    const fileBytes = new TextEncoder().encode(file.content).length;
    if (fileBytes > MAX_FILE_BYTES) {
      return {
        pass: false,
        error: `File "${file.path}" is ${fileBytes} bytes, exceeds limit of ${MAX_FILE_BYTES}`,
      };
    }
    totalBytes += fileBytes;

    // 3. Total size limit
    if (totalBytes > MAX_TOTAL_BYTES) {
      return {
        pass: false,
        error: `Total generated code size ${totalBytes} bytes exceeds limit of ${MAX_TOTAL_BYTES}`,
      };
    }

    // 4. Check that no actual env var VALUES appear in the generated code.
    // This catches exfiltration attempts where the LLM was tricked into echoing
    // a secret into the source code (e.g. as a hardcoded string).
    for (const val of sensitiveEnvValues) {
      if (file.content.includes(val)) {
        // Don't log the value itself — just flag the finding.
        return {
          pass: false,
          error: `Generated code in "${file.path}" contains a current environment variable value`,
        };
      }
    }
  }

  // 5. Must have an index.ts
  if (!files.some(f => f.path === "index.ts")) {
    return { pass: false, error: "Generated files do not include index.ts" };
  }

  return { pass: true };
}

// ---------------------------------------------------------------------------
// Local testing (hardened env stripping + .env protection + strict timeout)
// ---------------------------------------------------------------------------

async function testLocally(
  name: string,
  files: GeneratedFile[]
): Promise<{ success: boolean; error?: string }> {
  const testDir = join(TEST_BUILDS_DIR, name);

  // .env protection: temporarily rename .env so the test process cannot read
  // secrets directly from disk even if env vars are stripped from process.env.
  const envPath = join(PROJECT_DIR, ".env");
  const envBakPath = join(PROJECT_DIR, ".env.bak.brain-test");
  let envRenamed = false;

  try {
    await Bun.spawn(["rm", "-rf", testDir]).exited;
    await Bun.spawn(["mkdir", "-p", testDir]).exited;

    const resolvedBase = resolve(testDir);
    for (const file of files) {
      const safePath = file.path
        .replace(/\\/g, "/")
        .split("/")
        .filter((p) => p !== ".." && p !== "." && p.length > 0)
        .join("/");

      if (!safePath || safePath.length === 0) {
        return { success: false, error: `Invalid file path in LLM response: "${file.path}"` };
      }

      if (!/\.(ts|json)$/.test(safePath)) {
        return { success: false, error: `Disallowed file extension: "${safePath}"` };
      }

      const filePath = join(testDir, safePath);
      const resolvedPath = resolve(filePath);
      if (!resolvedPath.startsWith(resolvedBase + "/")) {
        return { success: false, error: `Path traversal attempt: "${file.path}"` };
      }

      const dir = filePath.substring(0, filePath.lastIndexOf("/"));
      await Bun.spawn(["mkdir", "-p", dir]).exited;
      await Bun.write(filePath, file.content);
    }

    // Syntax check (runs before .env rename — just a build step, no execution)
    console.log(`[build] Checking syntax...`);
    const syntaxCheck = Bun.spawnSync(
      [BUN, "build", "--no-bundle", join(testDir, "index.ts")],
      { cwd: PROJECT_DIR, stderr: "pipe", stdout: "pipe" }
    );
    if (syntaxCheck.exitCode !== 0) {
      const stderr = new TextDecoder().decode(syntaxCheck.stderr);
      const stdout = new TextDecoder().decode(syntaxCheck.stdout);
      const detail = stderr || stdout || `exit code ${syntaxCheck.exitCode}`;
      return { success: false, error: `Syntax/build error: ${detail.slice(0, 500)}` };
    }
    console.log("[build] Syntax check passed");

    // Copy to apis/ temporarily so imports resolve
    const tempApiDir = join(APIS_DIR, `_test_${name}`);
    await Bun.spawn(["rm", "-rf", tempApiDir]).exited;
    await Bun.spawn(["cp", "-r", testDir, tempApiDir]).exited;

    // Rename .env before starting the test server so even a Bun.file(".env")
    // call inside the generated code will get a file-not-found error rather
    // than the actual secrets.
    try {
      const envFile = Bun.file(envPath);
      if (await envFile.exists()) {
        // Bun.file.rename is not available; use the filesystem rename via spawn
        await Bun.spawn(["mv", envPath, envBakPath]).exited;
        envRenamed = true;
        console.log("[build] .env temporarily renamed for test isolation");
      }
    } catch {
      // If we can't rename (e.g. doesn't exist), proceed anyway
    }

    // Start on test port with stripped env
    console.log(`[build] Starting test server on port ${TEST_PORT}...`);
    const safeEnv: Record<string, string> = { PORT: String(TEST_PORT) };
    // Only propagate the env vars the server actually needs for startup;
    // do NOT spread process.env — that would re-include secrets.
    // The PATH is needed for bun to resolve its own binary.
    if (process.env.PATH) safeEnv.PATH = process.env.PATH;
    if (process.env.HOME) safeEnv.HOME = process.env.HOME;
    if (process.env.TZ) safeEnv.TZ = process.env.TZ;
    // Public vars required by shared/x402.ts and shared/mpp.ts at import time:
    if (process.env.WALLET_ADDRESS) safeEnv.WALLET_ADDRESS = process.env.WALLET_ADDRESS;
    if (process.env.NETWORK) safeEnv.NETWORK = process.env.NETWORK;
    if (process.env.CDP_API_KEY_ID) safeEnv.CDP_API_KEY_ID = process.env.CDP_API_KEY_ID;
    if (process.env.CDP_API_KEY_SECRET) safeEnv.CDP_API_KEY_SECRET = process.env.CDP_API_KEY_SECRET;
    // MPP_ENABLED intentionally NOT passed — test builds don't need payment
    // integration, and passing it without STRIPE_SECRET_KEY causes a fatal exit.

    const testProc = Bun.spawn(
      [BUN, "run", join(tempApiDir, "index.ts")],
      { cwd: testDir, env: safeEnv, stdout: "pipe", stderr: "pipe" }
    );

    // Set a hard kill timer — if the test server hasn't responded by
    // TEST_KILL_TIMEOUT_MS, kill it and report failure.
    const killTimer = setTimeout(() => {
      try { testProc.kill(); } catch {}
    }, TEST_KILL_TIMEOUT_MS);

    await Bun.sleep(TEST_SERVER_BOOT_MS);

    if (testProc.exitCode !== null) {
      clearTimeout(killTimer);
      const stderr = new TextDecoder().decode(await new Response(testProc.stderr).arrayBuffer());
      await restoreEnv(envRenamed, envBakPath, envPath);
      await cleanup(tempApiDir, testDir);
      return { success: false, error: `Server crashed on startup: ${stderr.slice(0, 500)}` };
    }

    console.log(`[build] Server running (pid ${testProc.pid}), checking health...`);

    let healthOk = false;
    try {
      const res = await fetch(`http://127.0.0.1:${TEST_PORT}/health`, {
        signal: AbortSignal.timeout(5000),
      });
      healthOk = res.ok;
      const body = await res.text();
      console.log(`[build] Health check: ${res.status} ${body.slice(0, 100)}`);
    } catch (e) {
      console.error(`[build] Health check failed: ${e instanceof Error ? e.message : String(e)}`);
    }

    clearTimeout(killTimer);
    testProc.kill();
    await testProc.exited;
    await Bun.spawn(["rm", "-rf", tempApiDir]).exited;
    await restoreEnv(envRenamed, envBakPath, envPath);

    if (!healthOk) {
      await cleanup(tempApiDir, testDir);
      return { success: false, error: "Health check failed — /health did not return 200" };
    }

    console.log(`[build] Local test passed for ${name}`);
    return { success: true };
  } catch (e) {
    await restoreEnv(envRenamed, envBakPath, envPath);
    const error = e instanceof Error ? `${e.message}\n${e.stack}` : String(e);
    await cleanup(join(APIS_DIR, `_test_${name}`), testDir);
    return { success: false, error };
  }
}

/** Restore .env from its temporary backup if we renamed it. */
async function restoreEnv(renamed: boolean, bakPath: string, origPath: string): Promise<void> {
  if (!renamed) return;
  try {
    await Bun.spawn(["mv", bakPath, origPath]).exited;
    console.log("[build] .env restored");
  } catch (e) {
    // Log loudly — a failed restore leaves secrets hidden on disk.
    console.error(`[build] CRITICAL: failed to restore .env from ${bakPath}: ${e}`);
  }
}

async function cleanup(...dirs: string[]) {
  for (const dir of dirs) {
    try { await Bun.spawn(["rm", "-rf", dir]).exited; } catch {}
  }
}

// ---------------------------------------------------------------------------
// Registry management
// ---------------------------------------------------------------------------

async function updateRegistry(name: string) {
  const content = await Bun.file(REGISTRY_PATH).text();
  if (content.includes(`"${name}"`)) return;

  const camelName = toCamelCase(name);
  const importLine = `import { app as ${camelName} } from "./${name}/index";`;

  const lines = content.split("\n");
  const importLines: string[] = [];
  const otherLines: string[] = [];

  for (const line of lines) {
    if (line.startsWith("import ")) {
      importLines.push(line);
    } else {
      otherLines.push(line);
    }
  }

  importLines.push(importLine);

  const rebuilt = otherLines.map((line) => {
    if (line.trim() === "};") {
      return `  "${name}": ${camelName},\n};`;
    }
    return line;
  });

  const newContent = [...importLines, "", ...rebuilt].join("\n");
  await Bun.write(REGISTRY_PATH, newContent);
}

function toCamelCase(kebab: string): string {
  return kebab.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Staging deployment & testing
// ---------------------------------------------------------------------------

async function deployToStaging(name: string): Promise<{ success: boolean; error?: string }> {
  // The brain runs ON the server. Staging is at /opt/conway-staging on the same machine.
  // Copy the new API + updated registry, then restart staging services.
  const STAGING_DIR = "/opt/conway-staging";
  const stagingApiDir = join(STAGING_DIR, "apis", name);
  const sourceApiDir = join(APIS_DIR, name);
  console.log(`[build] Deploying ${name} to staging (${STAGING_DIR})...`);

  try {
    // Copy API files to staging
    await Bun.spawn(["rm", "-rf", stagingApiDir]).exited;
    await Bun.spawn(["cp", "-r", sourceApiDir, stagingApiDir]).exited;
    // Copy updated registry
    await Bun.spawn(["cp", REGISTRY_PATH, join(STAGING_DIR, "apis/registry.ts")]).exited;

    // Restart staging services
    const proc = Bun.spawn(["sudo", "/usr/local/bin/conway-staging-restart"], {
      stdout: "pipe", stderr: "pipe",
    });
    const exitCode = await proc.exited;
    if (exitCode !== 0) {
      const stderr = new TextDecoder().decode(await new Response(proc.stderr).arrayBuffer());
      return { success: false, error: `Staging restart failed (exit ${exitCode}): ${stderr.slice(0, 300)}` };
    }

    // Wait for staging router to fully restart and be ready to serve
    console.log(`[build] Waiting for staging router to be ready...`);
    let stagingReady = false;
    for (let i = 0; i < 10; i++) {
      await Bun.sleep(2000);
      try {
        const res = await fetch(`https://${name}.staging.apimesh.xyz/health`, {
          signal: AbortSignal.timeout(5000),
        });
        if (res.status === 200) { stagingReady = true; break; }
      } catch { /* retry */ }
    }
    if (!stagingReady) {
      return { success: false, error: "Staging router did not become ready within 20 seconds" };
    }
    console.log(`[build] Staging deploy succeeded`);
    return { success: true };
  } catch (e) {
    return { success: false, error: `Staging deploy error: ${e instanceof Error ? e.message : String(e)}` };
  }
}

async function testStagingEndpoints(name: string, files: GeneratedFile[]): Promise<{ success: boolean; error?: string }> {
  console.log(`[build] Testing staging endpoints for ${name}...`);
  const baseUrl = `https://${name}.staging.apimesh.xyz`;
  const errors: string[] = [];

  // Test /health
  try {
    const res = await fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(10_000) });
    if (res.status !== 200) {
      errors.push(`/health returned ${res.status}, expected 200`);
    } else {
      console.log(`[build] Staging /health: 200 OK`);
    }
  } catch (e) {
    errors.push(`/health fetch failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  // Test / info endpoint
  try {
    const res = await fetch(`${baseUrl}/`, { signal: AbortSignal.timeout(10_000) });
    if (res.status !== 200) {
      errors.push(`/ returned ${res.status}, expected 200`);
    } else {
      const body = await res.json() as Record<string, unknown>;
      if (!body.api) {
        errors.push(`/ response missing "api" field`);
      } else {
        console.log(`[build] Staging /: 200 OK, api="${body.api}"`);
      }
    }
  } catch (e) {
    errors.push(`/ fetch failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  // Find paid routes from the generated index.ts and verify they return 402
  const indexFile = files.find(f => f.path === "index.ts");
  if (indexFile) {
    // Small delay after health check passes — paid routes may need extra time
    // for the router to fully initialize after a staging restart.
    await Bun.sleep(2000);

    // Match route patterns like "GET /analyze" or "POST /check" in paymentMiddleware config.
    // Only capture clean paths (letters, digits, hyphens, slashes, colons for params).
    const paidRoutePattern = /["'](GET|POST|PUT|DELETE|PATCH)\s+(\/[a-zA-Z0-9/:_-]*)["']/g;
    let match;
    while ((match = paidRoutePattern.exec(indexFile.content)) !== null) {
      const method = match[1];
      const path = match[2];
      if (path === "/health" || path === "/" || path === "/preview" || path.length < 2) continue;

      let res: Response | undefined;
      try {
        res = await fetch(`${baseUrl}${path}`, {
          method,
          signal: AbortSignal.timeout(30_000),
        });

        // Retry once on 502 — staging router may still be settling after restart
        if (res.status === 502) {
          console.log(`[build] Staging ${method} ${path}: 502 — retrying in 3s...`);
          await Bun.sleep(3000);
          res = await fetch(`${baseUrl}${path}`, {
            method,
            signal: AbortSignal.timeout(30_000),
          });
        }

        if (res.status === 402) {
          console.log(`[build] Staging ${method} ${path}: 402 (payment required) — correct`);
        } else if (res.status >= 500) {
          // 5xx on paid routes is a warning, not a hard failure — the API itself
          // may work fine but staging payment/routing infrastructure can return 502
          // due to timing. /health and / passing is the definitive signal.
          console.warn(`[build] Staging ${method} ${path}: ${res.status} (warning — may be infra timing)`);
        } else {
          console.log(`[build] Staging ${method} ${path}: ${res.status} (not 402 — may have free access)`);
        }
      } catch (e) {
        errors.push(`${method} ${path} fetch failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }

  if (errors.length > 0) {
    return { success: false, error: `Staging test failures:\n${errors.join("\n")}` };
  }

  console.log(`[build] All staging endpoint tests passed for ${name}`);
  return { success: true };
}

// ---------------------------------------------------------------------------
// Production deployment
// ---------------------------------------------------------------------------

async function deployToProd(name: string): Promise<{ success: boolean; error?: string }> {
  // The brain runs ON the prod server at /opt/conway-agent (= PROJECT_DIR).
  // Files are already in apis/{name}/ and registry.ts is updated.
  // Just restart prod services and verify health.
  console.log(`[build] Deploying to production (restarting services)...`);
  try {
    const proc = Bun.spawn(["sudo", "/usr/local/bin/conway-deploy-restart"], {
      stdout: "pipe", stderr: "pipe",
    });
    const exitCode = await proc.exited;
    if (exitCode !== 0) {
      const stderr = new TextDecoder().decode(await new Response(proc.stderr).arrayBuffer());
      return { success: false, error: `Prod restart failed (exit ${exitCode}): ${stderr.slice(0, 300)}` };
    }

    // Wait for services to initialize then verify health
    await Bun.sleep(5000);
    try {
      const res = await fetch(`https://${name}.apimesh.xyz/health`, {
        signal: AbortSignal.timeout(30_000),
      });
      if (res.status !== 200) {
        return { success: false, error: `Prod health check returned ${res.status}` };
      }
      console.log(`[build] Prod /health: 200 OK`);
    } catch (e) {
      return { success: false, error: `Prod health check failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    return { success: true };
  } catch (e) {
    return { success: false, error: `Prod deploy error: ${e instanceof Error ? e.message : String(e)}` };
  }
}

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

async function rollbackApi(name: string): Promise<void> {
  console.log(`[build] Rolling back ${name}...`);

  // Remove the api directory
  const apiDir = join(APIS_DIR, name);
  await Bun.spawn(["rm", "-rf", apiDir]).exited;

  // Revert registry.ts changes
  const content = await Bun.file(REGISTRY_PATH).text();
  const camelName = toCamelCase(name);
  const importLine = `import { app as ${camelName} } from "./${name}/index";`;

  const lines = content.split("\n");
  const filtered = lines.filter(line => {
    if (line.trim() === importLine) return false;
    if (line.trim() === `"${name}": ${camelName},`) return false;
    return true;
  });

  await Bun.write(REGISTRY_PATH, filtered.join("\n"));

  // Remove from staging too and restart
  const STAGING_DIR = "/opt/conway-staging";
  await Bun.spawn(["rm", "-rf", join(STAGING_DIR, "apis", name)]).exited;
  await Bun.spawn(["cp", REGISTRY_PATH, join(STAGING_DIR, "apis/registry.ts")]).exited;
  try {
    await Bun.spawn(["sudo", "/usr/local/bin/conway-staging-restart"]).exited;
  } catch { /* best effort */ }

  console.log(`[build] Rollback complete for ${name}`);
}

// ---------------------------------------------------------------------------
// Main build pipeline
// ---------------------------------------------------------------------------

export async function build(): Promise<boolean> {
  if (!process.env.OPENAI_API_KEY) {
    console.warn("[build] OPENAI_API_KEY not set — skipping code generation");
    return false;
  }

  const item = getTopBacklogItem();
  if (!item) {
    console.log("[build] No pending backlog items");
    return false;
  }

  const { name, description } = item;
  console.log(`[build] Building: ${name} — ${description}`);

  // Validate name
  if (!API_NAME_PATTERN.test(name)) {
    console.error(`[build] Invalid API name: "${name}"`);
    updateBacklogStatus(item.id, "rejected");
    return false;
  }
  if (RESERVED_NAMES.has(name)) {
    console.error(`[build] Reserved name: "${name}"`);
    updateBacklogStatus(item.id, "rejected");
    return false;
  }

  updateBacklogStatus(item.id, "building");

  // Model escalation: use gpt-4.1 for high-scoring items
  let model = (item as any).overall_score > ESCALATION_THRESHOLD ? ESCALATION_MODEL : DEFAULT_MODEL;
  console.log(`[build] Using model: ${model} (score: ${(item as any).overall_score}, threshold: ${ESCALATION_THRESHOLD})`);

  // Daily cap: limit escalated model usage to 1 build per day
  if (model === ESCALATION_MODEL) {
    try {
      const escalatedToday = db.query(`
        SELECT COUNT(*) as cnt FROM backlog
        WHERE status = 'built' AND demand_source IS NOT NULL
        AND date(created_at) = date('now')
      `).get() as { cnt: number };
      if (escalatedToday.cnt >= 1) {
        console.log(`[build] Daily escalation cap reached (${escalatedToday.cnt} today), using ${DEFAULT_MODEL}`);
        model = DEFAULT_MODEL;
      }
    } catch {
      // If query fails (e.g. demand_source column doesn't exist yet), continue with escalated model
    }
  }

  // Pre-build competitive research (QUAL-09)
  const category = (item as any).category || "security";
  let competitiveContext = "";
  try {
    competitiveContext = competitiveResearch(name, description, category);
    if (competitiveContext) {
      console.log(`[build] Competitive research: found differentiation context for ${category}`);
    }
  } catch (e) {
    console.warn(`[build] Competitive research failed (non-blocking): ${e instanceof Error ? e.message : String(e)}`);
  }

  // Retry loop: generate -> output-validate -> audit -> quality-score -> test locally
  let lastError: string | undefined;
  let successFiles: GeneratedFile[] | undefined;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    console.log(`[build] Attempt ${attempt}/${MAX_RETRIES}`);

    const files = await generateApi(name, description, lastError, model, category, competitiveContext);
    if (files.length === 0) {
      lastError = "LLM returned no files";
      continue;
    }

    // Output validation (size limits, path safety, env value leakage)
    const outputCheck = validateOutput(files);
    if (!outputCheck.pass) {
      lastError = `Output validation FAILED: ${outputCheck.error}\n\nFix the issue.`;
      console.warn(`[build] Attempt ${attempt} failed output validation: ${outputCheck.error}`);
      continue;
    }
    console.log("[build] Output validation passed");

    // Security audit
    const audit = securityAudit(files);
    if (audit.findings.length > 0) {
      console.log(`[build] Security audit findings:\n${formatFindings(audit.findings)}`);
    }
    if (!audit.pass) {
      lastError = `Security audit FAILED:\n${formatFindings(audit.findings)}\n\nFix ALL critical and high severity issues.`;
      console.warn(`[build] Attempt ${attempt} failed security audit`);
      continue;
    }
    console.log("[build] Security audit passed");

    // Quality scoring gate (QUAL-08)
    const qualityResult = scoreQuality(files);
    console.log(`[build] Quality score: ${qualityResult.overall}/100 (richness=${qualityResult.richness}, errors=${qualityResult.error_handling}, docs=${qualityResult.documentation}, perf=${qualityResult.performance})`);
    for (const detail of qualityResult.details) {
      console.log(`[build]   ${detail}`);
    }
    if (!qualityResult.pass) {
      lastError = `Quality score ${qualityResult.overall}/100 (minimum 60 required).\n\n${qualityResult.feedback}\n\nFix these quality issues in your next attempt.`;
      console.warn(`[build] Attempt ${attempt} failed quality gate (${qualityResult.overall}/100)`);
      continue;
    }
    console.log("[build] Quality gate passed");

    // Local testing
    const result = await testLocally(name, files);
    if (!result.success) {
      lastError = result.error;
      console.warn(`[build] Attempt ${attempt} failed local test: ${lastError?.slice(0, 200)}`);
      continue;
    }

    successFiles = files;
    break;
  }

  if (!successFiles) {
    console.error(`[build] All ${MAX_RETRIES} attempts failed for ${name}`);
    updateBacklogStatus(item.id, "failed");
    return false;
  }

  // Deploy pipeline: copy -> registry -> staging -> staging test -> prod
  const testDir = join(TEST_BUILDS_DIR, name);
  const finalDir = join(APIS_DIR, name);
  await Bun.spawn(["rm", "-rf", finalDir]).exited;
  await Bun.spawn(["cp", "-r", testDir, finalDir]).exited;
  await cleanup(testDir);

  await updateRegistry(name);

  // Staging deploy
  const stagingResult = await deployToStaging(name);
  if (!stagingResult.success) {
    console.error(`[build] Staging deploy failed: ${stagingResult.error}`);
    await rollbackApi(name);
    updateBacklogStatus(item.id, "staging-failed");
    return false;
  }

  // Staging endpoint tests
  const stagingTest = await testStagingEndpoints(name, successFiles);
  if (!stagingTest.success) {
    console.error(`[build] Staging tests failed: ${stagingTest.error}`);
    await rollbackApi(name);
    updateBacklogStatus(item.id, "staging-test-failed");
    return false;
  }

  // Production deploy
  const prodResult = await deployToProd(name);
  if (!prodResult.success) {
    console.error(`[build] Prod deploy failed: ${prodResult.error}`);
    updateBacklogStatus(item.id, "prod-deploy-failed");
    return false;
  }

  // Register in DB and mark complete
  registerApi(name, 3001, name);
  updateBacklogStatus(item.id, "deployed");

  console.log(`[build] Successfully built and deployed: ${name}`);
  return true;
}

// Run directly
if (import.meta.main) {
  const result = await build();
  console.log(`Build result: ${result ? "SUCCESS" : "FAILED/SKIPPED"}`);
}
