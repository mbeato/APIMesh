import { test, expect } from "bun:test";
import { scoreQuality, type QualityScore } from "./quality-scorer";

interface GeneratedFile {
  path: string;
  content: string;
}

// ---------- Fixtures ----------

const HIGH_QUALITY_FILES: GeneratedFile[] = [
  {
    path: "index.ts",
    content: `
import { Hono } from "hono";
import { safeFetch, readBodyCapped } from "../../shared/ssrf";

const app = new Hono();

interface AnalysisResult {
  url: string;
  severity: number;
  score: number;
  grade: string;
  explanation: string;
  recommendations: string[];
  protocol_version: string;
  certificate_valid: boolean;
  headers_present: string[];
  issues_found: string[];
}

/** Performs deep SSL/TLS analysis on the target URL */
app.get("/", (c) => c.json({
  api: "ssl-check",
  status: "healthy",
  docs: {
    endpoints: { "/check": "Analyze SSL configuration" },
    parameters: { url: "Target URL to analyze" },
  },
  pricing: "$0.005 per call via x402",
  examples: {
    request: "GET /check?url=https://example.com",
    response: { severity: 85, grade: "A", explanation: "Strong SSL configuration" },
  },
}));

app.get("/check", async (c) => {
  const url = c.req.query("url");
  if (!url) {
    return c.json({ error: "Missing ?url= parameter" }, 400);
  }

  try {
    const [certRes, headerRes] = await Promise.all([
      safeFetch(url, { signal: AbortSignal.timeout(10000) }),
      safeFetch(url, { signal: AbortSignal.timeout(10000) }),
    ]);
    const certBody = await readBodyCapped(certRes, 50000);
    const headerBody = await readBodyCapped(headerRes, 50000);

    const result: AnalysisResult = {
      url,
      severity: 85,
      score: 92,
      grade: "A",
      explanation: "Strong SSL configuration with modern cipher suites",
      recommendations: ["Enable HSTS preload", "Add CAA records"],
      protocol_version: "TLSv1.3",
      certificate_valid: true,
      headers_present: ["Strict-Transport-Security"],
      issues_found: [],
    };

    return c.json({ status: "ok", data: result, meta: { timestamp: Date.now(), duration_ms: 120, api_version: "1.0" } });
  } catch (e: any) {
    if (e.name === "TimeoutError") {
      return c.json({ error: "Request timed out", detail: e.message }, 504);
    }
    return c.json({ error: "Analysis failed", detail: e.message }, 500);
  }
});

export default app;
`,
  },
];

const LOW_QUALITY_FILES: GeneratedFile[] = [
  {
    path: "index.ts",
    content: `
import { Hono } from "hono";

const app = new Hono();

interface Result {
  url: string;
  ok: boolean;
}

app.get("/", (c) => c.json({ api: "basic-check" }));

app.get("/check", async (c) => {
  try {
    const res = await fetch("https://example.com");
  } catch (e) {}

  return c.json({ url: "test", ok: true });
});

export default app;
`,
  },
];

const ENVELOPE_FILES: GeneratedFile[] = [
  {
    path: "index.ts",
    content: `
import { Hono } from "hono";
const app = new Hono();

interface SimpleResult { url: string; ok: boolean; }

app.get("/check", async (c) => {
  const result: SimpleResult = { url: "test", ok: true };
  return c.json({ status: "ok", data: result, meta: { timestamp: Date.now() } });
});
export default app;
`,
  },
];

const NO_ENVELOPE_FILES: GeneratedFile[] = [
  {
    path: "index.ts",
    content: `
import { Hono } from "hono";
const app = new Hono();

interface SimpleResult { url: string; ok: boolean; }

app.get("/check", async (c) => {
  return c.json({ url: "test", ok: true });
});
export default app;
`,
  },
];

// ---------- Tests ----------

test("high quality files score >= 75 overall", () => {
  const result = scoreQuality(HIGH_QUALITY_FILES);
  expect(result.overall).toBeGreaterThanOrEqual(75);
  expect(result.pass).toBe(true);
});

test("low quality files score < 60 and fail", () => {
  const result = scoreQuality(LOW_QUALITY_FILES);
  expect(result.overall).toBeLessThan(60);
  expect(result.pass).toBe(false);
});

test("low quality feedback is actionable", () => {
  const result = scoreQuality(LOW_QUALITY_FILES);
  expect(result.feedback.length).toBeGreaterThan(0);
  // Should mention specific counts or actionable items, not generic messages
  expect(result.feedback).toMatch(/\d|field|catch|timeout|docs/i);
});

test("empty catch blocks don't count", () => {
  const result = scoreQuality(LOW_QUALITY_FILES);
  // LOW_QUALITY has an empty catch block -- error_handling should be low
  expect(result.error_handling).toBeLessThan(40);
});

test("richness detects envelope pattern", () => {
  const withEnvelope = scoreQuality(ENVELOPE_FILES);
  const withoutEnvelope = scoreQuality(NO_ENVELOPE_FILES);
  expect(withEnvelope.richness).toBeGreaterThan(withoutEnvelope.richness);
});

test("weights sum correctly", () => {
  const result = scoreQuality(HIGH_QUALITY_FILES);
  const expected =
    result.richness * 0.3 +
    result.error_handling * 0.25 +
    result.documentation * 0.2 +
    result.performance * 0.25;
  expect(Math.abs(result.overall - expected)).toBeLessThan(1);
});
