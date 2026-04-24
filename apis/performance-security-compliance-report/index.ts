import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl } from "../../shared/ssrf";
import { fullReport, previewReport, PerformanceReportResult, PreviewReportResult } from "./analyzer";

const app = new Hono();
const API_NAME = "performance-security-compliance-report";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit with 5+ checks, scoring, detailed report
const PRICE_NUM = 0.01;

// CORS setup with open origins and constraints
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits:
// preview endpoint max 20/min to ensure reliability
app.use("/preview", rateLimit("performance-compliance-preview", 20, 60_000));
// check endpoint max 10/min due to complexity
app.use("/check", rateLimit("performance-compliance-check", 10, 60_000));
// global per wallet limit
app.use("*", rateLimit("performance-compliance-global", 30, 60_000));

// Wallet extraction middleware
app.use("*", extractPayerWallet());

// API Logger using the price number for paid route
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint after rate limiting and logger
app.get("/", (c) => {
  const docs = {
    endpoints: [
      {
        method: "GET",
        path: "/preview",
        description: "Free preview combining fast performance, security headers, SSL, and DNS checks with brief grading.",
        parameters: [{ name: "url", type: "string", description: "Target URL (http(s)://...) to scan." }],
        exampleResponse: {
          status: "ok",
          data: {
            url: "https://example.com",
            summaryScore: 85,
            grades: { performance: "B", securityHeaders: "A", ssl: "A", dns: "B" },
            issuesDetected: 3,
          },
          meta: { timestamp: new Date().toISOString(), duration_ms: 234, api_version: "1.0.0" },
        },
      },
      {
        method: "GET",
        path: "/check",
        description: "Comprehensive payable audit combining performance metrics, security headers, SSL cert and DNS analysis with scoring and prioritized fix suggestions.",
        parameters: [{ name: "url", type: "string", description: "Target URL (http(s)://...) to scan." }],
        exampleResponse: {
          status: "ok",
          data: {
            url: "https://example.com",
            performanceScore: 92,
            securityHeaders: [/* array of detailed header analyses */],
            sslInfo: { valid: true, expiryDays: 120, strengthScore: 90 },
            dnsInfo: { recommendations: [], issues: [], dnsGrade: "A" },
            overallScore: 90,
            grade: "A",
            recommendations: [
              { issue: "HSTS missing preload", severity: 60, suggestion: "Add preload directive to HSTS header" },
            ],
            checkedAt: new Date().toISOString(),
          },
          meta: { timestamp: new Date().toISOString(), duration_ms: 1024, api_version: "1.0.0" },
        },
      },
    ],
    parameters: [
      { name: "url", type: "string", description: "A fully qualified URL including protocol to analyze." },
    ],
    examples: [
      { path: "/preview?url=https://example.com", description: "Free preview combined report." },
      { path: "/check?url=https://example.com", description: "Paid comprehensive audit with detailed findings." },
    ],
  };

  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs,
    pricing: { default: PRICE, description: "One price tier: comprehensive audit combining performance, security, SSL, and DNS analysis with scoring and recommendations." },
  });
});

// Spend cap middleware
app.use("*", spendCapMiddleware());

// Payment middleware enforced only on paid endpoints
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive audit combining performance metrics, security headers, SSL certificates, and DNS configurations with in-depth scoring and prioritized remediation suggestions",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "Target URL (http(s)://...) to analyze" },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer,
  ),
);

// Free preview endpoint - returns rapid combined analysis but less depth
app.get("/preview", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing ?url= parameter (HTTP or HTTPS URL)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const validation = validateExternalUrl(rawUrl.trim());
  if ("error" in validation) {
    return c.json({ error: validation.error }, 400);
  }

  try {
    const start = performance.now();
    const result = await previewReport(validation.url.toString());
    const duration_ms = Math.round(performance.now() - start);
    if ("error" in result) {
      return c.json({ error: result.error, detail: "Failed preview analysis" }, 400);
    }
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Paid detailed endpoint
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing ?url= parameter (HTTP or HTTPS URL)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const validation = validateExternalUrl(rawUrl.trim());
  if ("error" in validation) {
    return c.json({ error: validation.error }, 400);
  }

  try {
    const start = performance.now();
    const result = await fullReport(validation.url.toString());
    const duration_ms = Math.round(performance.now() - start);
    if ("error" in result) {
      return c.json({ error: result.error, detail: "Failed full report analysis" }, 400);
    }
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} check error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Error handler - pass through 402 (payment required) from x402
app.onError((err, c) => {
  if (typeof err === "object" && err !== null && "getResponse" in err) {
    return (err as any).getResponse();
  }
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

app.notFound((c) => c.json({ error: "Not found" }, 404));

export { app };

if (import.meta.main) console.log(`${API_NAME} listening on port ${PORT}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
