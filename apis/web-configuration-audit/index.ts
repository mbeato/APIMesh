import { Hono } from "hono";
import { cors } from "hono/cors";
import {
  paymentMiddleware,
  paidRouteWithDiscovery,
  resourceServer,
} from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import {
  safeFetch,
  validateExternalUrl,
} from "../../shared/ssrf";
import {
  WebConfigurationAuditResult,
  AuditRecommendations,
  AuditScore,
  runFullAudit,
  runPreviewAudit,
} from "./analyzer";

const app = new Hono();
const API_NAME = "web-configuration-audit";
const PORT = Number(process.env.PORT) || 3001;
const PRICE_STR = "$0.01"; // Comprehensive audit
const PRICE_NUM = 0.01;
const SUBDOMAIN = "web-configuration-audit.apimesh.xyz";

// CORS - open to all origins with needed headers
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before any rate limiting or payments
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate Limits
// Higher rate limits for /preview (free), stricter for /check (paid)
app.use("/preview", rateLimit("web-config-audit-preview", 20, 60_000));
app.use("/check", rateLimit("web-config-audit-check", 10, 60_000));
app.use("*", rateLimit("web-config-audit-global", 30, 60_000));

// Payer wallet extraction
app.use("*", extractPayerWallet());

// API Logger for all endpoints with correct price log for paid routes (but log something for preview)
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint (after rate limiter, before payment middleware)
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    description: "Performs an in-depth audit combining robots.txt, sitemap.xml, security headers, meta tags, and .env file presence for web configuration security, leaks, and compliance.",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/preview",
          description: "Free preview audit with limited checks and capped timeout.",
          parameters: [{ name: "url", type: "string", description: "URL to audit (http(s)://...)" }],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              summaryScore: 72,
              grade: "B",
              checksPerformed: ["robots.txt", "sitemap.xml", "headers"],
              recommendations: [
                { issue: "Missing robots.txt", severity: "medium", suggestion: "Create and configure robots.txt to control crawler access." }
              ],
              details: "This preview audit covers robots.txt, sitemap.xml, and key headers to give an initial assessment."
            },
            meta: { timestamp: "...", duration_ms: 1234, api_version: "1.0.0" }
          }
        },
        {
          method: "GET",
          path: "/check",
          description: "Comprehensive paid audit with detailed scoring, grade, meta tags, and .env leak detection.",
          parameters: [{ name: "url", type: "string", description: "URL to audit (http(s)://...)" }],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              checksPerformed: ["robots.txt", "sitemap.xml", "headers", "metaTags", ".envExposure"],
              scores: {
                robotsTxtScore: 95,
                sitemapScore: 90,
                headersScore: 80,
                metaTagsScore: 85,
                envExposureScore: 100,
                overallScore: 90,
                grade: "A"
              },
              recommendations: [
                { issue: "Unprotected .env file", severity: "high", suggestion: "Block access to .env via server configuration." },
                { issue: "Missing robots.txt", severity: "medium", suggestion: "Add robots.txt and disallow sensitive paths." }
              ],
              details: "Detailed audit identifies misconfigurations and possible security leaks with action suggestions."
            },
            meta: { timestamp: "...", duration_ms: 5678, api_version: "1.0.0" }
          }
        }
      ],
      parameters: [
        { name: "url", type: "string", description: "Target website URL to audit." }
      ],
      examples: [
        { request: "/preview?url=https://example.com", description: "Run free preview audit on example.com" },
        { request: "/check?url=https://example.com", description: "Run paid comprehensive audit on example.com" }
      ]
    },
    pricing: {
      symbolic: PRICE_STR,
      numeric: PRICE_NUM,
      explanation: "Comprehensive audit combining 5+ distinct checks with scoring, grading, and actionable remediation recommendations."
    },
    subdomain: SUBDOMAIN
  });
});

// Free preview endpoint
app.get("/preview", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing or invalid ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length (2048)" }, 400);
  }

  // Validate URL
  const validation = validateExternalUrl(rawUrl.trim());
  if ("error" in validation) {
    return c.json({ error: `Invalid URL: ${validation.error}` }, 400);
  }

  const signal = AbortSignal.timeout(20_000); // generous timeout for preview

  try {
    const auditResult = await runPreviewAudit(validation.url.toString(), signal);
    if ("error" in auditResult && !("summaryScore" in auditResult)) {
      return c.json({ error: auditResult.error }, 400);
    }
    const duration_ms = auditResult.duration_ms || 0;
    return c.json({
      status: "ok",
      data: auditResult,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0"
      }
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Payment and spend cap middlewares before paid endpoints
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE_STR,
        "Comprehensive audit combining robots.txt, sitemap.xml, HTTP headers, meta tags, and .env exposure detection with scoring and remediation.",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "URL to audit (http(s)://...)" },
            },
            required: ["url"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid endpoint
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing or invalid ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length (2048)" }, 400);
  }

  // Validate URL
  const validation = validateExternalUrl(rawUrl.trim());
  if ("error" in validation) {
    return c.json({ error: `Invalid URL: ${validation.error}` }, 400);
  }

  try {
    const result = await runFullAudit(validation.url.toString());
    if ("error" in result && !("scores" in result)) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms: result.duration_ms || 0,
        api_version: "1.0.0"
      }
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// On error handler, passes through 402 from x402 payment errors
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
