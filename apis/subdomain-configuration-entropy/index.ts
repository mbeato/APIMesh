import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl, safeFetch } from "../../shared/ssrf";
import { analyzeSubdomainConfigurations, analyzeSubdomainPreview, SubdomainConfigEntropyResult, SubdomainConfigEntropyPreviewResult } from "./analyzer";

const app = new Hono();
const API_NAME = "subdomain-configuration-entropy";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit (5+ checks, scoring, detailed report): $0.01
const PRICE_NUM = 0.01;
const SUBDOMAIN = "subdomain-configuration-entropy.apimesh.xyz";

// CORS middleware open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit policies
// Because analysis is expensive, limit accordingly
app.use("/analyze", rateLimit("subdomain-configuration-entropy-analyze", 20, 60_000));
app.use("/preview", rateLimit("subdomain-configuration-entropy-preview", 30, 60_000));
app.use("*", rateLimit("subdomain-configuration-entropy-global", 90, 60_000));

// Extract payer wallet address
app.use("*", extractPayerWallet());
// API logger with pricing
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint after rate limiting and logging
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    description: "Analyze DNS configurations across subdomains to detect misconfigurations, anomalies, and inconsistent security policies.",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/preview",
          description: "Free preview analysis of DNS record diversity and basic inconsistency detection based on a subset of subdomains.",
          parameters: ["domain (string): The domain name to analyze, e.g. example.com"],
          example_response: {
            status: "ok",
            data: {
              domain: "example.com",
              subdomainsScanned: 10,
              distinctDnsRecords: 4,
              txtRecordsDiversity: 0.35,
              cNameConsistencyScore: 78,
              explanation: "Preview analysis on a sample of subdomains for quick insight.",
              grade: 80,
              recommendations: [{ issue: "High TXT record diversity", severity: "medium", suggestion: "Standardize TXT records to prevent delivery issues." }]
            },
            meta: { timestamp: "2023-01-01T00:00:00Z", duration_ms: 1500, api_version: "1.0.0" }
          }
        },
        {
          method: "GET",
          path: "/analyze",
          description: "Comprehensive paid endpoint performing multiple DNS fetches, TXT, CNAME and other record checks across many subdomains, with scoring and detailed report.",
          parameters: ["domain (string): The domain name to analyze, e.g. example.com"],
          example_response: {
            status: "ok",
            data: {
              domain: "example.com",
              totalSubdomainsAnalyzed: 50,
              uniqueDnsRecords: 12,
              txtEntropyScore: 68,
              cnameConsistencyGrade: "B",
              ttlStabilityScore: 75,
              anomalyDetections: ["3 subdomains have missing SPF TXT record."],
              grade: 72,
              explanation: "Comprehensive analysis combining multiple DNS record types and metrics to evaluate subdomain configuration stability.",
              recommendations: [
                {
                  issue: "Missing SPF records",
                  severity: "high",
                  suggestion: "Add SPF TXT records to all subdomains sending email to improve deliverability."
                },
                {
                  issue: "Inconsistent CNAME target",
                  severity: "medium",
                  suggestion: "Standardize CNAME targets to a central service or hostname where applicable."
                }
              ]
            },
            meta: { timestamp: "2023-01-01T00:00:00Z", duration_ms: 6500, api_version: "1.0.0" }
          }
        }
      ],
      parameters: [
        { name: "domain", type: "string", description: "Root domain to analyze, e.g. example.com" }
      ],
      examples: [
        "GET /preview?domain=example.com",
        "GET /analyze?domain=example.com"
      ]
    },
    pricing: {
      preview: "$0 (free preview limited to 10 subdomains)",
      analyze: PRICE
    },
    subdomain: SUBDOMAIN
  });
});

// Free preview endpoint - analyze a small sample set of subdomains
app.get("/preview", async (c) => {
  const domain = c.req.query("domain");
  if (typeof domain !== "string" || domain.trim().length === 0) {
    return c.json({ error: "Missing or invalid ?domain= parameter (e.g. example.com)" }, 400);
  }
  if (domain.length > 253) {
    return c.json({ error: "Domain name too long" }, 400);
  }
  try {
    const start = performance.now();
    const result = await analyzeSubdomainPreview(domain.trim());
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0",
      },
    });
  } catch (e: unknown) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Spend cap middleware
app.use("*", spendCapMiddleware());

// Payment middleware with paidRouteWithDiscovery
app.use(
  "*",
  paymentMiddleware(
    {
      "GET /analyze": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive DNS configuration audit across subdomains with scoring, anomaly detection, and recommendations",
        {
          input: { domain: "example.com" },
          inputSchema: {
            type: "object",
            properties: {
              domain: { type: "string", description: "Root domain to analyze" },
            },
            required: ["domain"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid analyze endpoint
app.get("/analyze", async (c) => {
  const domain = c.req.query("domain");
  if (typeof domain !== "string" || domain.trim().length === 0) {
    return c.json({ error: "Missing or invalid ?domain= parameter (e.g. example.com)" }, 400);
  }
  if (domain.length > 253) {
    return c.json({ error: "Domain name too long" }, 400);
  }

  try {
    const start = performance.now();
    const result = await analyzeSubdomainConfigurations(domain.trim());
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0",
      },
    });
  } catch (e: unknown) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} analyze error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Error handler (pass through HTTPExceptions for 402s)
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
