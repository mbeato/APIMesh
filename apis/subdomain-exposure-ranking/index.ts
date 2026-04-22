import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { safeFetch, validateExternalUrl } from "../../shared/ssrf";
import {
  analyzeSubdomains,
  analyzeExposures,
  EnrichedSubdomainResult,
  SubdomainExposureReport,
} from "./analyzer";

const app = new Hono();
const API_NAME = "subdomain-exposure-ranking";
const PORT = Number(process.env.PORT) || 3001;
const PRICE_NUMBER = 0.01; // $0.01 for comprehensive audit
const PRICE_STRING = "$0.01";
const SUBDOMAIN = "subdomain-exposure-ranking.apimesh.xyz";

// CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limiting: 15/min preview, 30/min full
app.use("/preview", rateLimit("subdomain-exposure-preview", 15, 60_000));
app.use("*", rateLimit("subdomain-exposure", 30, 60_000));

// Middleware chain
app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, PRICE_NUMBER));

// Info endpoint after rate limiting and logger
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    description:
      "Performs exhaustive subdomain enumeration via free DNS and certificate transparency logs, then assesses each subdomain for misconfigurations, exposure of sensitive endpoints, or outdated services, scoring risk and providing actionable recommendations.",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/preview",
          description:
            "Free preview: enumerates subdomains from DNS and CT logs (limited), scores exposure, returns summary report.",
          parameters: [
            { name: "domain", type: "string", description: "Root domain to enumerate and analyze" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              totalSubdomains: 4,
              subdomainsSample: [
                {
                  subdomain: "www.example.com",
                  score: 25,
                  grade: "C",
                  exposures: 1,
                  outdatedServices: 0,
                },
              ],
              overallScore: 65,
              overallGrade: "B",
              recommendations: [
                {
                  issue: "Open admin interface detected",
                  severity: 80,
                  suggestion: "Restrict access to admin.example.com by IP or VPN.",
                },
              ],
              checkedAt: "2024-06-01T12:00:00Z",
              explanation:
                "Preliminary scan based on DNS and CT logs. Detailed paid scan includes deeper checks.",
            },
            meta: {
              timestamp: "2024-06-01T12:00:00Z",
              duration_ms: 1200,
              api_version: "1.0.0",
            },
          },
        },
        {
          method: "GET",
          path: "/check",
          description:
            "Comprehensive paid scan: exhaustive enumeration from DNS, CT logs, plus HTTP endpoint probing, header analysis, TLS version checks, outdated service detection, with full scoring and rich recommendations.",
          parameters: [
            { name: "domain", type: "string", description: "Root domain to enumerate and analyze" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              totalSubdomains: 15,
              subdomains: [
                {
                  subdomain: "www.example.com",
                  score: 20,
                  grade: "D",
                  exposures: 2,
                  outdatedServices: 1,
                  details: {
                    httpHeaders: {
                      "server": "Apache",
                      "x-powered-by": "PHP/5.6",
                    },
                    tlsVersion: "TLS 1.2",
                  },
                  recommendations: [
                    {
                      issue: "Outdated PHP version",
                      severity: 90,
                      suggestion: "Upgrade PHP to 8.x to patch known vulnerabilities.",
                    },
                    {
                      issue: "Server header leaks info",
                      severity: 30,
                      suggestion: "Remove or obfuscate Server header.",
                    },
                  ],
                },
              ],
              overallScore: 55,
              overallGrade: "C",
              recommendations: [
                {
                  issue: "Multiple subdomains expose admin or dev endpoints",
                  severity: 80,
                  suggestion: "Restrict access or disable unnecessary services.",
                },
                {
                  issue: "Several subdomains run outdated TLS versions",
                  severity: 70,
                  suggestion: "Upgrade TLS to 1.3 where possible.",
                },
              ],
              checkedAt: "2024-06-01T12:30:00Z",
              explanation:
                "Full scan combines multiple data sources and network probes; partial failures handled gracefully.",
            },
            meta: {
              timestamp: "2024-06-01T12:30:00Z",
              duration_ms: 7320,
              api_version: "1.0.0",
            },
          },
        },
      ],
      parameters: [
        {
          name: "domain",
          type: "string",
          description: "Root domain to analyze, e.g., example.com",
        },
      ],
      examples: [
        "GET /preview?domain=example.com",
        "GET /check?domain=example.com",
      ],
    },
    pricing: {
      freePreview: "Free",
      paidScan: PRICE_STRING,
      currency: "USD",
    },
    subdomain: SUBDOMAIN,
  });
});

// Free preview route
app.get("/preview", async (c) => {
  const domain = c.req.query("domain");
  if (!domain || typeof domain !== "string") {
    return c.json({ error: "Missing or invalid ?domain= parameter" }, 400);
  }
  if (domain.length > 253) {
    return c.json({ error: "Domain length exceeds maximum of 253 characters" }, 400);
  }
  try {
    const start = performance.now();
    const report = await analyzeSubdomains(domain, { mode: "preview" });
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: report,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0",
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Payment and spend cap middleware
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE_STRING,
        "Comprehensive subdomain enumeration and exposure ranking with detailed risk scoring and recommendations",
        {
          input: { domain: "example.com" },
          inputSchema: {
            type: "object",
            properties: {
              domain: {
                type: "string",
                description: "Root domain name to enumerate and analyze",
              },
            },
            required: ["domain"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid detailed scan endpoint
app.get("/check", async (c) => {
  const domain = c.req.query("domain");
  if (!domain || typeof domain !== "string") {
    return c.json({ error: "Missing or invalid ?domain= parameter" }, 400);
  }
  if (domain.length > 253) {
    return c.json({ error: "Domain length exceeds maximum of 253 characters" }, 400);
  }
  try {
    const start = performance.now();
    const report = await analyzeSubdomains(domain, { mode: "full" });
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: report,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0",
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Global error handler with pass-through for HTTPException (like 402)
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
