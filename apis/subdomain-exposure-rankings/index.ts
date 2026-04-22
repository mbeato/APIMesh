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
import { validateExternalUrl } from "../../shared/ssrf";
import {
  fullSubdomainExposureRankings,
  previewSubdomainExposureRankings,
  SubdomainExposureRankingsPreviewResult,
  SubdomainExposureRankingsFullResult,
} from "./analyzer";

const app = new Hono();
const API_NAME = "subdomain-exposure-rankings";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit (5+ checks, scoring, detailed report), 0.01 USD
const PRICE_NUM = 0.01;

app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// Health check before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit for preview and check endpoints
app.use("/preview", rateLimit("subdomain-exposure-rankings-preview", 15, 60_000));
app.use("/check", rateLimit("subdomain-exposure-rankings-check", 30, 60_000));
app.use("*", rateLimit("subdomain-exposure-rankings", 90, 60_000));

app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint
app.get("/", (c) => {
  const docs = {
    endpoints: [
      {
        method: "GET",
        path: "/preview?domain={domain}",
        description: "Perform a free preview of the subdomain exposure ranking for a domain.",
        parameters: [
          { name: "domain", type: "string", description: "Root domain to enumerate subdomains", required: true },
        ],
        example_response: {
          status: "ok",
          data: {
            domain: "example.com",
            subdomains_found: 5,
            subdomains: [
              {
                name: "www.example.com",
                score: 75,
                grade: "B",
                issues: ["Outdated software detected"],
                recommendations: [{ issue: "Outdated software detected", severity: 50, suggestion: "Upgrade to latest security patch" }]
              },
              {
                name: "api.example.com",
                score: 90,
                grade: "A",
                issues: [],
                recommendations: []
              }
            ],
            summary_score: 80,
            summary_grade: "B",
            explanation: "This preview found 5 subdomains with minor security issues on 2 subdomains.",
          },
          meta: {
            timestamp: "2024-01-01T00:00:00.000Z",
            duration_ms: 1500,
            api_version: "1.0.0"
          }
        }
      },
      {
        method: "GET",
        path: "/check?domain={domain}",
        description: "Paid, comprehensive analysis of subdomain exposure and security ranking.",
        parameters: [
          { name: "domain", type: "string", description: "Root domain to enumerate and analyze", required: true }
        ],
        example_response: {
          status: "ok",
          data: {
            domain: "example.com",
            total_subdomains: 20,
            analyzed_subdomains: 20,
            subdomains: [
              {
                name: "www.example.com",
                score: 85,
                grade: "A",
                issues: ["Exposed sensitive endpoint", "Outdated TLS configuration"],
                recommendations: [
                  { issue: "Exposed sensitive endpoint", severity: 85, suggestion: "Restrict access to endpoint via firewall and authentication" },
                  { issue: "Outdated TLS configuration", severity: 75, suggestion: "Upgrade to TLS 1.3 and patch vulnerable ciphers" }
                ],
                lastScanned: "2024-01-01T00:00:00.000Z"
              }
            ],
            overall_score: 78,
            overall_grade: "B",
            explanation: "Comprehensive analysis detected multiple issues affecting security posture. Immediate attention recommended.",
            scannedAt: "2024-01-01T00:00:00.000Z"
          },
          meta: {
            timestamp: "2024-01-01T00:00:01.200Z",
            duration_ms: 4200,
            api_version: "1.0.0"
          }
        }
      }
    ],
    parameters: [
      { name: "domain", type: "string", description: "Root domain name, e.g. example.com", required: true }
    ],
    examples: [
      {
        description: "Preview usage",
        request: "GET /preview?domain=example.com",
        response_status: 200
      },
      {
        description: "Paid comprehensive check",
        request: "GET /check?domain=example.com",
        response_status: 200
      }
    ],
  };

  return c.json({
    api: API_NAME,
    status: "healthy",
    docs,
    pricing: {
      preview: "FREE",
      paid: PRICE,
      description: "Preview is free. Paid API does a comprehensive subdomain enumeration + analysis, priced at $0.01 per call via x402 or MPP payment",
    },
  });
});

app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive subdomain enumeration and exposure ranking including multiple data sources and detailed analysis",
        {
          input: { domain: "example.com" },
          inputSchema: {
            type: "object",
            properties: {
              domain: { type: "string", description: "Root domain name for enumeration" },
            },
            required: ["domain"],
          },
        },
      ),
    },
    resourceServer
  )
);

// Free preview endpoint
app.get("/preview", async (c) => {
  const rawDomain = c.req.query("domain");
  if (!rawDomain || typeof rawDomain !== "string") {
    return c.json({ error: "Missing ?domain= parameter" }, 400);
  }
  if (rawDomain.length > 255) {
    return c.json({ error: "Domain length exceeds maximum (255 chars)" }, 400);
  }

  try {
    const result: SubdomainExposureRankingsPreviewResult = await previewSubdomainExposureRankings(rawDomain.trim());
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    const start = performance.now();
    // Duration included by analyzer
    return c.json(result);
  } catch (e: any) {
    console.error(
      `[${new Date().toISOString()}] ${API_NAME} preview error:`,
      e
    );
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Paid comprehensive check endpoint
app.get("/check", async (c) => {
  const rawDomain = c.req.query("domain");
  if (!rawDomain || typeof rawDomain !== "string") {
    return c.json({ error: "Missing ?domain= parameter" }, 400);
  }
  if (rawDomain.length > 255) {
    return c.json({ error: "Domain length exceeds maximum (255 chars)" }, 400);
  }

  try {
    const start = performance.now();
    const result: SubdomainExposureRankingsFullResult = await fullSubdomainExposureRankings(rawDomain.trim());
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result && !("subdomains" in result)) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0",
      },
    });
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} check error: `, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// CRITICAL error handler - pass through HTTPException for 402s
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
