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
  validateExternalUrl,
  safeFetch,
} from "../../shared/ssrf";
import {
  performComprehensiveRiskRanking,
  RiskRankingResult,
  PreviewRiskRankingResult,
} from "./analyzer";

const app = new Hono();
const API_NAME = "subdomain-risk-ranking";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit costs $0.01 per pricing guide
const PRICE_NUM = 0.01;

// 1. CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// 2. Health endpoint BEFORE rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limits
app.use("/rank", rateLimit("subdomain-risk-ranking-rank", 15, 60_000));
app.use("*", rateLimit("subdomain-risk-ranking", 45, 60_000));

// 4. Extract payer wallet after rate limiting
app.use("*", extractPayerWallet());

// 5. API Logger
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// 6. / info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/rank",
          description: "Perform a deep, comprehensive subdomain enumeration and risk ranking audit.",
          parameters: [
            {
              name: "domain",
              type: "string",
              description: "The root domain to enumerate subdomains for (e.g. example.com).",
              required: true,
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              subdomains: [
                {
                  name: "sub1.example.com",
                  ipAddresses: ["1.2.3.4"],
                  riskScore: 72,
                  riskGrade: "B",
                  issuesCount: 3,
                  recommendations: [
                    { issue: "Expired SSL certificate", severity: "high", suggestion: "Renew SSL certificate promptly" },
                    { issue: "Open HTTP endpoint", severity: "medium", suggestion: "Redirect HTTP to HTTPS" },
                    { issue: "Outdated server software", severity: "medium", suggestion: "Update to latest stable version" }
                  ],
                  details: "This subdomain has an expired SSL certificate and an open HTTP endpoint that could expose sensitive data. Software is not up to date."
                }
              ],
              totalSubdomains: 1,
              scannedAt: "2024-06-07T12:34:56.789Z"
            },
            meta: {
              timestamp: "2024-06-07T12:34:56.789Z",
              duration_ms: 1234,
              api_version: "1.0.0"
            }
          }
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview of subdomain enumeration with basic info; no risk scoring.",
          parameters: [
            { name: "domain", type: "string", description: "The root domain to enumerate", required: true }
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              subdomains: [
                { name: "sub1.example.com", ipAddresses: ["1.2.3.4"] },
                { name: "test.example.com", ipAddresses: [] }
              ],
              totalSubdomains: 2,
              scannedAt: "2024-06-07T12:34:56.789Z"
            },
            meta: {
              timestamp: "2024-06-07T12:34:56.789Z",
              duration_ms: 345,
              api_version: "1.0.0"
            }
          }
        }
      ],
      parameters: [
        { name: "domain", in: "query", type: "string", description: "The domain to analyze, e.g. example.com" }
      ],
      examples: [
        {
          name: "Basic Request",
          value: "/rank?domain=example.com"
        }
      ]
    },
    pricing: {
      paidEndpoint: "/rank",
      price_per_call: PRICE,
      price_description: "Comprehensive audit with 5+ checks, scoring and recommendations",
    },
  });
});

// 7. Rate limit and free preview (longer timeout on preview)
app.use("/preview", rateLimit("subdomain-risk-ranking-preview", 10, 60_000));

// Free preview endpoint - no payment required
app.get("/preview", async (c) => {
  const domain = c.req.query("domain");
  if (!domain || typeof domain !== "string") {
    return c.json({ error: "Missing or invalid ?domain= parameter (top-level domain)" }, 400);
  }
  if (domain.length > 253) {
    return c.json({ error: "Domain length exceeds maximum allowed length" }, 400);
  }
  try {
    const start = performance.now();
    const result: PreviewRiskRankingResult = await performComprehensiveRiskRanking(domain.trim(), { previewOnly: true });

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

// 8. Payment middleware
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /rank": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive subdomain enumeration from multiple free DNS and certificate transparency data sources, combined with security risk scoring and detailed recommendations",
        {
          input: { domain: "example.com" },
          inputSchema: {
            properties: {
              domain: { type: "string", description: "Domain name to analyze, e.g. example.com" },
            },
            required: ["domain"],
          },
        },
      ),
    },
    resourceServer,
  ),
);

interface RankQuery {
  domain?: string;
}

// 9. Paid route
app.get("/rank", async (c) => {
  const query = c.req.query<RankQuery>();
  const domain = query.domain;
  if (!domain || typeof domain !== "string") {
    return c.json({ error: "Missing or invalid ?domain= parameter (top-level domain)" }, 400);
  }
  if (domain.length > 253) {
    return c.json({ error: "Domain length exceeds maximum allowed length" }, 400);
  }

  try {
    const start = performance.now();
    const result: RiskRankingResult = await performComprehensiveRiskRanking(domain.trim(), { previewOnly: false });
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
    if (typeof e === "object" && e !== null && "getResponse" in e) {
      return (e as any).getResponse();
    }
    console.error(`[${new Date().toISOString()}] ${API_NAME} rank error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 10. onError handler - pass through x402 HTTPExceptions
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
