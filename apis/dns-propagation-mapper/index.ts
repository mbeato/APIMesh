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
  safeFetch
} from "../../shared/ssrf";
import {
  runFullPropagationAudit,
  runPreviewPropagationCheck,
  DNSPropagationResult,
  DNSPropagationPreviewResult,
} from "./analyzer";

const app = new Hono();
const API_NAME = "dns-propagation-mapper";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit (5+ checks, scoring, detailed report)
const PRICE_NUM = 0.01;

// Middleware 1: CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Middleware 2: health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Middleware 3: rate limiting
app.use(
  "/check",
  rateLimit("dns-propagation-mapper-check", 20, 60_000)
);
app.use("*", rateLimit("dns-propagation-mapper", 60, 60_000));

// Middleware 4: extract payer wallet
app.use("*", extractPayerWallet());

// Middleware 5: apiLogger with price
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/check",
          description: "Comprehensive DNS propagation audit across multiple global DNS resolvers with delay correlation, misconfiguration detection, scoring, grading, and recommendations.",
          parameters: [
            {
              name: "domain",
              type: "string",
              description: "Domain name to check propagation status for",
              required: true
            },
            {
              name: "recordType",
              type: "string",
              description: "DNS record type to evaluate, e.g. A, AAAA, CNAME, TXT",
              required: false
            }
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              recordType: "A",
              queryTimeUTC: "2024-04-01T12:00:00Z",
              propagationScores: {
                completenessPct: 98,
                consistencyPct: 95,
                averageLatencyMs: 1350,
                grade: "A",
                recommendations: [
                  {
                    issue: "Delayed propagation in Asia",
                    severity: 70,
                    suggestion: "Check TTL and nameserver redundancy for better global coverage"
                  },
                  {
                    issue: "Resolver misconfiguration detected",
                    severity: 50,
                    suggestion: "Monitor and avoid unreliable DNS resolvers"
                  }
                ]
              },
              resolverStatuses: [
                {
                  resolver: "1.1.1.1",
                  response: "93.184.216.34",
                  lastSeen: "2024-04-01T11:59:50Z",
                  success: true,
                  latencyMs: 800
                }
              ],
              details: "DNS A records are mostly propagated globally with minor latency in Asia Pacific region. No major misconfigurations found."
            },
            meta: {
              timestamp: "2024-04-01T12:00:01Z",
              duration_ms: 1450,
              api_version: "1.0.0"
            }
          }
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free lightweight DNS record snapshot preview from a few major global resolvers. Limited data and latency info, no scoring.",
          parameters: [
            {
              name: "domain",
              type: "string",
              description: "Domain name for a quick DNS snapshot",
              required: true
            },
            {
              name: "recordType",
              type: "string",
              description: "DNS record type to retrieve (A, MX, TXT, etc.)",
              required: false
            }
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              recordType: "A",
              snapshots: [
                {
                  resolver: "8.8.8.8",
                  value: "93.184.216.34",
                  timestampUTC: "2024-04-01T11:59:55Z",
                  success: true
                }
              ],
              note: "Preview endpoint does basic DNS checks from 3 resolvers with no scoring. Full analytics require paid access."
            },
            meta: {
              timestamp: "2024-04-01T12:00:00Z",
              duration_ms: 900,
              api_version: "1.0.0"
            }
          }
        }
      ],
      parameters: [
        {
          name: "domain",
          description: "The domain name to query DNS propagation status for",
          type: "string",
          required: true
        },
        {
          name: "recordType",
          description: "Specific DNS record type (e.g., A, AAAA, CNAME, TXT)",
          type: "string",
          required: false
        }
      ],
      examples: [
        {
          path: "/check?domain=example.com&recordType=A",
          description: "Perform a comprehensive propagation audit for A record of example.com"
        },
        {
          path: "/preview?domain=example.com",
          description: "Get a quick DNS record snapshot preview for example.com"
        }
      ]
    },
    pricing: {
      free: "Preview endpoint is free with rate limits.",
      paid: {
        price_per_call: PRICE,
        description: "Comprehensive DNS propagation audit with 5+ resolver checks, scoring, grading, and actionable recommendations."
      }
    },
  });
});

// Free preview endpoint - relaxed rate limit and longer timeout
app.get(
  "/preview",
  rateLimit("dns-propagation-mapper-preview", 15, 60_000),
  async (c) => {
    const domain = c.req.query("domain");
    let recordType = c.req.query("recordType") || "A";

    if (!domain || typeof domain !== "string") {
      return c.json({ error: "Missing ?domain= parameter" }, 400);
    }

    if (domain.length > 255) {
      return c.json({ error: "Domain name too long" }, 400);
    }

    if (typeof recordType !== "string" || recordType.length > 10) {
      recordType = "A";
    }

    try {
      const result = await runPreviewPropagationCheck(domain.trim(), recordType.trim());
      return c.json({
        status: "ok",
        data: result,
        meta: {
          timestamp: new Date().toISOString(),
          duration_ms: 1500,
          api_version: "1.0.0",
        },
      });
    } catch (e: any) {
      console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e);
      const msg = e instanceof Error ? e.message : String(e);
      const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
      return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
    }
  }
);

// Apply spend cap middleware before paid endpoints
app.use("*", spendCapMiddleware());

// Payment middleware with paid route
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive DNS propagation audit across multiple global DNS resolvers with delay correlation, misconfiguration detection, scoring, grading, and actionable recommendations",
        {
          input: { domain: "example.com", recordType: "A" },
          inputSchema: {
            properties: {
              domain: { type: "string", description: "Domain name to check" },
              recordType: {
                type: "string",
                description: "DNS record type (e.g., A, AAAA, CNAME, TXT)",
                default: "A",
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

// Paid comprehensive check endpoint
app.get("/check", async (c) => {
  const domain = c.req.query("domain");
  let recordType = c.req.query("recordType") || "A";

  if (!domain || typeof domain !== "string") {
    return c.json({ error: "Missing ?domain= parameter" }, 400);
  }
  if (domain.length > 255) {
    return c.json({ error: "Domain name too long" }, 400);
  }

  if (typeof recordType !== "string" || recordType.length > 10) {
    recordType = "A";
  }

  try {
    const start = performance.now();
    const result = await runFullPropagationAudit(domain.trim(), recordType.trim());
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
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// On error must pass through HTTPException with 402 passing
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
