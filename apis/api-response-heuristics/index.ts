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
} from "../../shared/ssrf";
import {
  fullHeuristicsAnalyze,
  previewHeuristics,
} from "./analyzer";
import type { ApiHeuristicsInput } from "./types";

const app = new Hono();
const API_NAME = "api-response-heuristics";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit
const PRICE_NUM = 0.01;

// CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint (before rate limiting)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits
app.use("/analyze", rateLimit("api-response-heuristics-analyze", 20, 60_000));
app.use("*", rateLimit("api-response-heuristics", 60, 60_000));

// Extract payer wallet
app.use("*", extractPayerWallet());

// API Logger middleware logs price as number
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint must be before payment middleware
app.get("/", (c) =>
  c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/analyze",
          description: "Comprehensive API response heuristic analysis; requires payment",
          parameters: [
            { name: "url", type: "string", description: "URL of the API endpoint to analyze" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              analyzedUrl: "https://api.example.com/v1/users",
              analysis: {
                url: "https://api.example.com/v1/users",
                stableResponse: true,
                statusCodeDiversity: 2,
                commonStatusCodes: [200, 404],
                averageResponseTimeMs: 250,
                responseSamples: [/*...*/],
                inferredApiType: "JSON API",
                complexityScore: 40,
                issues: [],
                score: 60,
                grade: "C",
                recommendations: [
                  {
                    issue: "High status code variability",
                    severity: "medium",
                    suggestion: "Document all returned status codes clearly.",
                  },
                ],
                details: "..."
              }
            },
            meta: { timestamp: "...", duration_ms: 350, api_version: "1.0.0" },
          },
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview fetch to check basic reachability and response time",
          parameters: [
            { name: "url", type: "string", description: "URL to preview analyze" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://api.example.com/v1/users",
              reachable: true,
              statusCode: 200,
              contentType: "application/json",
              responseTimeMs: 150,
              note: "Preview performs basic reachability test."
            },
            meta: { timestamp: "...", duration_ms: 200, api_version: "1.0.0" },
          },
        },
      ],
      parameters: [
        { name: "url", type: "string", description: "Fully qualified URL for the API endpoint" },
      ],
      examples: [
        "/analyze?url=https://api.example.com/v1/users",
        "/preview?url=https://api.example.com/v1/users",
      ],
    },
    pricing: {
      price: PRICE,
      description: "Comprehensive audit: 5+ checks, scoring, detailed report",
    },
  })
);

// Free preview endpoint, generous timeout (15s), rate limited
app.get("/preview", rateLimit("api-response-heuristics-preview", 15, 60_000), async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  try {
    const start = performance.now();
    const result = await previewHeuristics(rawUrl.trim());
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result) {
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
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Spend cap middleware
app.use("*", spendCapMiddleware());

// Payment middleware for /analyze endpoint
app.use(
  paymentMiddleware(
    {
      "GET /analyze": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive API response heuristics with multiple fetches, scoring, grading, detailed diagnostics",
        {
          input: { url: "https://api.example.com/v1/users" },
          inputSchema: {
            type: "object",
            properties: {
              url: { type: "string", description: "URL of the API endpoint to analyze" },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer
  )
);

// Paid route
app.get("/analyze", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  try {
    const start = performance.now();
    const result = await fullHeuristicsAnalyze(rawUrl.trim());
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result) {
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
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Error handler
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
