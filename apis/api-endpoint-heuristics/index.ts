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
  analyzeEndpoint,
  EndpointHeuristicsResult,
} from "./analyzer";

const app = new Hono();
const API_NAME = "api-endpoint-heuristics";
const PORT = Number(process.env.PORT) || 3001;

// Pricing tier: Comprehensive audit (5+ checks, scoring, detailed report): $0.01
const PRICE = "$0.01";
const PRICE_NUM = 0.01;

// 1. CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// 2. /health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limit setup: /analyze endpoint limited 20/min, global 60/min
app.use("/analyze", rateLimit("api-endpoint-heuristics-analyze", 20, 60_000));
app.use("*", rateLimit("api-endpoint-heuristics", 60, 60_000));

// 4. Extract payer wallet
app.use("*", extractPayerWallet());

// 5. API Logger middleware logs requests and usage with price
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// 6. Info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/analyze",
          description: "Analyze endpoint URL to determine if API, REST resource or static page",
          parameters: [
            { name: "url", type: "string", required: true, description: "Full http(s) URL to analyze" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com/api/v1/users?id=123",
              heuristics: {
                isLikelyApi: true,
                isRestResource: true,
                isStaticPage: false,
                apiConfidence: 88,
                restConfidence: 75,
                staticConfidence: 10,
                patternScore: 85,
                recommendations: [
                  {
                    issue: "URL contains camelCase path segments",
                    severity: 30,
                    suggestion: "Prefer kebab-case or snake_case for REST APIs for clarity.",
                  },
                ],
                explanation: "The endpoint pattern and parameter style highly suggest a REST resource API.",
              },
            },
            meta: {
              timestamp: "2024-01-01T12:00:00Z",
              duration_ms: 172,
              api_version: "1.0.0",
            },
          },
        },
      ],
      parameters: [
        {
          name: "url",
          type: "string",
          description: "Full HTTP(S) URL to analyze",
          required: true,
        },
      ],
      examples: [
        {
          description: "Analyze a typical REST API URL",
          request: "/analyze?url=https://example.com/api/v1/users?id=123",
          response: {
            status: "ok",
            data: { /* heuristics result */ },
            meta: { timestamp: "...", duration_ms: 150, api_version: "1.0.0" },
          },
        },
      ],
    },
    pricing: {
      tier: "Comprehensive audit",
      price_per_call: PRICE,
      description: "Comprehensive heuristics combining multiple analyses and actionable recommendations",
    },
  });
});

// 7. spendCapMiddleware to enforce per-wallet spending limits
app.use("*", spendCapMiddleware());

// 8. Payment middleware with paidRouteWithDiscovery config
app.use(
  paymentMiddleware(
    {
      "GET /analyze": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive heuristics to distinguish APIs, REST resources, or static pages from endpoint URL patterns, with scoring and actionable suggestions.",
        {
          input: {
            url: "https://example.com/api/v1/users?id=123",
          },
          inputSchema: {
            type: "object",
            properties: {
              url: {
                type: "string",
                description: "Full http(s) URL to analyze",
                maxLength: 2048,
              },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer
  ),
);

// 9. Paid route: /analyze
app.get("/analyze", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing required ?url= parameter (http or https URL)" }, 400);
  }
  if (typeof rawUrl !== "string") {
    return c.json({ error: "Parameter ?url= must be a string" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL length exceeds maximum of 2048 characters" }, 400);
  }

  const check = validateExternalUrl(rawUrl.trim());
  if ("error" in check) {
    return c.json({ error: check.error }, 400);
  }

  const start = performance.now();
  let result: EndpointHeuristicsResult | { error: string };
  try {
    result = await analyzeEndpoint(check.url.toString());
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
  const duration_ms = Math.round(performance.now() - start);

  if ("error" in result) {
    return c.json({
      status: "error",
      error: result.error,
      detail: "Failed to analyze endpoint URL",
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms: 0,
        api_version: "1.0.0",
      },
    }, 400);
  }

  return c.json({
    status: "ok",
    data: {
      url: check.url.toString(),
      heuristics: result,
    },
    meta: {
      timestamp: new Date().toISOString(),
      duration_ms,
      api_version: "1.0.0",
    },
  });
});

// 10. Error handler passing x402 HTTPExceptions through
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
