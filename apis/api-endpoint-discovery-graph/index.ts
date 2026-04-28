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
import { performDiscovery, discoveryPreview } from "./analyzer";
import type { EndpointDiscoveryRequest } from "./types";

const app = new Hono();
const API_NAME = "api-endpoint-discovery-graph";
const PORT = Number(process.env.PORT) || 3001;
const PRICE_STRING = "$0.02";
const PRICE_NUM = 0.02;

// CORS open to all origins, support GET only
app.use("*", 
  cors({
    origin: "*",
    allowMethods: ["GET"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// Health endpoint (before rate limiter)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit
app.use("/check", rateLimit("api-endpoint-discovery-graph-check", 10, 60_000));
app.use("*", rateLimit("api-endpoint-discovery-graph", 30, 60_000));

// Extract payer wallet
app.use("*", extractPayerWallet());

// Api logger with price
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint
app.get("/", (c) => {
  const docs = {
    description: "Automatically crawl common API paths and analyze responses to map available API endpoints across a domain, visualize as a graph for security and documentation.",
    version: "1.0.0",
    endpoints: [
      {
        method: "GET",
        path: "/",
        description: "Info endpoint with API details, docs, and pricing.",
        parameters: [],
        example_response: {
          api: API_NAME,
          status: "healthy",
          version: "1.0.0",
          docs: {},
          pricing: PRICE_STRING
        },
      },
      {
        method: "GET",
        path: "/preview",
        description: "Free preview showing common tested API paths for a target domain.",
        parameters: [
          { name: "url", type: "string", description: "Base URL to preview API endpoint paths (http(s)://...)", required: true }
        ],
        example_response: {
          preview: true,
          baseUrl: "https://example.com",
          samplePaths: ["/", "/api", "/v1", "/users"],
          note: "Preview provides sample common API paths without live crawling or payment...",
          timestamp: "ISO8601"
        }
      },
      {
        method: "GET",
        path: "/check",
        description: "Paid endpoint: perform deep scan of common API paths, analyze HTTP methods, statuses, content types, and response samples.",
        parameters: [
          { name: "url", type: "string", description: "Base URL to scan (http(s)://...)", required: true },
          { name: "maxDepth", type: "number", description: "Max depth of path layering, 1-3. Default 2", required: false },
          { name: "maxEndpoints", type: "number", description: "Max endpoints to discover. Default 50, max 100", required: false }
        ],
        example_response: {
          baseUrl: "https://example.com",
          crawledPaths: 100,
          discoveredEndpoints: [],
          score: 85,
          grade: "B",
          recommendations: [],
          explanation: "...",
          completedAt: "ISO8601"
        }
      },
    ],
    pricing: {
      price_per_call: PRICE_STRING,
      description: "Deep scan pricing tier at $0.02 per call.",
    }
  };

  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs,
    pricing: PRICE_STRING,
  });
});

// Free preview endpoint
app.get("/preview", rateLimit("api-endpoint-discovery-graph-preview", 30, 60_000), async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing or invalid ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  try {
    const result = await discoveryPreview(rawUrl.trim());
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, status);
  }
});

// Spend cap middleware
app.use("*", spendCapMiddleware());

// Payment middleware with paidRouteWithDiscovery for /check
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE_STRING,
        "Deep scan crawling multiple known API paths with HTTP methods and response analysis",
        {
          input: {
            url: "https://example.com",
            maxDepth: 2,
            maxEndpoints: 50,
          },
          inputSchema: {
            type: "object",
            properties: {
              url: { type: "string", description: "Base URL to scan (http(s)://...)" },
              maxDepth: { type: "number", description: "Max crawl depth, 1-3", minimum: 1, maximum: 3 },
              maxEndpoints: { type: "number", description: "Max endpoints to discover, max 100", minimum: 1, maximum: 100 },
            },
            required: ["url"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid scan endpoint
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing or invalid ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  // Optional params
  let maxDepthParam = c.req.query("maxDepth");
  let maxEndpointsParam = c.req.query("maxEndpoints");
  const maxDepthNum = typeof maxDepthParam === "string" ? parseInt(maxDepthParam) : undefined;
  const maxEndpointsNum = typeof maxEndpointsParam === "string" ? parseInt(maxEndpointsParam) : undefined;

  if (maxDepthParam && (isNaN(maxDepthNum!) || maxDepthNum! < 1 || maxDepthNum! > 3)) {
    return c.json({ error: "Invalid maxDepth parameter; must be integer 1-3" }, 400);
  }

  if (maxEndpointsParam && (isNaN(maxEndpointsNum!) || maxEndpointsNum! < 1 || maxEndpointsNum! > 100)) {
    return c.json({ error: "Invalid maxEndpoints parameter; must be integer 1-100" }, 400);
  }

  try {
    const start = performance.now();
    const result = await performDiscovery({
      url: rawUrl.trim(),
      maxDepth: maxDepthNum,
      maxEndpoints: maxEndpointsNum,
    });
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result) {
      return c.json({ status: "error", error: result.error, detail: result.error, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } }, 400);
    }

    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ status: "error", error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, status);
  }
});

// OnError handler — pass through HTTPExceptions for 402s
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
