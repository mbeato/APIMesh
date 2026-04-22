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
  analyzeCdnInfrastructure,
  PreviewResult,
  FullAnalysisResult,
} from "./analyzer";

const app = new Hono();
const API_NAME = "cdn-infrastructure-enricher";
const PORT = Number(process.env.PORT) || 3001;

// $0.01 per call: comprehensive audit with multiple checks & scoring
const PRICE = "$0.01";
const PRICE_NUM = 0.01;
const SUBDOMAIN = "cdn-infrastructure-enricher.apimesh.xyz";
const API_VERSION = "1.0.0";

// Allowed HTTP methods
const ALLOWED_METHODS = ["GET"];

// CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ALLOWED_METHODS,
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before rate limiter
app.get("/health", (c) => {
  return c.json({ status: "ok" });
});

// Rate limiting
// Preview endpoints generous: 30 per minute
app.use("/preview", rateLimit("cdn-infrastructure-enricher-preview", 30, 60_000));
// Paid endpoints global: 90/min
app.use("*", rateLimit("cdn-infrastructure-enricher", 90, 60_000));

// Extract payer wallet
app.use("*", extractPayerWallet());

// API logger: use numerical price for consistent logging
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint with detailed docs and pricing
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: API_VERSION,
    description: "Analyzes website response headers, DNS records, and IP ranges to deduce CDN providers, hosting infrastructure, and regional distribution. Combines public DNS, response analysis, and IP info APIs for deep insights.",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/preview",
          description: "Free preview analysis combining HTTP headers and basic DNS lookups with latency scoring.",
          parameters: [{ name: "url", required: true, description: "Target website URL (http(s)://...) to analyze." }],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              detectedCdns: ["Cloudflare", "Fastly"],
              detectedHosting: "AWS",
              ipRanges: ["104.16.0.0/12"],
              regionalDistribution: "Global",
              score: 70,
              grade: "B",
              explanation: "Site uses Cloudflare CDN with AWS hosting in multiple regions.",
              recommendations: [
                { issue: "Non-optimal header cache TTL", severity: 30, suggestion: "Increase Cache-Control max-age for static assets." }
              ]
            },
            meta: { timestamp: "2024-06-01T00:00:00Z", duration_ms: 145, api_version: API_VERSION }
          }
        },
        {
          method: "GET",
          path: "/check",
          description: "Comprehensive paid audit integrating DNS, HTTP headers, IP and regional info with detailed scoring and recommendations.",
          parameters: [{ name: "url", required: true, description: "Target website URL (http(s)://...) to deeply analyze." }],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              detectedCdns: ["Cloudflare", "Akamai"],
              detectedHosting: "AWS",
              ipRanges: ["104.16.0.0/12", "23.0.0.0/8"],
              regionalDistribution: "Global with North America & Europe presence",
              score: 85,
              grade: "A",
              explanation: "Site utilizes Cloudflare and Akamai CDNs with strong global presence and low latency regions. No major misconfigurations detected.",
              recommendations: []
            },
            meta: { timestamp: "2024-06-01T00:00:00Z", duration_ms: 420, api_version: API_VERSION }
          }
        }
      ],
      parameters: [
        { name: "url", description: "Website URL to analyze. Must be http or https." }
      ],
      examples: [
        "GET /preview?url=https://example.com",
        "GET /check?url=https://example.com"
      ]
    },
    pricing: {
      preview: "$0 (free, usage limited)",
      paid: PRICE
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
    return c.json({ error: "URL exceeds maximum length of 2048 characters" }, 400);
  }

  const validation = validateExternalUrl(rawUrl.trim());
  if ("error" in validation) {
    return c.json({ error: validation.error }, 400);
  }

  try {
    // Preview calls use longer timeout for reliability (20s)
    const result = await analyzeCdnInfrastructure(validation.url.toString(), { preview: true });
    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms: result.duration_ms || 0,
        api_version: API_VERSION,
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({
      status: "error",
      error: "Analysis temporarily unavailable",
      detail: msg,
      meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: API_VERSION },
    }, status);
  }
});

// Payment & spend cap middleware
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive CDN and hosting infrastructure audit combining response headers, DNS records, and IP range analysis with scoring and recommendations.",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            type: "object",
            properties: {
              url: { type: "string", description: "Target website URL (http(s)://...)" },
            },
            required: ["url"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid route for full check
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing or invalid ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length of 2048 characters" }, 400);
  }

  const validation = validateExternalUrl(rawUrl.trim());
  if ("error" in validation) {
    return c.json({ error: validation.error }, 400);
  }

  try {
    // Full audit timeout 15 seconds
    const result = await analyzeCdnInfrastructure(validation.url.toString(), { preview: false });
    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms: result.duration_ms || 0,
        api_version: API_VERSION,
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({
      status: "error",
      error: "Analysis temporarily unavailable",
      detail: msg,
      meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: API_VERSION },
    }, status);
  }
});

// Not found handler
app.notFound((c) => c.json({ error: "Not found" }, 404));

// Error handler passes through 402 from x402 HTTPExceptions
app.onError((err, c) => {
  if (typeof err === "object" && err !== null && "getResponse" in err) {
    return (err as any).getResponse();
  }
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

export { app };

if (import.meta.main) console.log(`${API_NAME} listening on port ${PORT}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
