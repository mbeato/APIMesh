import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { safeFetch, validateExternalUrl } from "../../shared/ssrf";
import { fullEnumeration, previewEnumeration } from "./analyzer";

const app = new Hono();
const API_NAME = "http-method-enumeration";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit price
const PRICE_NUM = 0.01;

// CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before rate limit
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit: 10 per minute for paid usage, 30 per minute global
app.use("/enumerate", rateLimit("http-method-enumeration-enumerate", 10, 60_000));
app.use("*", rateLimit("http-method-enumeration", 30, 60_000));

// Extract wallet then log all requests with revenue tracking
app.use("*", extractPayerWallet());
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
          path: "/",
          description: "API info and documentation.",
          parameters: [],
          exampleResponse: {
            api: API_NAME,
            status: "healthy",
            version: "1.0.0",
            docs: {},
            pricing: { paid: PRICE, preview: "$0" },
          },
        },
        {
          method: "GET",
          path: "/preview?url={url}",
          description: "Free preview enumerating HTTP methods via OPTIONS header and HEAD test.",
          parameters: ["url (string) - target HTTP or HTTPS URL"],
          exampleResponse: {
            url: "https://example.com",
            preview: true,
            supportedMethods: ["GET", "HEAD", "OPTIONS"],
            scannedAt: "2024-01-01T00:00:00.000Z",
            note: "Preview runs only OPTIONS and HEAD method checks. Pay for full scan.",
          },
        },
        {
          method: "GET",
          path: "/enumerate?url={url}",
          description: "Paid full enumeration of HTTP methods with scoring and analysis.",
          parameters: ["url (string) - target URL"],
          exampleResponse: {
            url: "https://example.com",
            supports: [
              { method: "GET", allowed: true, description: "Retrieve resource data." },
              { method: "POST", allowed: false, description: "Create new resource or submit data." },
              // ...other methods
            ],
            overallScore: 80,
            overallGrade: "A",
            recommendations: [{ issue: "TRACE allowed", severity: 70, suggestion: "Disable TRACE method." }],
            scannedAt: "2024-01-01T00:00:00.000Z",
            details: "Comprehensive method enumeration combining OPTIONS and probes.",
          },
        },
      ],
      parameters: ["url: string - must be a valid HTTP or HTTPS URL, max 2048 characters."],
      examples: [
        "GET /preview?url=https://example.com",
        "GET /enumerate?url=https://example.com",
      ],
    },
    pricing: {
      preview: "$0",
      paid: PRICE,
    },
  });
});

// Free preview (no payment required) - more generous rate limit
app.get(
  "/preview",
  rateLimit("http-method-enumeration-preview", 15, 60_000),
  async (c) => {
    const rawUrl = c.req.query("url");
    if (!rawUrl) {
      return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
    }
    if (rawUrl.length > 2048) {
      return c.json({ error: "URL exceeds maximum length" }, 400);
    }

    try {
      const result = await previewEnumeration(rawUrl.trim());
      if ("error" in result) {
        return c.json({ error: result.error }, 400);
      }
      const start = performance.now();
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
      console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e);
      const msg = e instanceof Error ? e.message : String(e);
      const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
      return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
    }
  },
);

// Paid route MUST be after spendCap and paymentMiddleware
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /enumerate": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive audit enumerating HTTP methods on a URL with scoring, grading, and actionable recommendations.",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "Target HTTP or HTTPS URL (max 2048 characters)" },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer,
  ),
);

// Paid full enumeration endpoint
app.get("/enumerate", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }
  try {
    const start = performance.now();
    const result = await fullEnumeration(rawUrl.trim());
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
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} enumerate error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// CRITICAL error handler - pass through 402 HTTPException from x402 payment
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
