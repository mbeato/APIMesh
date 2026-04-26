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
import { previewTechnologyHeaders, fullTechnologyHeadersAudit } from "./analyzer";

const app = new Hono();
const API_NAME = "api-technology-headers";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUM = 0.01;

// 1. CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// 2. Health endpoint before rate limiting
app.get("/health", c => c.json({ status: "ok" }));

// 3. Rate limits then logger
app.use(
  "/check",
  rateLimit("api-technology-headers-check", 20, 60_000),
);
app.use("*", rateLimit("api-technology-headers", 90, 60_000));
app.use("*", extractPayerWallet());
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
          path: "/check",
          description:
            "Comprehensive technology headers aggregation and analysis for underlying technologies, frameworks, and outdated software detection",
          parameters: [
            {
              name: "url",
              type: "string",
              description: "The target URL to analyze (full http(s):// URL)",
              required: true,
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              technologies: [
                { name: "Apache", version: "2.4.46", confidence: 95 },
                { name: "PHP", version: "7.4.3", confidence: 88 },
              ],
              outdated: true,
              score: 71,
              grade: "C",
              recommendations: [
                {
                  issue: "Apache version is outdated",
                  severity: 80,
                  suggestion: "Upgrade Apache to latest stable release to address security vulnerabilities",
                },
              ],
              explanation: "The analyzed headers indicate presence of Apache 2.4.46 and PHP 7.4.3; PHP is end-of-life and Apache is not latest",
            },
            meta: {
              timestamp: "ISO8601 string",
              duration_ms: 123,
              api_version: "1.0.0",
            },
          },
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free, lightweight preview analysis focusing on key server headers",
          parameters: [
            {
              name: "url",
              type: "string",
              description: "The target URL to preview (full http(s):// URL)",
              required: true,
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              technologies: [
                { name: "nginx", version: null, confidence: 75 }
              ],
              score: 50,
              grade: "D",
              recommendations: [
                {
                  issue: "Unable to extract server version. Provide more headers or authentication if needed",
                  severity: 50,
                  suggestion: "Ensure headers expose required version info or run full scan",
                }
              ],
              explanation: "Limited headers detected; server identified as nginx but version info not present",
            },
            meta: {
              timestamp: "ISO8601 string",
              duration_ms: 200,
              api_version: "1.0.0",
            },
          },
        },
      ],
      parameters: [
        {
          name: "url",
          type: "string",
          description: "URL to analyze, must be http or https",
          required: true,
        },
      ],
      examples: [
        "GET /check?url=https://example.com",
        "GET /preview?url=https://example.com"
      ],
    },
    pricing: {
      price_per_call: PRICE,
      description: "Comprehensive audit with 5+ header-based tech checks, scoring, grading, and recommendations",
    },
  });
});

// 7. Free preview before payment middleware
app.get(
  "/preview",
  rateLimit("api-technology-headers-preview", 20, 60_000),
  async (c) => {
    const rawUrl = c.req.query("url");
    if (!rawUrl || typeof rawUrl !== "string") {
      return c.json({ error: "Missing or invalid ?url= parameter (http(s)://...)" }, 400);
    }
    if (rawUrl.length > 2048) {
      return c.json({ error: "URL exceeds maximum length" }, 400);
    }

    const validated = validateExternalUrl(rawUrl.trim());
    if ("error" in validated) {
      return c.json({ error: validated.error }, 400);
    }

    try {
      const result = await previewTechnologyHeaders(validated.url.toString());
      if ("error" in result) {
        return c.json({ error: result.error }, 400);
      }
      return c.json(result);
    } catch (e: any) {
      console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e);
      const msg = e instanceof Error ? e.message : String(e);
      const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
      return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
    }
  },
);

// 7.5 middleware: spendCap, payment
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive header aggregation & analysis with technology identification, outdated software detection, scoring, and actionable security recommendations",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "URL to analyze (http or https)" },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer,
  ),
);

// 9. Paid route
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const validated = validateExternalUrl(rawUrl.trim());
  if ("error" in validated) {
    return c.json({ error: validated.error }, 400);
  }

  try {
    const result = await fullTechnologyHeadersAudit(validated.url.toString());
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    return c.json(result);
  } catch (e: any) {
    if (typeof e === "object" && e !== null && "getResponse" in e) {
      return (e as any).getResponse();
    }
    console.error(`[${new Date().toISOString()}] ${API_NAME} check error:`, e?.message ?? e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 10. OnError handler - must pass through x402 HTTPExceptions
app.onError((err, c) => {
  if (typeof err === "object" && err !== null && "getResponse" in err) {
    return (err as any).getResponse();
  }
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

app.notFound((c) => c.json({ error: "Not found" }, 404));

export { app };

if (import.meta.main) {
  console.log(`${API_NAME} listening on port ${PORT}`);
}

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
