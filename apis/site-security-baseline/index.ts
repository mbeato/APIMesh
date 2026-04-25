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
  fullSecurityBaselineAudit,
  previewSecurityBaselineAudit,
  SiteSecurityBaselineResult,
  SiteSecurityBaselinePreviewResult,
} from "./analyzer";

const app = new Hono();
const API_NAME = "site-security-baseline";
const PORT = Number(process.env.PORT) || 3001;
const PRICE_STR = "$0.01";
const PRICE_NUM = 0.01;

app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  }),
);

// Health check before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limiting
app.use("/check", rateLimit("site-security-baseline-check", 10, 60_000));
app.use("*", rateLimit("site-security-baseline", 30, 60_000));

app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint with full docs and pricing
app.get("/", (c) => {
  const docs = {
    endpoints: [
      {
        method: "GET",
        path: "/",
        description: "API info, status, docs, and pricing",
        parameters: [],
        exampleResponse: {
          api: API_NAME,
          status: "healthy",
          version: "1.0.0",
          docs: {
            endpoints: ["GET /", "GET /preview?url=", "GET /check?url="],
            parameters: [
              { name: "url", type: "string", description: "Full URL of the website to analyze (http(s)://...)" },
            ],
            examples: [
              {
                description: "Preview free endpoint",
                request: "/preview?url=https://example.com",
                responseSample: {
                  status: "ok",
                  data: {
                    url: "https://example.com",
                    preview: true,
                    summary: {
                      securityHeadersScore: 80,
                      sslGrade: "B",
                      recommendationsCount: 3
                    },
                    explanation: "Preview performs limited checks on security headers and SSL reachability.",
                  },
                  meta: {
                    timestamp: "2023-01-01T00:00:00.000Z",
                    duration_ms: 123,
                    api_version: "1.0.0"
                  }
                }
              },
              {
                description: "Paid comprehensive baseline audit",
                request: "/check?url=https://example.com",
                responseSample: {
                  status: "ok",
                  data: {
                    url: "https://example.com",
                    headerAnalyses: [],
                    sslAnalysis: {},
                    overallScore: 90,
                    overallGrade: "A",
                    recommendations: [
                      { issue: "Missing HSTS preload", severity: 4, suggestion: "Add preload directive to HSTS header." }
                    ],
                    explanation: "Detailed website security baseline assessment combining multiple audits.",
                    scannedAt: "2023-01-01T00:00:00.000Z"
                  },
                  meta: {
                    timestamp: "2023-01-01T00:00:00.000Z",
                    duration_ms: 1234,
                    api_version: "1.0.0"
                  }
                }
              }
            ]
          },
          pricing: {
            paidEndpoint: "/check",
            pricePerCall: PRICE_STR,
            description: "Comprehensive baseline audit with combined security headers, SSL, and configuration checks"
          }
        }
      }],
    parameters: [
      { name: "url", type: "string", description: "Target website URL to analyze", required: true }
    ],
    examples: [
      "GET /preview?url=https://example.com",
      "GET /check?url=https://example.com"
    ],
  };

  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs,
    pricing: {
      paidEndpoint: "/check",
      pricePerCall: PRICE_STR,
      description: "Comprehensive baseline audit with combined security headers, SSL, and configuration checks",
    },
  });
});

// Free preview before payment middleware
app.get(
  "/preview",
  rateLimit("site-security-baseline-preview", 15, 60_000),
  async (c) => {
    const rawUrl = c.req.query("url");
    if (!rawUrl) {
      return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
    }
    if (typeof rawUrl !== "string") {
      return c.json({ error: "Invalid URL parameter" }, 400);
    }
    if (rawUrl.length > 2048) {
      return c.json({ error: "URL exceeds maximum length" }, 400);
    }

    const validation = validateExternalUrl(rawUrl.trim());
    if ("error" in validation) {
      return c.json({ error: validation.error }, 400);
    }

    try {
      const result = await previewSecurityBaselineAudit(validation.url.toString());
      if ("error" in result) {
        return c.json({ error: result.error }, 400);
      }
      return c.json({
        status: "ok",
        data: result,
        meta: {
          timestamp: new Date().toISOString(),
          duration_ms: 200,
          api_version: "1.0.0",
        },
      });
    } catch (e: unknown) {
      console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e);
      const msg = e instanceof Error ? e.message : String(e);
      const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
      return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
    }
  },
);

// Payment middleware
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE_STR,
        "Comprehensive assessment of website security headers, SSL configuration, and potential misconfigurations with scoring and recommendations",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            type: "object",
            properties: {
              url: { type: "string", description: "URL of website to analyse including scheme" },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer,
  ),
);

// Paid endpoint
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing or invalid ?url= parameter (provide http(s):// URL)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const validation = validateExternalUrl(rawUrl.trim());
  if ("error" in validation) {
    return c.json({ error: validation.error }, 400);
  }

  try {
    const start = performance.now();
    const result = await fullSecurityBaselineAudit(validation.url.toString());
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
    console.error(`[${new Date().toISOString()}] ${API_NAME} check error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Critical error handler - pass through 402 HTTPException (x402)
app.onError((err, c) => {
  if (typeof err === "object" && err !== null && "getResponse" in err) {
    return (err as any).getResponse();
  }
  console.error(`[${new Date().toISOString()}] ${API_NAME} server error:`, err);
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
