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
import { validateExternalUrl, safeFetch } from "../../shared/ssrf";
import {
  performFullAnalysis,
  performPreviewAnalysis,
  CorsPolicyAnalysisResult,
} from "./analyzer";

const app = new Hono();
const API_NAME = "cors-policy-check";
const PORT = Number(process.env.PORT) || 3001;
const PRICE_STRING = "$0.01";
const PRICE_NUMBER = 0.01;

// CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint (before rate limiting)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits
app.use("/check", rateLimit("cors-policy-check-check", 30, 60_000));
app.use("*", rateLimit("cors-policy-check", 90, 60_000));

// Extract payer wallet for accounting
app.use("*", extractPayerWallet());

// Logger with price for paid endpoint
app.use("*", apiLogger(API_NAME, PRICE_NUMBER));

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
          description:
            "Performs comprehensive CORS policy checks on the provided URL, including preflight, headers, and origin reflection detection.",
          parameters: [{ name: "url", type: "string", description: "Target URL (http or https)" }],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              corsHeaders: {
                "access-control-allow-origin": "https://example.com",
                "access-control-allow-methods": "GET, POST",
                "access-control-allow-credentials": "true",
                "access-control-expose-headers": "Content-Length, X-Kuma-Revision",
                "access-control-max-age": "86400"
              },
              preflightResult: {
                status: 204,
                allowedMethods: ["GET", "POST"],
                allowedHeaders: ["X-Custom-Header", "Content-Type"],
                maxAgeSeconds: 86400
              },
              reflectedOriginDetected: true,
              score: 45,
              grade: "D",
              recommendations: [
                {
                  issue: "Access-Control-Allow-Origin is set to the request Origin dynamically.",
                  severity: 80,
                  suggestion: "Avoid reflecting the Origin header. Use a strict whitelist or fixed origins."
                },
                {
                  issue: "Access-Control-Allow-Credentials is true.",
                  severity: 75,
                  suggestion: "Verify that allowed origins are restricted if credentials are allowed."
                }
              ],
              explanation: "The target site allows credentials and reflects the Origin header, which can lead to potential CSRF attacks via malicious origins. The preflight allows multiple methods and headers with a long max age, increasing risk scope."
            },
            meta: {
              timestamp: "2024-06-05T12:00:00Z",
              duration_ms: 1573,
              api_version: "1.0.0"
            }
          },
        },
        {
          method: "GET",
          path: "/preview",
          description: "Quick CORS header presence check with limited depth. Useful for initial scanning.",
          parameters: [{ name: "url", type: "string", description: "Target URL" }],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              corsHeadersPresent: true,
              credentialsAllowed: false,
              explanation: "CORS headers detected but no credentials allowed."
            },
            meta: {
              timestamp: "2024-06-05T12:00:00Z",
              duration_ms: 654,
              api_version: "1.0.0"
            }
          }
        },
      ],
      parameters: [
        {
          name: "url",
          type: "string",
          description: "Target website URL for CORS policy analysis. Must be a fully qualified http or https URL.",
        }
      ],
      examples: [
        {
          description: "Full paid analysis",
          request: "GET /check?url=https://example.com",
        },
        {
          description: "Free preview analysis",
          request: "GET /preview?url=https://example.com"
        }
      ]
    },
    pricing: {
      mainEndpoint: "/check",
      price: PRICE_STRING,
      description: "Comprehensive CORS policy audit with multiple request checks, origin reflection detection, scoring and detailed remediation."
    }
  });
});

// Free preview endpoint — simple header presence and basics
app.get("/preview", rateLimit("cors-policy-check-preview", 20, 60_000), async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Provide ?url= parameter (http or https URL)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const validated = validateExternalUrl(rawUrl);
  if ("error" in validated) {
    return c.json({ error: `Invalid URL: ${validated.error}` }, 400);
  }

  try {
    const start = performance.now();
    const result = await performPreviewAnalysis(validated.url);
    const duration_ms = Math.round(performance.now() - start);
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Payment middleware: enforce spend caps and payments
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE_STRING,
        "Performs a comprehensive audit of CORS policies on a target website including preflight, origin reflection checks, header validation, scoring (0-100) and letter grade (A-F), plus detailed recommendations to improve security.",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "Target website URL (http or https) for CORS policy check" },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer
  )
);

// Paid full comprehensive check
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing ?url= parameter (http or https URL)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const validated = validateExternalUrl(rawUrl);
  if ("error" in validated) {
    return c.json({ error: `Invalid URL: ${validated.error}` }, 400);
  }

  try {
    const start = performance.now();
    const result: CorsPolicyAnalysisResult = await performFullAnalysis(validated.url);
    const duration_ms = Math.round(performance.now() - start);
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// OnError handler (passes through HTTPExceptions, logs others)
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
