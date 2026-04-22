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
  fullAudit,
  previewAudit,
  SSLEvaluationResult,
  PreviewResult,
  APIInfoResponse
} from "./analyzer";

const app = new Hono();
const API_NAME = "ssl-tls-configuration-ranker";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit pricing
const PRICE_NUM = 0.01;

// CORS - open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"]
}));

// Health endpoint before rate limiting
app.get("/health", (c) => {
  return c.json({ status: "ok" });
});

// Rate limits: heavier on paid endpoint
app.use("/check", rateLimit("ssl-tls-configuration-ranker-check", 15, 60_000));
app.use("*", rateLimit("ssl-tls-configuration-ranker", 50, 60_000));

// Extract payer wallet before logging
app.use("*", extractPayerWallet());

// API logging middleware with correct price number
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint
app.get("/", (c) => {
  const info: APIInfoResponse = {
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/check",
          description: "Perform a deep, comprehensive SSL/TLS configuration audit of a target site",
          parameters: [
            { name: "url", description: "URL of the target site (https://...)", required: true, type: "string" }
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              sslEvaluationScore: 86,
              sslEvaluationGrade: "B",
              weakestProtocols: ["SSLv3", "TLSv1"],
              cipherSuites: {
                strong: ["TLS_AES_256_GCM_SHA384"],
                weak: ["TLS_RSA_WITH_RC4_128_SHA"]
              },
              recommendations: [
                { issue: "Weak protocols enabled", severity: "high", suggestion: "Disable SSLv3 and TLSv1 support to improve security." }
              ],
              details: "Scan aggregated from SSL Labs, DNS records and Certificate Transparency logs.",
              scannedAt: "2024-06-01T12:34:56Z"
            },
            meta: {
              timestamp: "2024-06-01T12:34:58Z",
              duration_ms: 2321,
              api_version: "1.0.0"
            }
          }
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview endpoint doing a quick check for weak protocols and cert age",
          parameters: [
            { name: "url", description: "URL of the target site (https://...)", required: true, type: "string" }
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              quickScore: 65,
              quickGrade: "C",
              notes: "Preview checks only SSL protocol support and cert expiry age.",
              scannedAt: "2024-06-01T12:00:00Z"
            },
            meta: {
              timestamp: "2024-06-01T12:00:01Z",
              duration_ms: 1123,
              api_version: "1.0.0"
            }
          }
        }
      ],
      parameters: [
        { name: "url", description: "HTTPS URL of the target site to be analyzed", type: "string", required: true }
      ],
      examples: [
        "GET /preview?url=https://example.com",
        "GET /check?url=https://example.com"
      ]
    },
    pricing: {
      paidEndpoint: "/check",
      description: "Comprehensive SSL/TLS audit combining SSL Labs, DNS records, CT logs, and protocol analysis.",
      pricePerCall: PRICE
    }
  };
  return c.json(info);
});

// Free preview endpoint with extended timeout (20s) and lighter rate limiting
app.get("/preview", rateLimit("ssl-tls-configuration-ranker-preview", 20, 60_000), async (c) => {
  const rawUrl = c.req.query("url");

  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing ?url= parameter (https://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const validation = validateExternalUrl(rawUrl);
  if ("error" in validation) {
    return c.json({ error: validation.error }, 400);
  }

  try {
    // Use AbortSignal.timeout with generous timeout of 20s for preview
    const result: PreviewResult = await previewAudit(validation.url.toString());
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// spendCapMiddleware enforces spend caps before payment
app.use("*", spendCapMiddleware());

// Payment middleware with paidRouteWithDiscovery on /check
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive SSL/TLS configuration auditor combining multiple data sources for scoring and recommendations",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "HTTPS URL of the site to analyze" }
            },
            required: ["url"]
          }
        }
      )
    },
    resourceServer
  )
);

// Paid route: /check
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");

  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing ?url= parameter (https://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const validation = validateExternalUrl(rawUrl);
  if ("error" in validation) {
    return c.json({ error: validation.error }, 400);
  }

  try {
    // Use AbortSignal.timeout with 10s as required
    const result: SSLEvaluationResult = await fullAudit(validation.url.toString());

    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }

    const start = performance.now();
    const duration_ms = Math.round(performance.now() - start);
    // Return standard envelope with meta
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Error handler - pass through HTTPExceptions for 402s
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
  fetch: app.fetch
};
