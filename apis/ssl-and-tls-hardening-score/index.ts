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
import { fullHardeningAudit, previewAudit } from "./analyzer";
import type { HardeningScoreResult, PreviewResult } from "./types";

const app = new Hono();
const API_NAME = "ssl-and-tls-hardening-score";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit pricing
const PRICE_NUM = 0.01;

// 1. CORS open to all
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// 2. /health endpoint before rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limiting
app.use("/check", rateLimit(`${API_NAME}-check`, 30, 60_000));
app.use("*", rateLimit(API_NAME, 90, 60_000));

// 4. Extract payer wallet
app.use("*", extractPayerWallet());

// 5. API logger with price numeric
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
          description: "Run full SSL, TLS, and HTTP security header comprehensive hardening score with actionable recommendations",
          parameters: [{ name: "url", type: "string", description: "HTTPS URL to analyze (http:// will be rejected)" }],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              sslCertificate: { valid: true, strengthScore: 98, subject: "example.com", /* ... */ },
              tlsAnalysis: { protocolsSupported: ["TLS 1.3", "TLS 1.2"], cipherStrengthScore: 95, /* ... */ },
              securityHeaders: { overallGrade: "A", score: 92, /* ... */ },
              combinedScore: 95,
              combinedGrade: "A",
              recommendations: [
                { issue: "All checks passed", severity: "low", suggestion: "Maintain current settings." }
              ],
              checkedAt: "2024-06-10T12:34:56.000Z"
            },
            meta: { timestamp: "2024-06-10T12:34:56.000Z", duration_ms: 1300, api_version: "1.0.0" },
          },
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview endpoint giving a summarized SSL and TLS hardening summary for the site",
          parameters: [{ name: "url", type: "string", description: "HTTPS URL for preview analysis" }],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              preview: true,
              sslCertificateSummary: { valid: true, expiryDays: 75 },
              tlsSummary: { strongProtocols: ["TLS 1.3", "TLS 1.2"], weakProtocols: [] },
              overallScore: 92,
              overallGrade: "A",
              checkedAt: "2024-06-10T12:34:56.000Z",
              note: "Preview endpoint returns limited data, full audit requires payment."
            },
            meta: { timestamp: "2024-06-10T12:34:56.000Z", duration_ms: 800, api_version: "1.0.0" }
          }
        }
      ],
      parameters: [
        { name: "url", type: "string", description: "The HTTPS URL to analyze, max 2048 chars" },
      ],
      examples: [
        "GET /check?url=https://example.com",
        "GET /preview?url=https://expired.badssl.com",
      ],
    },
    pricing: {
      mainEndpoint: "/check",
      pricePerCall: PRICE,
      description: "Comprehensive SSL, TLS, and HTTP header analysis for HTTPS sites",
    },
  });
});

// 7. Free preview endpoint with longer timeout
app.get(
  "/preview",
  rateLimit(`${API_NAME}-preview`, 15, 60_000),
  async (c) => {
    const rawUrl = c.req.query("url");
    if (!rawUrl) {
      return c.json({ error: "Missing ?url= parameter (provide a full https:// URL)" }, 400);
    }
    if (typeof rawUrl !== "string") {
      return c.json({ error: "Invalid url parameter type" }, 400);
    }
    if (rawUrl.length > 2048) {
      return c.json({ error: "URL exceeds maximum length" }, 400);
    }

    // Validate URL
    const valid = validateExternalUrl(rawUrl.trim());
    if ("error" in valid) {
      return c.json({ error: valid.error }, 400);
    }

    try {
      // Use extended timeout for preview (15s)
      const start = performance.now();
      const result = await previewAudit(valid.url.toString());
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
  }
);

// 8. Spend cap middleware
app.use("*", spendCapMiddleware());

// 9. Payment middleware
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive SSL certificate, TLS cipher and protocol, and HTTP security headers hardening audit with grading and recommendations",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            type: "object",
            properties: {
              url: { type: "string", description: "HTTPS URL of the site to analyze" },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer,
  ),
);

// 10. Paid endpoint
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (provide full https:// URL)" }, 400);
  }
  if (typeof rawUrl !== "string") {
    return c.json({ error: "Invalid url parameter type" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  // Validate URL
  const valid = validateExternalUrl(rawUrl.trim());
  if ("error" in valid) {
    return c.json({ error: valid.error }, 400);
  }

  try {
    const start = performance.now();
    const result = await fullHardeningAudit(valid.url.toString());
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result && !("sslCertificate" in result)) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({ status: "ok", data: result as HardeningScoreResult, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: any) {
    if (typeof e === "object" && e !== null && "getResponse" in e) {
      return (e as any).getResponse();
    }
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 11. Error handler
app.onError((err, c) => {
  // Pass through HTTPException from x402
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
