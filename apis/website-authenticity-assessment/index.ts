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
  performFullAssessment,
  performPreviewAssessment,
  AssessmentResult,
  PreviewResult,
} from "./authenticator";

const app = new Hono();
const API_NAME = "website-authenticity-assessment";
const PORT = Number(process.env.PORT) || 3001;
const PRICE_USD = 0.01; // Comprehensive audit tier
const PRICE_STR = "$0.01";

// 1. CORS open all origins
app.use("*",
  cors({
    origin: "*",
    allowMethods: ["GET"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// 2. Health check BEFORE rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limits
app.use("/assess", rateLimit("website-authenticity-assessment-assess", 20, 60_000));
app.use("*", rateLimit("website-authenticity-assessment", 60, 60_000));

// 4. Extract payer wallet
app.use("*", extractPayerWallet());

// 5. API Logger with price
app.use("*", apiLogger(API_NAME, PRICE_USD));

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
          path: "/assess",
          description: "Comprehensive website authenticity assessment combining SSL cert validation, DNS records, redirect chain analysis, and server headers",
          parameters: [
            { name: "url", type: "string", description: "Target website URL (http(s)://...)" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              sslCertificate: {
                valid: true,
                issuer: "Let's Encrypt",
                expiryDays: 45,
                signatureAlgorithm: "SHA256",
                score: 85,
              },
              dnsRecords: {
                aRecords: ["93.184.216.34"],
                cnameRecords: [],
                nsRecords: ["ns1.example.com"],
                mxRecords: ["mail.example.com"],
                score: 90
              },
              redirectChain: ["http://example.com", "https://example.com"],
              securityHeaders: {
                strictTransportSecurity: "max-age=31536000; includeSubDomains; preload",
                xFrameOptions: "SAMEORIGIN",
                contentSecurityPolicy: "default-src 'self'",
                overallScore: 92,
              },
              overallScore: 90,
              grade: "A",
              recommendations: [
                { issue: "SSL expiryDays low", severity: 2, suggestion: "Renew SSL certificate before expiration." },
                { issue: "No SPF record", severity: 1, suggestion: "Add SPF DNS record to improve email trust." }
              ],
              checkedAt: "2024-06-10T12:34:56.789Z"
            },
            meta: {
              timestamp: "2024-06-10T12:34:56.789Z",
              duration_ms: 2345,
              api_version: "1.0.0"
            }
          },
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free quick preview analysis combining SSL validity, basic DNS A record presence, and minimal headers",
          parameters: [
            { name: "url", type: "string", description: "Target website URL (http(s)://...)" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              sslValid: true,
              dnsARecordCount: 2,
              minimalHeadersPresent: true,
              overallScore: 78,
              grade: "B",
              recommendations: [
                { issue: "TTL too long", severity: 1, suggestion: "Lower DNS TTL to reduce cache poisoning risk." }
              ],
              checkedAt: "2024-06-10T12:30:00.000Z"
            },
            meta: {
              timestamp: "2024-06-10T12:30:01.123Z",
              duration_ms: 1350,
              api_version: "1.0.0"
            }
          },
        }
      ],
      parameters: [
        { name: "url", type: "string", description: "Target website URL (http(s)://...)" }
      ],
      examples: [
        "GET /assess?url=https://example.com",
        "GET /preview?url=https://example.com"
      ]
    },
    pricing: {
      paidEndpoint: "/assess",
      pricePerCall: PRICE_STR,
      priceUSD: PRICE_USD,
      description: "Comprehensive website authenticity assessment combining multiple analyses"
    }
  });
});

// 7. Free preview endpoint BEFORE payment middleware
app.get(
  "/preview",
  rateLimit("website-authenticity-assessment-preview", 15, 60_000),
  async (c) => {
    const rawUrl = c.req.query("url");
    if (!rawUrl || typeof rawUrl !== "string") {
      return c.json({ error: "Missing or invalid ?url= parameter" }, 400);
    }
    if (rawUrl.length > 2048) {
      return c.json({ error: "URL exceeds maximum length" }, 400);
    }

    const check = validateExternalUrl(rawUrl.trim());
    if ("error" in check) {
      return c.json({ error: check.error }, 400);
    }

    const start = performance.now();
    try {
      const previewResult: PreviewResult = await performPreviewAssessment(check.url.toString());
      const duration_ms = Math.round(performance.now() - start);
      return c.json({
        status: "ok",
        data: previewResult,
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
  }
);

// 8. Payment and spend cap middleware
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /assess": paidRouteWithDiscovery(
        PRICE_STR,
        "Comprehensive website authenticity assessment with SSL cert, DNS, redirects, headers, scoring, and actionable recommendations",
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

// 9. Paid comprehensive assessment endpoint
app.get("/assess", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing or invalid ?url= parameter" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const check = validateExternalUrl(rawUrl.trim());
  if ("error" in check) {
    return c.json({ error: check.error }, 400);
  }

  const start = performance.now();
  try {
    const result: AssessmentResult = await performFullAssessment(check.url.toString());
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
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 10. Error handling (pass HTTPExceptions for 402s through)
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
