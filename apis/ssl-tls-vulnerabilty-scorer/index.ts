import { Hono } from "hono";
import { cors } from "hono/cors";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl, safeFetch } from "../../shared/ssrf";
import { performFullAudit, performPreviewAudit, SslTlsScorerResult, SslTlsScorerPreview } from "./analyzer";

const app = new Hono();
const API_NAME = "ssl-tls-vulnerabilty-scorer";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit
const PRICE_NUM = 0.01;

// CORS first
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health before rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit
app.use("/check", rateLimit("ssl-tls-vulnerabilty-scorer-check", 25, 60_000));
app.use("*", rateLimit("ssl-tls-vulnerabilty-scorer", 75, 60_000));

// Extract payer wallet
app.use("*", extractPayerWallet());

// Logger with price number
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
          path: "/check",
          description: "Comprehensive SSL/TLS configuration audit by domain or URL",
          parameters: [
            {
              name: "target",
              type: "string",
              description: "Domain or URL to audit (e.g. example.com or https://example.com)",
              required: true
            }
          ],
          example_response: {
            status: "ok",
            data: {
              domain: "example.com",
              sslLabsGrade: "A",
              tlsProtocols: ["TLS 1.2", "TLS 1.3"],
              weakCipherSuites: [],
              vulnerableToLogjam: false,
              certificateTransparency: {
                entries: 5,
                lastSeen: "2023-10-01T12:34:56Z"
              },
              score: 92.5,
              grade: "A",
              recommendations: [
                {
                  issue: "Enable TLS 1.3",
                  severity: "medium",
                  suggestion: "Upgrade your server to support TLS 1.3 for better security and performance."
                }
              ],
              details: "The domain supports strong TLS protocols and cipher suites. Certificate transparency logs indicate recent monitoring."
            },
            meta: {
              timestamp: "2023-10-01T18:00:00Z",
              duration_ms: 2000,
              api_version: "1.0.0"
            }
          }
        },
        {
          method: "GET",
          path: "/preview",
          description: "Lightweight free preview of SSL/TLS support, limited sources",
          parameters: [
            {
              name: "target",
              type: "string",
              description: "Domain or URL to preview audit (e.g. example.com or https://example.com)",
              required: true
            }
          ],
          example_response: {
            status: "ok",
            data: {
              domain: "example.com",
              tlsProtocols: ["TLS 1.2"],
              certificateTransparencyCount: 3,
              score: 78.0,
              grade: "B",
              recommendations: [
                {
                  issue: "Missing TLS 1.3",
                  severity: "medium",
                  suggestion: "Add support for TLS 1.3 to improve security and performance."
                }
              ],
              details: "Basic TLS protocol support detected. Certificate transparency logs found but limited."
            },
            meta: {
              timestamp: "2023-10-01T18:00:00Z",
              duration_ms: 1200,
              api_version: "1.0.0"
            }
          }
        }
      ],
      parameters: [
        {
          name: "target",
          type: "string",
          description: "Domain name or HTTPS URL to analyze",
          required: true
        }
      ],
      examples: [
        "GET /check?target=https://example.com",
        "GET /preview?target=example.com"
      ]
    },
    pricing: {
      check: PRICE
    }
  });
});

// Preview endpoint (free)
app.get("/preview", rateLimit("ssl-tls-vulnerabilty-scorer-preview", 20, 60_000), async (c) => {
  const rawTarget = c.req.query("target");
  if (!rawTarget || typeof rawTarget !== "string") {
    return c.json({ error: "Missing ?target= parameter (domain or URL)" }, 400);
  }
  if (rawTarget.length > 2048) {
    return c.json({ error: "Input exceeds maximum length" }, 400);
  }

  try {
    const result: SslTlsScorerPreview = await performPreviewAudit(rawTarget.trim());
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    const start = performance.now();
    // result already computed
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0"
      }
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Paid route gate
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Aggregates SSL/TLS data from public scans, DNS, and CT logs to score protocol support, cipher suites, and vulnerabilities",
        {
          input: { target: "example.com or https://example.com" },
          inputSchema: {
            type: "object",
            properties: {
              target: { type: "string", description: "Domain or URL to audit" },
            },
            required: ["target"],
          },
        },
      ),
    },
    resourceServer
  )
);

// Paid comprehensive check
app.get("/check", async (c) => {
  const rawTarget = c.req.query("target");
  if (!rawTarget || typeof rawTarget !== "string") {
    return c.json({ error: "Missing ?target= parameter (domain or URL)" }, 400);
  }
  if (rawTarget.length > 2048) {
    return c.json({ error: "Input exceeds maximum length" }, 400);
  }

  try {
    const start = performance.now();
    const result: SslTlsScorerResult = await performFullAudit(rawTarget.trim());
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
        api_version: "1.0.0"
      }
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// CRITICAL error handler - must pass through x402 HTTPExceptions
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
