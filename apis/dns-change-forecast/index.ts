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
import { safeFetch, validateExternalUrl } from "../../shared/ssrf";
import {
  DNSChangeForecastRequest,
  DNSChangeForecastResult,
  forecastDnsChanges,
  forecastDnsChangesPreview,
} from "./analyzer";

const app = new Hono();
const API_NAME = "dns-change-forecast";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit
const PRICE_NUM = 0.01;

// 1. CORS middleware open to all origins
app.use("*",
  cors({
    origin: "*",
    allowMethods: ["GET"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// 2. Health check endpoint BEFORE rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limits
// Preview allowed 10/minute due to multi-fetch
app.use("/preview", rateLimit("dns-change-forecast-preview", 10, 60_000));
// Paid endpoint: 30/minute per wallet
app.use("/forecast", rateLimit("dns-change-forecast-forecast", 30, 60_000));
// Global rate limit
app.use("*", rateLimit("dns-change-forecast", 60, 60_000));

// 4. Extract payer wallet
app.use("*", extractPayerWallet());

// 5. API logger with price
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// 6. Info endpoint before payment middleware
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/forecast",
          description: "Get a detailed DNS change forecast report for a domain combining multiple DNS and CT data sources with scoring and recommendations.",
          parameters: [
            { name: "domain", type: "string", required: true, description: "The domain name to analyze." },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              lastScanAt: "2024-06-01T12:00:00Z",
              dnsChangesScore: 92,
              ctCertChangesScore: 85,
              combinedGrade: "A-",
              changeSummary: {
                recentDnsAdds: 3,
                recentDnsDeletes: 1,
                recentCtCerts: 2
              },
              recommendations: [
                {
                  issue: "Frequent DNS TXT record changes",
                  severity: 40,
                  suggestion: "Monitor your DNS TXT records closely and ensure TTLs are optimized for propagation stability."
                }
              ],
              explanation: "The domain shows low frequency DNS changes but moderate certificate transparency log additions, indicating active domain usage with stable DNS settings.",
              details: { dns: {}, ctLogs: {}, forecast: {} }
            },
            meta: {
              timestamp: "2024-06-01T12:00:01Z",
              duration_ms: 350,
              api_version: "1.0.0"
            }
          }
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview with limited insight from recent DNS A record changes only.",
          parameters: [
            { name: "domain", type: "string", required: true, description: "The domain name to get preview." },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              recentARecordChanges: 2,
              previewScore: 78,
              explanation: "Preview includes basic A record change monitoring only.",
              recommendations: [
                { issue: "Ensure NS records are consistent.", severity: 60, suggestion: "Verify and monitor your authoritative NS set." }
              ]
            },
            meta: {
              timestamp: "2024-06-01T12:00:01Z",
              duration_ms: 120,
              api_version: "1.0.0"
            }
          }
        },
      ],
      parameters: [
        { name: "domain", type: "string", description: "The domain name (e.g. example.com)" }
      ],
      examples: [
        "GET /forecast?domain=example.com",
        "GET /preview?domain=example.com"
      ]
    },
    pricing: {
      forecast: PRICE,
      preview: "$0.00 (free)"
    }
  });
});

// 7. Free preview endpoint (no payment)
app.get("/preview", async (c) => {
  const domainRaw = c.req.query("domain");
  if (!domainRaw || typeof domainRaw !== "string") {
    return c.json({ error: "Missing or invalid ?domain= parameter" }, 400);
  }
  if (domainRaw.length > 253) {
    return c.json({ error: "Domain name exceeds maximum length" }, 400);
  }
  const domain = domainRaw.toLowerCase().trim();

  // No validation deeper here, just basic regex check
  if (!/^([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(domain)) {
    return c.json({ error: "Invalid domain format" }, 400);
  }

  const start = performance.now();
  try {
    const result = await forecastDnsChangesPreview(domain);
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
    console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 8. Payment-related middlewares
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /forecast": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive DNS & certificate transparency change forecast and propagation risk analysis with scoring and actionable recommendations",
        {
          input: { domain: "example.com" },
          inputSchema: {
            type: "object",
            properties: {
              domain: { type: "string", description: "Domain name to forecast DNS changes for" },
            },
            required: ["domain"],
          },
        }
      ),
    },
    resourceServer
  )
);

// 9. Paid endpoint
app.get("/forecast", async (c) => {
  const domainRaw = c.req.query("domain");
  if (!domainRaw || typeof domainRaw !== "string") {
    return c.json({ error: "Missing or invalid ?domain= parameter" }, 400);
  }
  if (domainRaw.length > 253) {
    return c.json({ error: "Domain name exceeds maximum length" }, 400);
  }
  const domain = domainRaw.toLowerCase().trim();
  if (!/^([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(domain)) {
    return c.json({ error: "Invalid domain format" }, 400);
  }

  const start = performance.now();
  try {
    // Call full forecast analyzer
    const result = await forecastDnsChanges(domain);
    const duration_ms = Math.round(performance.now() - start);

    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0"
      },
    });
  } catch (e: unknown) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} forecast error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 10. onError handler, pass through HTTPException for 402
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
