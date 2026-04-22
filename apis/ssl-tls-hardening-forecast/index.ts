import { Hono } from "hono";
import { cors } from "hono/cors";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl, safeFetch } from "../../shared/ssrf";
import {
  analyzeSslScanResults,
  analyzeDnsTlsRecords,
  mergeForecasts,
  forecastExpiryAndSecurity,
  SslTlsHardeningReport,
  ForecastInput,
  ForecastResult,
} from "./analyzer";

const app = new Hono();
const API_NAME = "ssl-tls-hardening-forecast";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = 0.01;
const PRICE_STR = "$0.01";
const SUBDOMAIN = "ssl-tls-hardening-forecast.apimesh.xyz";

// ── Middleware order ─────────────────────────────────────────────────────────
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

app.get("/health", (c) => c.json({ status: "ok" }));

app.use("/forecast", rateLimit("ssl-tls-hardening-forecast-forecast", 20, 60_000));
app.use("*", rateLimit("ssl-tls-hardening-forecast", 60, 60_000));

app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, PRICE));

app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    description: "Aggregates SSL/TLS configuration details from free public scans and DNS records, then forecasts expiry dates, protocol and cipher support with detailed alerts and recommendations.",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/forecast",
          description: "Paid endpoint: Analyze SSL/TLS info and forecast renewal and security outlook",
          parameters: [
            {
              name: "host",
              description: "Hostname to analyze (no scheme)"
            }
          ],
          exampleResponse: {
            status: "ok",
            data: {
              host: "example.com",
              sslReport: {},
              dnsTlsReport: {},
              forecast: {},
              grade: "A",
              score: 85,
              recommendations: [
                { issue: "Upcoming SSL cert expiry", severity: 80, suggestion: "Renew certificate at least 15 days before expiry." }
              ]
            },
            meta: {
              timestamp: "2024-01-01T00:00:00Z",
              duration_ms: 250,
              api_version: "1.0.0"
            }
          }
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview endpoint: Quick partial SSL/TLS check"
        }
      ],
      parameters: [
        { name: "host", type: "string", description: "Domain name (no scheme)" }
      ],
      examples: [
        "GET /forecast?host=example.com",
        "GET /preview?host=example.com"
      ]
    },
    pricing: {
      paidEndpoint: PRICE_STR,
      info: "$0.01 per full analysis call via x402 or MPP payment protocols"
    },
    subdomain: SUBDOMAIN
  });
});

// Free preview endpoint - more lenient timeout and minimal data
app.get("/preview", rateLimit("ssl-tls-hardening-forecast-preview", 30, 60_000), async (c) => {
  const start = performance.now();
  const host = c.req.query("host");
  if (!host || typeof host !== "string") {
    return c.json({ error: "Missing ?host= parameter" }, 400);
  }

  if (host.length > 253) {
    return c.json({ error: "Host parameter too long" }, 400);
  }

  // Basic host validation
  if (!/^[a-z0-9.-]+$/i.test(host)) {
    return c.json({ error: "Invalid hostname" }, 400);
  }

  try {
    const result = await analyzeSslScanResults(host, AbortSignal.timeout(20000));
    // limit fields returned for preview
    const previewData = {
      host: result.host,
      certExpiryDays: result.certExpiryDays,
      protocols: result.protocols,
      ciphers: result.ciphers,
      secure: result.secure,
      warnings: result.warnings.filter((w) => w.level >= 60), // high severity only
      checkedAt: result.checkedAt,
    };
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: previewData,
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

// Payment middleware
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /forecast": paidRouteWithDiscovery(
        PRICE_STR,
        "Comprehensive SSL/TLS configuration aggregation, expiry forecasting, protocol and cipher support analysis, with detailed scoring and actionable recommendations.",
        {
          input: { host: "example.com" },
          inputSchema: {
            type: "object",
            properties: {
              host: { type: "string", description: "Hostname to analyze (no scheme)" }
            },
            required: ["host"]
          }
        }
      ),
    },
    resourceServer
  )
);

// Paid endpoint
app.get("/forecast", async (c) => {
  const start = performance.now();
  const host = c.req.query("host");
  if (!host || typeof host !== "string") {
    return c.json({ error: "Missing ?host= parameter" }, 400);
  }

  if (host.length > 253) {
    return c.json({ error: "Host parameter too long" }, 400);
  }

  if (!/^[a-z0-9.-]+$/i.test(host)) {
    return c.json({ error: "Invalid hostname" }, 400);
  }

  try {
    // Run multiple parallel external queries with 10s timeout: public SSL scans and DNS TLS records
    // Then advance forecast aggregation
    const [sslScan, dnsTls] = await Promise.all([
      analyzeSslScanResults(host, AbortSignal.timeout(10000)),
      analyzeDnsTlsRecords(host, AbortSignal.timeout(10000))
    ]);

    const forecast = mergeForecasts(sslScan, dnsTls);
    const grading = forecastExpiryAndSecurity(forecast);

    const result: ForecastResult = {
      host: host.toLowerCase(),
      sslReport: sslScan,
      dnsTlsReport: dnsTls,
      forecast,
      score: grading.score,
      grade: grading.grade,
      recommendations: grading.recommendations,
      checkedAt: new Date().toISOString()
    };

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

// onError handler passes through HTTPException 402 etc.
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
