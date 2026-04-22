import { Hono } from "hono";
import { cors } from "hono/cors";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import {
  paymentMiddleware,
  paidRouteWithDiscovery,
  resourceServer,
} from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import {
  validateExternalUrl,
  safeFetch,
} from "../../shared/ssrf";
import {
  ForecastResult,
  fetchDnsTlsRecords,
  fetchCrtShCertificates,
  analyzeCertificates,
  analyzeTlsProtocols,
  computeScoreAndGrade,
  generateRecommendations,
} from "./analyzer";

const app = new Hono();
const API_NAME = "ssl-tls-expiry-forecast";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUMBER = 0.01;

// CORS first
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health check before rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limiting
app.use("/forecast", rateLimit("ssl-tls-expiry-forecast-forecast", 15, 60_000));
app.use("*", rateLimit("ssl-tls-expiry-forecast", 60, 60_000));

app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, PRICE_NUMBER));

// Info endpoint with doc and pricing
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    description: "Aggregates SSL certificate data from free public sources and DNS to forecast expiry dates and protocol support, enabling proactive certificate renewal alerts across multiple domains.",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/forecast",
          description: "Comprehensive SSL/TLS certificate and protocol expiry forecast for multiple domains",
          parameters: [
            { name: "domains", description: "Comma separated domains to analyze (required, max 10 domains)", in: "query", required: true, type: "string" },
          ],
          exampleRequest: "/forecast?domains=example.com,google.com",
          exampleResponse: {
            status: "ok",
            data: {
              domains: [
                {
                  domain: "example.com",
                  certExpiryDays: 42,
                  certScore: 87,
                  protocolSupport: {
                    tls1_2: true,
                    tls1_3: true,
                    legacyTls: false
                  },
                  grade: "B",
                  recommendations: [
                    { issue: "Certificate expires soon", severity: "high", suggestion: "Renew certificate within 30 days" },
                    { issue: "Legacy TLS disabled", severity: "low", suggestion: "Check clients compatibility" }
                  ],
                  details: "Certificate is valid but expires in 42 days. Supports TLS 1.2 and 1.3, legacy TLS disabled."
                },
              ],
              scannedAt: "2024-06-24T12:00:00Z"
            },
            meta: {
              timestamp: "2024-06-24T12:00:00Z",
              duration_ms: 312,
              api_version: "1.0.0"
            }
          }
        },
      ],
      parameters: [
        { name: "domains", description: "Comma separated domain names, max 10", type: "string", required: true }
      ],
      examples: [
        {
          description: "Forecast SSL/TLS expiry and protocol support for example.com and google.com",
          request: "/forecast?domains=example.com,google.com",
        },
      ],
    },
    pricing: {
      unit: "per call",
      price: PRICE,
      explanation: "Comprehensive audit with multiple data sources combined, scoring, grading and actionable recommendations.",
    },
  });
});

// Free preview endpoint - just perform basic DNS TLS fetch, no payment
app.get("/preview", rateLimit("ssl-tls-expiry-forecast-preview", 30, 60_000), async (c) => {
  const domainsRaw = c.req.query("domains");
  if (!domainsRaw || typeof domainsRaw !== "string") {
    return c.json({ error: "Missing ?domains= parameter (comma separated domain list)" }, 400);
  }

  const domains = domainsRaw.split(",").map((d) => d.trim()).filter((d) => d.length > 0).slice(0, 5);
  if (domains.length === 0) {
    return c.json({ error: "At least one domain must be provided" }, 400);
  }

  const start = performance.now();

  try {
    const results = await Promise.all(domains.map(async (domain) => {
      try {
        const dnsTls = await fetchDnsTlsRecords(domain, AbortSignal.timeout(20000));
        return {
          domain,
          dnsTls,
          note: "Basic DNS TLS records fetched for preview",
        };
      } catch (e: any) {
        return {
          domain,
          error: e.message || String(e),
        };
      }
    }));

    const duration_ms = Math.round(performance.now() - start);

    return c.json({
      status: "ok",
      data: {
        domains: results,
        scannedAt: new Date().toISOString(),
      },
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0",
      },
    });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

app.use("*", spendCapMiddleware());

app.use(
  paymentMiddleware(
    {
      "GET /forecast": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive SSL/TLS expiry forecast combining DNS, crt.sh data and protocol support analysis with scoring, grading and actionable recommendations",
        {
          input: { domains: "example.com,google.com" },
          inputSchema: {
            properties: {
              domains: {
                type: "string",
                description: "Comma separated list of domains (max 10)",
              },
            },
            required: ["domains"],
          },
        },
      ),
    },
    resourceServer
  )
);

interface ForecastQuery {
  domains?: string;
}

app.get("/forecast", async (c) => {
  const query = c.req.query();
  const domainsRaw = query.domains;
  if (!domainsRaw || typeof domainsRaw !== "string") {
    return c.json({ error: "Missing ?domains= parameter (comma separated domain list)" }, 400);
  }

  // Limit to 10 domains max
  const domains = domainsRaw.split(",").map((d) => d.trim().toLowerCase()).filter((d) => d.length > 0).slice(0, 10);
  if (domains.length === 0) {
    return c.json({ error: "At least one domain must be provided" }, 400);
  }

  const start = performance.now();

  try {
    // Parallel fetch crt.sh certificate data and DNS TLS records
    // For each domain

    const domainResults: ForecastResult[] = [];

    for (const domain of domains) {
      // Validate domain string format loosely
      if (!/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(domain)) {
        domainResults.push({
          domain,
          error: "Invalid domain format",
        });
        continue;
      }

      try {
        // parallel crt.sh and DNS fetch
        const [crtData, dnsTls] = await Promise.all([
          fetchCrtShCertificates(domain, AbortSignal.timeout(10000)),
          fetchDnsTlsRecords(domain, AbortSignal.timeout(10000)),
        ]);

        // Analyze certs and protocols
        const certAnalysis = analyzeCertificates(crtData);
        const protocolAnalysis = analyzeTlsProtocols(dnsTls);

        // Compute final score and grade
        const { score, grade } = computeScoreAndGrade(certAnalysis, protocolAnalysis);

        // Generate recommendations
        const recommendations = generateRecommendations(certAnalysis, protocolAnalysis);

        const detailsText = `Certificate has ${certAnalysis.certCount} entries, earliest expiry in ${certAnalysis.earliestExpiryDays} days. ` +
          `Protocols: TLS1.2 supported=${protocolAnalysis.tls1_2}, TLS1.3 supported=${protocolAnalysis.tls1_3}, legacy TLS=${protocolAnalysis.legacyTls ? "enabled" : "disabled"}.`;

        domainResults.push({
          domain,
          certExpiryDays: certAnalysis.earliestExpiryDays,
          certScore: certAnalysis.certScore,
          protocolSupport: protocolAnalysis,
          grade,
          recommendations,
          details: detailsText,
        });
      } catch (e: any) {
        domainResults.push({
          domain,
          error: e.message || String(e),
        });
      }
    }

    const duration_ms = Math.round(performance.now() - start);

    return c.json({
      status: "ok",
      data: {
        domains: domainResults,
        scannedAt: new Date().toISOString(),
      },
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0",
      },
    });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// CRITICAL error handler: pass through HTTPException for 402s
app.onError((err: unknown, c) => {
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
