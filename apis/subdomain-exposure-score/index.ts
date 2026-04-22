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
import {
  comprehensiveExposureScan,
  previewExposureScan,
  SubdomainExposureScoreResult,
  SubdomainExposureScorePreview,
} from "./analyzer";

const API_NAME = "subdomain-exposure-score";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit tier
const PRICE_NUM = 0.01;

const app = new Hono();

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before any rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limiting
app.use(
  "/scan",
  rateLimit("subdomain-exposure-score-scan", 20, 60_000) // 20 requests/min on /scan
);
app.use("*", rateLimit("subdomain-exposure-score", 60, 60_000));

// Extract payer wallet for x402/MPP
app.use("*", extractPayerWallet());

// Logger with price as number
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
          path: "/preview",
          description: "Free preview scan of subdomain enumeration with exposure scoring, limited data sources",
          parameters: [
            { name: "domain", type: "string", required: true, description: "Domain name to analyze subdomains for" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              subdomainCount: 15,
              exposureScore: 42,
              grade: "D",
              details: "Preview scan with limited data sources; for full audit pay via x402 or MPP.",
              recommendations: [
                {
                  issue: "Subdomains expose unused services",
                  severity: 70,
                  suggestion: "Review and disable or secure unused subdomains to reduce attack surface.",
                },
              ],
            },
            meta: {
              timestamp: "2024-01-01T12:00:00.000Z",
              duration_ms: 1423,
              api_version: "1.0.0",
            },
          },
        },
        {
          method: "GET",
          path: "/scan",
          description: "Paid comprehensive full subdomain exposure scoring and audit report",
          parameters: [
            { name: "domain", type: "string", required: true, description: "Domain name to analyze subdomains for" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              subdomains: ["admin.example.com", "dev.example.com"],
              sources: {
                dns: 78,
                ctLogs: 56,
                publicApis: 32,
              },
              exposureScore: 68,
              grade: "C",
              explanation: "Subdomains include sensitive and unused subdomains; several exposed to public access.",
              recommendations: [
                { issue: "Unused subdomains present potential attack paths", severity: 80, suggestion: "Disable or restrict access to unused subdomains ASAP." },
                { issue: "Certificate Transparency detected outdated certs", severity: 60, suggestion: "Renew or revoke outdated certificates and monitor CT logs." },
              ],
            },
            meta: {
              timestamp: "2024-01-01T12:10:00.000Z",
              duration_ms: 5308,
              api_version: "1.0.0",
            },
          },
        },
      ],
      parameters: [
        { name: "domain", type: "string", description: "Domain name to analyze subdomains for" }
      ],
      examples: [
        "/preview?domain=example.com",
        "/scan?domain=example.com",
      ],
    },
    pricing: {
      paidScan: PRICE,
      previewScan: "$0.00 (free)"
    },
  });
});

// Free preview endpoint
app.get(
  "/preview",
  rateLimit("subdomain-exposure-score-preview", 25, 60_000),
  async (c) => {
    const rawDomain = c.req.query("domain");
    if (!rawDomain || typeof rawDomain !== "string") {
      return c.json({ error: "Missing ?domain= parameter" }, 400);
    }
    const domain = rawDomain.trim().toLowerCase();
    if (domain.length > 253) {
      return c.json({ error: "Domain name too long" }, 400);
    }

    // Basic domain pattern check
    if (!/^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$/.test(domain)) {
      return c.json({ error: "Invalid domain format" }, 400);
    }

    const start = performance.now();
    try {
      const result: SubdomainExposureScorePreview = await previewExposureScan(domain);
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
  }
);

// Payment and spend cap middleware
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /scan": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive subdomain enumeration from multiple data sources with scoring, grading, and actionable security recommendations",
        {
          input: { domain: "example.com" },
          inputSchema: {
            type: "object",
            properties: {
              domain: { type: "string", description: "Domain to scan subdomain exposure for" },
            },
            required: ["domain"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid /scan endpoint
app.get("/scan", async (c) => {
  const rawDomain = c.req.query("domain");
  if (!rawDomain || typeof rawDomain !== "string") {
    return c.json({ error: "Missing ?domain= parameter" }, 400);
  }
  const domain = rawDomain.trim().toLowerCase();
  if (domain.length > 253) {
    return c.json({ error: "Domain name too long" }, 400);
  }

  if (!/^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$/.test(domain)) {
    return c.json({ error: "Invalid domain format" }, 400);
  }

  const start = performance.now();
  try {
    const result: SubdomainExposureScoreResult = await comprehensiveExposureScan(domain);
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
