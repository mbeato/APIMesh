import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl } from "../../shared/ssrf";
import { generateFullReport, generatePreviewReport, ReportResult, PreviewResult } from "./analyzer";

const app = new Hono();
const API_NAME = "domain-security-report";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUM = 0.01;

// CORS middleware, open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint (before rate limiting)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limiting
app.use("/report", rateLimit("domain-security-report-report", 10, 60_000));
app.use("*", rateLimit("domain-security-report", 30, 60_000));

// Extract payer wallet
app.use("*", extractPayerWallet());

// Log api usage and revenue
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
          description: "Free preview generating quick domain security summary",
          parameters: [
            { name: "domain", type: "string", description: "Domain name to analyze" }
          ],
          example_response: {
            status: "ok",
            data: {
              domain: "example.com",
              dmarc: { present: true, policy: "reject", score: 85, details: "DMARC configured with reject policy" },
              dnssec: { enabled: false, score: 40, details: "DNSSEC not enabled" },
              score: 62,
              grade: "D",
              recommendations: [
                {
                  issue: "DNSSEC missing",
                  severity: 70,
                  suggestion: "Enable DNSSEC to protect against DNS spoofing and cache poisoning."
                }
              ],
              explanation: "Basic checks show DMARC present but DNSSEC missing."
            },
            meta: { timestamp: "2024-01-01T12:00:00Z", duration_ms: 200, api_version: "1.0.0" }
          }
        },
        {
          method: "GET",
          path: "/report",
          description: "Comprehensive, paid security report for a domain",
          parameters: [
            { name: "domain", type: "string", description: "Domain name to analyze" }
          ],
          example_response: {
            status: "ok",
            data: {
              domain: "example.com",
              dnsRecords: {
                aRecords: ["93.184.216.34"],
                nsRecords: ["ns1.example.com", "ns2.example.com"],
                dmarc: { present: true, policy: "reject", score: 90, details: "Strict DMARC policy in place." },
                dnssec: { enabled: true, score: 95, details: "DNSSEC is enabled and properly configured." }
              },
              sslCertificate: {
                valid: true,
                issuer: "Let's Encrypt",
                validFrom: "2023-12-01T00:00:00Z",
                validTo: "2024-03-01T00:00:00Z",
                signatureAlgorithm: "SHA256",
                strengthScore: 92,
                recommendations: ["Renew certificate 15 days before expiry."],
                details: "SSL cert is valid, strong algorithm, not expiring soon."
              },
              whois: {
                registered: true,
                registrar: "Example Registrar Inc.",
                creationDate: "2010-01-15T00:00:00Z",
                expiryDate: "2025-01-15T00:00:00Z",
                status: ["clientTransferProhibited"],
                score: 85,
                details: "Domain is actively registered, status locked."
              },
              overallScore: 88,
              grade: "B",
              recommendations: [
                { issue: "Add SPF record", severity: 60, suggestion: "Publish SPF record to reduce email spoofing." },
                { issue: "Enable DNSSEC", severity: 80, suggestion: "Activate DNSSEC for DNS integrity and protection." }
              ],
              explanation: "Comprehensive domain audit found good SSL and WHOIS status, but SPF missing and DNSSEC should be activated."
            },
            meta: { timestamp: "2024-01-01T12:00:00Z", duration_ms: 2100, api_version: "1.0.0" }
          }
        }
      ],
      parameters: [
        { name: "domain", type: "string", required: true, description: "Domain name to analyze, e.g., example.com" }
      ],
      examples: [
        { request: "/preview?domain=example.com", description: "A quick free preview of domain security" },
        { request: "/report?domain=example.com", description: "A detailed paid security report" }
      ]
    },
    pricing: {
      preview: "free",
      report: PRICE
    }
  });
});

// Free preview endpoint
app.get("/preview", rateLimit("domain-security-report-preview", 15, 120_000), async (c) => {
  const domain = c.req.query("domain");
  if (!domain || typeof domain !== "string") {
    return c.json({ status: "error", error: "Missing or invalid ?domain= parameter", detail: "Parameter 'domain' is required and must be a string.", meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, 400);
  }

  const start = performance.now();

  try {
    const result: PreviewResult = await generatePreviewReport(domain.trim());

    const duration_ms = Math.round(performance.now() - start);

    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ status: "error", error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, status);
  }
});

// Register spend cap middleware
app.use("*", spendCapMiddleware());

// Payment middleware for paid routes
app.use(
  paymentMiddleware(
    {
      "GET /report": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive domain security report combining DNS, SSL, and WHOIS with scoring and actionable recommendations",
        {
          input: { domain: "example.com" },
          inputSchema: {
            type: "object",
            properties: {
              domain: { type: "string", description: "Domain to analyze, e.g., example.com" }
            },
            required: ["domain"]
          }
        },
      ),
    },
    resourceServer
  )
);

// Paid comprehensive report endpoint
app.get("/report", async (c) => {
  const domain = c.req.query("domain");
  if (!domain || typeof domain !== "string") {
    return c.json({ status: "error", error: "Missing or invalid ?domain= parameter", detail: "Parameter 'domain' is required and must be a string.", meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, 400);
  }

  const domainClean = domain.trim().toLowerCase();

  const start = performance.now();

  try {
    const result: ReportResult = await generateFullReport(domainClean);

    const duration_ms = Math.round(performance.now() - start);

    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ status: "error", error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, status);
  }
});

// Critical error handler to pass through HTTP exceptions
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
