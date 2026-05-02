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
  safeFetch,
  validateExternalUrl,
  readBodyCapped
} from "../../shared/ssrf";
import {
  SubdomainSecurityAuditResult,
  previewAudit,
  fullAudit
} from "./analyzer";

const app = new Hono();
const API_NAME = "subdomain-security-audit";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUM = 0.01;

// CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits:
app.use("/check", rateLimit("subdomain-security-audit-check", 20, 60_000));
app.use("*", rateLimit("subdomain-security-audit", 80, 60_000));

// Extract payer wallet
app.use("*", extractPayerWallet());

// API usage logger
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint after logger
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
          description: "Perform a comprehensive subdomain configuration security audit, combining DNS, HTTPS certificate data, and security headers analysis.",
          parameters: [
            { name: "url", in: "query", description: "Full HTTP(S) URL of target subdomain", required: true, type: "string" }
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://sub.example.com",
              dnsRecords: {
                a: ["93.184.216.34"],
                ns: ["ns1.example.com", "ns2.example.com"],
                cname: null,
                mx: ["mail.example.com"]
              },
              httpsCertificate: {
                valid: true,
                subject: "CN=sub.example.com",
                issuer: "Let's Encrypt Authority X3",
                validFrom: "2023-01-01T00:00:00Z",
                validTo: "2023-04-01T00:00:00Z",
                expiryDays: 20,
                signatureAlgorithm: "sha256WithRSAEncryption",
                strengthScore: 85
              },
              securityHeaders: {
                present: ["Strict-Transport-Security", "X-Frame-Options"],
                missing: ["Content-Security-Policy", "Permissions-Policy"],
                deprecated: []
              },
              overallScore: 78,
              grade: "B",
              recommendations: [
                { issue: "Certificate expiring soon", severity: "high", suggestion: "Renew SSL certificate within 20 days." },
                { issue: "Missing Content-Security-Policy header", severity: "medium", suggestion: "Add a strict CSP header to reduce XSS risk." },
                { issue: "No Permissions-Policy header", severity: "medium", suggestion: "Add Permissions-Policy header to limit browser features." }
              ],
              explanation: "This subdomain has valid DNS and HTTPS configuration but misses several critical security headers, lowering its overall security grade. Renew SSL certificate soon and add missing headers for best security."
            },
            meta: { timestamp: "ISO8601", duration_ms: 500, api_version: "1.0.0" }
          }
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview audit providing basic checks (DNS resolution and HTTPS availability) of a subdomain.",
          parameters: [
            { name: "url", in: "query", description: "Full HTTP(S) URL of target subdomain", required: true, type: "string" }
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://sub.example.com",
              dnsResolved: true,
              httpsAvailable: true,
              issues: [],
              scannedAt: "ISO8601"
            },
            meta: { timestamp: "ISO8601", duration_ms: 150, api_version: "1.0.0" }
          }
        }
      ],
      parameters: [
        { name: "url", description: "The full HTTP or HTTPS URL of the subdomain to audit.", required: true }
      ],
      examples: [
        "GET /check?url=https://sub.example.com",
        "GET /preview?url=https://sub.example.com"
      ]
    },
    pricing: {
      description: "Comprehensive audit combining DNS, HTTPS, headers, scoring, and recommendations.",
      price: PRICE
    }
  });
});

// Free preview endpoint - basic DNS and HTTPS availability checks
app.get("/preview", rateLimit("subdomain-security-audit-preview", 20, 60_000), async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
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
    const result = await previewAudit(check.url.toString());
    const duration_ms = Math.round(performance.now() - start);
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Spend cap middleware
app.use("*", spendCapMiddleware());

// Payment middleware with price and discovery
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive subdomain security audit combining DNS records, HTTPS certificate, and HTTP security headers with scoring and actionable recommendations",
        {
          input: { url: "https://subdomain.example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "Subdomain URL to audit" },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer
  ),
);

// Paid full audit
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
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
    const result = await fullAudit(check.url.toString());
    if ((result as any).error && !(result as any).dnsRecords) {
      // If error and no dnsRecords, treat as error response
      return c.json({ error: (result as any).error }, 400);
    }
    const duration_ms = Math.round(performance.now() - start);
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Critical error handler
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
