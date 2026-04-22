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
  fullAudit,
  previewAudit,
  type FullAuditResult,
  type PreviewResult,
} from "./analyzer";

const app = new Hono();
const API_NAME = "ssl-tls-configuration-forecast";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUM = 0.01;

// Middleware and routing in STRICT order

// 1. CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// 2. Health endpoint before rate limit
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limits
app.use("/check", rateLimit("ssl-tls-config-check", 20, 60_000));
app.use("*", rateLimit("ssl-tls-config-global", 60, 60_000));

// 4. Extract payer wallet
app.use("*", extractPayerWallet());

// 5. API logger with correct price number
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
          path: "/",
          description: "API info and documentation summary",
          parameters: [],
          example_response: {
            api: API_NAME,
            status: "healthy",
            version: "1.0.0",
            docs: {},
            pricing: PRICE,
          },
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview of SSL/TLS configuration with limited scope",
          parameters: [
            { name: "domain", required: true, description: "Domain name to analyze (e.g. example.com)" },
          ],
          example_response: {
            status: "ok",
            data: {
              domain: "example.com",
              certificateExpiryDays: 120,
              protocolsSupported: ["TLSv1.2", "TLSv1.3"],
              cipherStrengthSummary: "Strong",
              score: 85,
              grade: "B",
              recommendations: [
                { issue: "Old TLS versions enabled", severity: 50, suggestion: "Disable TLS 1.0 and TLS 1.1 support" },
              ],
              details: "Preview limited to basic checks and public scan data.",
            },
            meta: {
              timestamp: "2024-01-01T00:00:00.000Z",
              duration_ms: 1300,
              api_version: "1.0.0",
            },
          },
        },
        {
          method: "GET",
          path: "/check",
          description: "Comprehensive paid SSL/TLS configuration forecast and security score",
          parameters: [
            { name: "domain", required: true, description: "Domain name to analyze (e.g. example.com)" },
          ],
          example_response: {
            status: "ok",
            data: {
              domain: "example.com",
              certificateExpiryDays: 120,
              certificateSubject: "CN=example.com",
              protocolsSupported: ["TLSv1.2", "TLSv1.3"],
              cipherSuites: [
                { name: "ECDHE-RSA-AES256-GCM-SHA384", strengthScore: 95 },
                { name: "TLS_AES_128_GCM_SHA256", strengthScore: 98 },
              ],
              overallScore: 92,
              grade: "A",
              recommendations: [
                { issue: "TLS 1.0 support detected", severity: 40, suggestion: "Disable TLS 1.0 and TLS 1.1" },
                { issue: "Certificate expiry under 90 days", severity: 70, suggestion: "Renew certificate promptly" },
              ],
              details: "Combination of DNS, public SSL scan, and own heuristic analysis.",
            },
            meta: {
              timestamp: "2024-01-01T00:00:00.000Z",
              duration_ms: 3000,
              api_version: "1.0.0",
            },
          },
        },
      ],
      parameters: [
        { name: "domain", type: "string", description: "Domain to analyze (no protocol, e.g. example.com)" },
      ],
      examples: [
        "GET /check?domain=example.com",
        "GET /preview?domain=example.com",
      ],
    },
    pricing: {
      paid_endpoint: "/check",
      price: PRICE,
      description: "Comprehensive audit with scoring, cipher analysis, and recommendations",
    },
  });
});

// 7. Spend cap middleware
app.use("*", spendCapMiddleware());

// 8. Payment middleware
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive SSL/TLS configuration forecast including certificate expiry, protocol support, and cipher strength analysis",
        {
          input: { domain: "example.com" },
          inputSchema: {
            type: "object",
            properties: {
              domain: {
                type: "string",
                description: "Domain name to analyze (e.g. example.com)",
                pattern: "^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.(?:[A-Za-z]{2,})$",
              },
            },
            required: ["domain"],
          },
        },
      ),
    },
    resourceServer,
  ),
);

// 9. Paid /check endpoint
app.get("/check", async (c) => {
  const domain = c.req.query("domain");
  if (!domain || typeof domain !== "string") {
    return c.json({ error: "Missing or invalid ?domain= parameter" }, 400);
  }
  if (domain.length > 253) {
    return c.json({ error: "Domain name too long" }, 400);
  }

  // Domain regex sanity check
  const domainRegex = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?:[A-Za-z]{2,})$/;
  if (!domainRegex.test(domain)) {
    return c.json({ error: "Invalid domain format" }, 400);
  }

  const start = performance.now();
  try {
    const result: FullAuditResult | { error: string } = await fullAudit(domain.trim());
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: result,
      meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" },
    });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json(
      { status: "error", error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } },
      status,
    );
  }
});

// 9b. Free /preview endpoint with extended timeout
app.get("/preview", rateLimit("ssl-tls-config-preview", 20, 60_000), async (c) => {
  const domain = c.req.query("domain");
  if (!domain || typeof domain !== "string") {
    return c.json({ error: "Missing or invalid ?domain= parameter" }, 400);
  }
  if (domain.length > 253) {
    return c.json({ error: "Domain name too long" }, 400);
  }

  // Domain regex sanity check
  const domainRegex = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?:[A-Za-z]{2,})$/;
  if (!domainRegex.test(domain)) {
    return c.json({ error: "Invalid domain format" }, 400);
  }

  const start = performance.now();
  try {
    const result: PreviewResult | { error: string } = await previewAudit(domain.trim());
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: result,
      meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" },
    });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json(
      { status: "error", error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } },
      status,
    );
  }
});

// 10. onError pass-through for HTTPException 402 etc
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
