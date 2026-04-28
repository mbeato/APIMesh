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
import { fullAudit, previewAudit } from "./analyzer";
import type { AuditResult, PreviewResult } from "./types";

const app = new Hono();
const API_NAME = "ssl-tls-protocol-compliance";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = 0.01; // $0.01 per call for comprehensive audit
const PRICE_STR = "$0.01";

// CORS open to all origins, allow GET only
app.use("*",
  cors({
    origin: "*",
    allowMethods: ["GET"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// Health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit: 30/min for /check, 90/min global
app.use("/check", rateLimit("ssl-tls-protocol-compliance-check", 30, 60_000));
app.use("*", rateLimit("ssl-tls-protocol-compliance", 90, 60_000));

// Extract payer wallet
app.use("*", extractPayerWallet());

// API Logger with fixed price number
app.use("*", apiLogger(API_NAME, PRICE));

// Info endpoint returns metadata and docs
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    description: "Evaluate SSL/TLS configurations of a domain with comprehensive audit using multiple data sources.",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/check",
          description: "Perform a comprehensive SSL/TLS compliance audit for a domain.",
          parameters: [{ name: "domain", required: true, type: "string", description: "Domain name to audit." }],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              sslScan: { supportsTlsVersions: ["TLS 1.2", "TLS 1.3"], weakProtocolsDetected: false, ciphersSummary: { total: 20, weak: 0, strong: 20 } },
              complianceScores: { tlsSupportScore: 100, cipherStrengthScore: 100, overall: 100, grade: "A" },
              recommendations: [],
              explanation: "Full report explanation text.",
            },
            meta: { timestamp: "...", duration_ms: 2000, api_version: "1.0.0" },
          },
        },
        {
          method: "GET",
          path: "/preview",
          description: "Get a free preview summary of SSL/TLS compliance for a domain.",
          parameters: [{ name: "domain", required: true, type: "string", description: "Domain name for preview." }],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              preview: true,
              tlsSupportSummary: "TLS 1.2, TLS 1.3",
              recommendations: [],
              note: "Preview provides basic TLS version info and suggestions.",
            },
            meta: { timestamp: "...", duration_ms: 500, api_version: "1.0.0" },
          },
        },
      ],
      parameters: [
        { name: "domain", type: "string", description: "Target domain to analyze." },
      ],
      examples: [
        { path: "/check?domain=example.com", description: "Run a full SSL/TLS audit" },
        { path: "/preview?domain=example.com", description: "Get a free TLS version summary preview" },
      ],
    },
    pricing: {
      description: "Comprehensive SSL/TLS audit with multi-source analysis.",
      pricePerRequest: PRICE_STR,
      paymentMethods: ["x402", "MPP"],
    },
  });
});

// Free preview endpoint with generous timeout (20s) and rate limit 15/min
app.get("/preview", rateLimit("ssl-tls-protocol-compliance-preview", 15, 60_000), async (c) => {
  const rawDomain = c.req.query("domain");
  if (!rawDomain || typeof rawDomain !== "string") {
    return c.json({ error: "Missing ?domain= parameter" }, 400);
  }
  if (rawDomain.length > 253) {
    return c.json({ error: "Domain length exceeds maximum allowed" }, 400);
  }

  const start = performance.now();
  try {
    const result = await previewAudit(rawDomain.trim());
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result) {
      return c.json({
        status: "error",
        error: "Preview analysis failed",
        detail: result.error,
        meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" },
      }, 502);
    }

    return c.json({
      status: "ok",
      data: result,
      meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Spend cap middleware
app.use("*", spendCapMiddleware());

// Payment middleware. Paid route /check with paidRouteWithDiscovery
app.use(
  "*",
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE_STR,
        "Comprehensive SSL/TLS protocol compliance audit combining SSL scan, DNS and TLS handshake analyses",
        {
          input: { domain: "example.com" },
          inputSchema: {
            properties: {
              domain: { type: "string", description: "Domain name to audit (e.g. example.com)" },
            },
            required: ["domain"],
          },
        },
      ),
    },
    resourceServer
  )
);

// Paid route /check endpoint
app.get("/check", async (c) => {
  const domainRaw = c.req.query("domain");

  if (!domainRaw || typeof domainRaw !== "string") {
    return c.json({ error: "Missing ?domain= parameter" }, 400);
  }
  if (domainRaw.length > 253) {
    return c.json({ error: "Domain exceeds maximum length" }, 400);
  }

  const start = performance.now();
  try {
    const result = await fullAudit(domainRaw.trim());
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result) {
      return c.json({
        status: "error",
        error: "Audit failed",
        detail: result.error,
        meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" },
      }, 400);
    }

    return c.json({
      status: "ok",
      data: result as AuditResult,
      meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// onError handler passes through HTTPExceptions (e.g. 402) else error 500
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
