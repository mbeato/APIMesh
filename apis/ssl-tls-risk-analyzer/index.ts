import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { analyzeRisk } from "./analyzer";

const app = new Hono();
const API_NAME = "ssl-tls-risk-analyzer";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit with 5+ checks, scoring, detailed report is $0.01 per spec
const PRICE_NUMERIC = 0.01;

// CORS Middleware open to all origins, allowGET with payments headers
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits after health
app.use("/analyze", rateLimit("ssl-tls-risk-analyzer-analyze", 20, 60_000)); // 20/min
app.use("*", rateLimit("ssl-tls-risk-analyzer", 60, 60_000)); // 60/min total

app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, PRICE_NUMERIC));

// Info endpoint after logger but before payments
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    description: "Aggregates SSL/TLS configuration details from free public scans, DNS records, and certificate transparency logs, then performs a risk assessment based on outdated protocols, weak cipher suites, and certificate transparency issues.",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/analyze",
          description: "Perform a comprehensive SSL/TLS risk analysis for a target hostname.",
          parameters: [{ name: "host", description: "Hostname or URL to analyze (http(s):// optional)" }],
          exampleResponse: {
            status: "ok",
            data: {
              overallScore: { numeric: 85, grade: "B" },
              protocolsEvaluated: [],
              weakCiphers: [],
              certTransparencyIssues: [],
              dnsTlsRecords: { tlsa: [], cAA: [], dANE: [], explanation: "" },
              recommendations: [],
              explanation: "",
              checkedAt: "2024-01-01T12:00:00Z",
              targetHost: "example.com"
            },
            meta: { timestamp: "2024-01-01T12:00:01Z", duration_ms: 150, api_version: "1.0.0" }
          },
        },
      ],
      parameters: [
        { name: "host", description: "Hostname or URL string to analyze" }
      ],
      examples: [
        {
          request: "/analyze?host=https://example.com",
          response: {
            status: "ok",
            data: {
              overallScore: { numeric: 85, grade: "B" },
              protocolsEvaluated: [],
              weakCiphers: [],
              certTransparencyIssues: [],
              dnsTlsRecords: { tlsa: [], cAA: [], dANE: [], explanation: "" },
              recommendations: [],
              explanation: "Detailed explanation text.",
              checkedAt: "2024-01-01T12:00:00Z",
              targetHost: "example.com"
            },
            meta: {
              timestamp: "2024-01-01T12:00:01Z",
              duration_ms: 150,
              api_version: "1.0.0"
            }
          }
        }
      ]
    },
    pricing: { pricePerCall: PRICE, description: "Comprehensive SSL/TLS risk audit with multi-source aggregation and scoring." }
  });
});

app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /analyze": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive SSL/TLS risk audit with multi-layered checks, scoring, and detailed remediation recommendations.",
        {
          input: { host: "example.com" },
          inputSchema: {
            properties: {
              host: { type: "string", description: "Hostname or URL to analyze SSL/TLS risk for" },
            },
            required: ["host"],
          },
        }
      ),
    },
    resourceServer
  )
);

app.get("/analyze", async (c) => {
  const hostRaw = c.req.query("host");
  if (!hostRaw || typeof hostRaw !== "string") {
    return c.json({ error: "Missing ?host= parameter with hostname or URL to analyze" }, 400);
  }
  if (hostRaw.length > 256) {
    return c.json({ error: "Host parameter exceeds maximum length" }, 400);
  }

  const start = performance.now();
  try {
    const riskResult = await analyzeRisk(hostRaw.trim());
    if ("error" in riskResult) {
      return c.json({ error: riskResult.error, detail: "Invalid or unsupported host parameter" }, 400);
    }
    const duration_ms = Math.round(performance.now() - start);

    return c.json({
      status: "ok",
      data: riskResult,
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

// Error handler to pass through 402 from x402 paymentMiddleware
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
