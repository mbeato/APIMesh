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
import { validateExternalUrl, safeFetch } from "../../shared/ssrf";

import {
  IpAnalysisResult,
  analyzeIp,
  IpInfrastructureInfo,
  previewAnalyzeIp
} from "./analyzer";

const app = new Hono();
const API_NAME = "ip-infrastructure-analyzer";
const PORT = Number(process.env.PORT) || 3001;
const PRICE_STRING = "$0.01";
const PRICE_NUM = 0.01;

// CORS middleware open to all origins and headers
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit for paid and preview endpoints (reasonable limits because of multiple external calls)
app.use("/analyze", rateLimit("ip-infrastructure-analyzer-analyze", 20, 60_000));
app.use("/preview", rateLimit("ip-infrastructure-analyzer-preview", 30, 60_000));
app.use("*", rateLimit("ip-infrastructure-analyzer", 90, 60_000));

// Extract payer wallet for payment tracking
app.use("*", extractPayerWallet());

// Logger middleware with price for paid routes
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
          path: "/analyze",
          description: "Comprehensive IP infrastructure analysis: ASN, ISP, geolocation, routing checks, scoring, recommendations.",
          parameters: [
            { name: "ip", type: "string", description: "IPv4 or IPv6 address to analyze (required)" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              ip: "8.8.8.8",
              asn: { asn: 15169, name: "Google LLC", isp: "Google LLC", country: "US" },
              geolocation: { country: "US", region: "California", city: "Mountain View", lat: 37.4056, lon: -122.0775 },
              routing: { bgpPrefix: "8.8.8.0/24", bgpOrigin: "IGP", bgpAsPath: [15169], isBogon: false },
              score: 87,
              grade: "B",
              explanation: "The IP is registered to Google LLC. Geolocation matches California. No routing bogon detected. Overall score good.",
              recommendations: [
                { issue: "No issues detected.", severity: 0, suggestion: "Maintain current IP allocation and monitor regularly." }
              ]
            },
            meta: {
              timestamp: "ISO8601",
              duration_ms: 140,
              api_version: "1.0.0"
            }
          },
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview of basic IP info: ASN, country, basic geolocation.",
          parameters: [
            { name: "ip", type: "string", description: "IPv4 or IPv6 address to preview (required)" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              ip: "8.8.8.8",
              asn: { asn: 15169, isp: "Google LLC", country: "US" },
              country: "US",
              city: null,
              region: null,
              note: "Preview gives only partial info. Pay for full report."
            },
            meta: {
              timestamp: "ISO8601",
              duration_ms: 120,
              api_version: "1.0.0"
            }
          }
        }
      ],
      parameters: [
        { name: "ip", type: "string", description: "IP address (v4 or v6) to analyze." }
      ],
      examples: [
        { path: "/analyze?ip=8.8.8.8", method: "GET" },
        { path: "/preview?ip=8.8.8.8", method: "GET" }
      ]
    },
    pricing: {
      analyze: PRICE_STRING,
      preview: "free",
      description: "$0.01 per full analysis via x402/MPP. Preview is free with limited info."
    }
  });
});

// Free preview endpoint with generous timeout
app.get("/preview", async (c) => {
  const rawIp = c.req.query("ip");
  if (!rawIp || typeof rawIp !== "string") {
    return c.json({ error: "Missing ?ip= parameter (IP address)" }, 400);
  }

  try {
    const start = performance.now();
    const result = await previewAnalyzeIp(rawIp.trim());
    const duration_ms = Math.round(performance.now() - start);
    if ("error" in result) {
      return c.json({
        status: "error",
        error: result.error,
        detail: "Invalid IP or data unavailable",
        meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" }
      }, 400);
    }

    return c.json({
      status: "ok",
      data: result,
      meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" }
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, status);
  }
});

// Payment and spend cap middleware after preview
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /analyze": paidRouteWithDiscovery(
        PRICE_STRING,
        "Comprehensive IP infrastructure audit combining ASN, ISP, geolocation, routing info, scoring, and remediation recommendations",
        {
          input: { ip: "8.8.8.8" },
          inputSchema: {
            properties: {
              ip: { type: "string", description: "IPv4 or IPv6 address to analyze" },
            },
            required: ["ip"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid analyze endpoint
app.get("/analyze", async (c) => {
  const rawIp = c.req.query("ip");
  if (!rawIp || typeof rawIp !== "string") {
    return c.json({ error: "Missing ?ip= parameter (IP address)" }, 400);
  }

  try {
    const start = performance.now();
    const result: IpAnalysisResult | { error: string } = await analyzeIp(rawIp.trim());
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result) {
      return c.json({
        status: "error",
        error: result.error,
        detail: "Failed to analyze IP",
        meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" }
      }, 400);
    }

    return c.json({
      status: "ok",
      data: result,
      meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" },
    });
  } catch (e: unknown) {
    if (typeof e === "object" && e !== null && "getResponse" in e) {
      return (e as any).getResponse();
    }

    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, status);
  }
});

// Critical error handler per spec, pass through HTTPExceptions
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
