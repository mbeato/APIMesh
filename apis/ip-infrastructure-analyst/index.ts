import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { IPInfrastructureAnalysis, InfoEndpointResponse } from "./types";
import { analyzeIpInfrastructure } from "./analyzer";

const app = new Hono();
const API_NAME = "ip-infrastructure-analyst";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUMERIC = 0.01;

// CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits
app.use("/analyze", rateLimit("ip-infrastructure-analyst-analyze", 15, 60_000));
app.use("*", rateLimit("ip-infrastructure-analyst", 45, 60_000));

// Extract payer wallet (required by x402 system)
app.use("*", extractPayerWallet());

// Logger middleware with price as number
app.use("*", apiLogger(API_NAME, PRICE_NUMERIC));

// Info endpoint
app.get("/", (c) => {
  const info: InfoEndpointResponse = {
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/analyze",
          description: "Analyze an IP address for ASN, ISP, geolocation, and routing info; returns comprehensive report with scoring and recommendations.",
          parameters: [
            {
              name: "ip",
              type: "string",
              required: true,
              description: "IPv4 or IPv6 address to analyze",
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              inputIP: "8.8.8.8",
              isValidIp: true,
              asnInfo: {
                asn: 15169,
                name: "Google LLC",
                country: "US",
                description: null
              },
              ispInfo: {
                isp: "Google LLC",
                organization: "Google LLC",
                asn: 15169,
                queryIp: "8.8.8.8"
              },
              geoLocation: {
                country: "US",
                region: "California",
                city: "Mountain View",
                latitude: 37.4056,
                longitude: -122.0775,
                timezone: "America/Los_Angeles",
                postalCode: "94043"
              },
              routingInfo: {
                originAS: 15169,
                ASPath: [15169],
                prefixes: ["8.8.8.0/24"],
                peersCount: 300
              },
              score: 92,
              grade: "A",
              recommendations: [
                {
                  issue: "None detected",
                  severity: 1,
                  suggestion: "No significant issues detected."
                }
              ],
              details: "IP: 8.8.8.8 is valid. ASN: AS15169 (Google LLC) in US. ISP: Google LLC. Located in Mountain View, California, US. Routing prefix count: 1. Overall risk and confidence score is 92, grade A."
            },
            meta: {
              timestamp: "2024-01-01T00:00:00.000Z",
              duration_ms: 200,
              api_version: "1.0.0"
            }
          },
        },
      ],
      parameters: [
        {
          name: "ip",
          type: "string",
          description: "The IP address to analyze (IPv4 or IPv6)"
        }
      ],
      examples: [
        {
          name: "Basic IP Analysis",
          description: "Analyze Google's public DNS IP",
          request: "/analyze?ip=8.8.8.8",
          response: {
            status: "ok",
            data: {
              inputIP: "8.8.8.8",
              isValidIp: true,
              asnInfo: {
                asn: 15169,
                name: "Google LLC",
                country: "US",
                description: null
              },
              ispInfo: {
                isp: "Google LLC",
                organization: "Google LLC",
                asn: 15169,
                queryIp: "8.8.8.8"
              },
              geoLocation: {
                country: "US",
                region: "California",
                city: "Mountain View",
                latitude: 37.4056,
                longitude: -122.0775,
                timezone: "America/Los_Angeles",
                postalCode: "94043"
              },
              routingInfo: {
                originAS: 15169,
                ASPath: [15169],
                prefixes: ["8.8.8.0/24"],
                peersCount: 300
              },
              score: 92,
              grade: "A",
              recommendations: [],
              details: "IP: 8.8.8.8 is valid. ASN: AS15169 (Google LLC) in US. ISP: Google LLC. Located in Mountain View, California, US. Routing prefix count: 1. Overall risk and confidence score is 92, grade A."
            },
            meta: {
              timestamp: "2024-01-01T00:00:00.000Z",
              duration_ms: 210,
              api_version: "1.0.0"
            }
          }
        }
      ]
    },
    pricing: {
      pricePerCall: PRICE,
      notes: "This API performs a comprehensive audit including multiple data sources, scoring, and actionable recommendations.",
    },
  };
  return c.json(info);
});

// Free preview endpoint
app.get("/preview", rateLimit("ip-infrastructure-analyst-preview", 20, 60_000), async (c) => {
  const ip = c.req.query("ip");
  if (!ip || typeof ip !== "string" || ip.trim().length === 0) {
    return c.json({ error: "Missing ?ip= parameter (IPv4 or IPv6)" }, 400);
  }

  if (ip.length > 45) { // IPv6 max length
    return c.json({ error: "IP address exceeds maximum length" }, 400);
  }

  try {
    // Basic validation only
    const isValidIp = (() => {
      const v = ip.trim();
      return /^[0-9a-fA-F:.]+$/.test(v) && v.length <= 45; // crude
    })();

    if (!isValidIp) {
      return c.json({
        status: "error",
        error: "Invalid IP format",
        detail: "IP address does not appear to be valid IPv4 or IPv6",
        meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" },
      }, 400);
    }

    // Minimal static preview response
    const start = performance.now();
    const data = {
      inputIP: ip.trim(),
      isValidIp: true,
      asnInfo: {
        asn: null,
        name: null,
        country: null,
        description: null,
      },
      ispInfo: {
        isp: null,
        organization: null,
        asn: null,
        queryIp: ip.trim(),
      },
      geoLocation: {
        country: null,
        region: null,
        city: null,
        latitude: null,
        longitude: null,
        timezone: null,
        postalCode: null,
      },
      routingInfo: {
        originAS: null,
        ASPath: [],
        prefixes: [],
      },
      score: 10,
      grade: "F",
      recommendations: [
        {
          issue: "This is a preview result.",
          severity: 1,
          suggestion: "Pay via x402 or MPP to get full analysis including ASN, ISP, geolocation, routing info, scoring, and recommendations.",
        },
      ],
      details: "Preview only: no external data fetched. Full results require payment.",
    } as IPInfrastructureAnalysis;
    const duration_ms = Math.round(performance.now() - start);

    return c.json({ status: "ok", data, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Spend cap middleware
app.use("*", spendCapMiddleware());

// Payment middleware with paid route config
app.use(
  paymentMiddleware(
    {
      "GET /analyze": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive IP infrastructure analysis combining ASN, ISP, geolocation, routing info, scoring, and recommendations",
        {
          input: { ip: "8.8.8.8" },
          inputSchema: {
            properties: {
              ip: { type: "string", description: "IPv4 or IPv6 address to analyze" },
            },
            required: ["ip"],
          },
        },
      ),
    },
    resourceServer,
  ),
);

// Paid analyze endpoint
app.get("/analyze", async (c) => {
  const ip = c.req.query("ip");
  if (!ip || typeof ip !== "string" || ip.trim().length === 0) {
    return c.json({ error: "Missing ?ip= parameter (IPv4 or IPv6)" }, 400);
  }
  if (ip.length > 45) {
    return c.json({ error: "IP address exceeds maximum length" }, 400);
  }

  try {
    const start = performance.now();
    const result = await analyzeIpInfrastructure(ip.trim());
    const duration_ms = Math.round(performance.now() - start);
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Error handler with pass-through for HTTPException 402 (x402 internal)
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
