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
  analyzeNetworkRoute,
  previewNetworkRoute,
  NetworkRouteResult,
  NetworkRoutePreviewResult,
} from "./analyzer";

const app = new Hono();
const API_NAME = "network-route-mapper";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit price, justified by 5+ checks and scoring
const PRICE_NUM = 0.01;

// CORS open to all origins and allow GET with payment headers
app.use("*",
  cors({
    origin: "*",
    allowMethods: ["GET"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// 1) Health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// 2) Rate limiting: strict on paid check endpoint and lighter on preview
app.use(
  "/route",
  rateLimit("network-route-mapper-route", 15, 60_000)
);
app.use("/preview", rateLimit("network-route-mapper-preview", 20, 60_000));
app.use("*", rateLimit("network-route-mapper", 60, 60_000));

// 3) Extract payer wallet
app.use("*", extractPayerWallet());

// 4) API logger with numeric price for paid routes
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// 5) Info endpoint - after rate limits and logger
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
          description:
            "Free preview of inferred network route info for an IP or domain with limited detail.",
          parameters: [
            {
              name: "target",
              in: "query",
              required: true,
              description: "Target IP address or domain name to analyze",
              schema: { type: "string" },
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              target: "8.8.8.8",
              detectedIp: "8.8.8.8",
              asnHops: [{ asn: 15169, name: "Google LLC", country: "US" }],
              geolocation: { country: "US", city: "Mountain View" },
              summaryScore: 85,
              grade: "B",
              details: "Route well known, no suspicious hops.",
              recommendations: [
                {
                  issue: "Peering inequality",
                  severity: 40,
                  suggestion:
                    "Consider multi-homing the network to improve route diversity.",
                },
              ],
            },
            meta: { timestamp: "2023-08-21T10:00:00Z", duration_ms: 150, api_version: "1.0.0" },
          },
        },
        {
          method: "GET",
          path: "/route",
          description:
            "Paid comprehensive analysis of network routing paths including ASN hops, geolocation, latency, suspicion scoring, and remediation.",
          parameters: [
            {
              name: "target",
              in: "query",
              required: true,
              description: "Target IP address or domain name to analyze",
              schema: { type: "string" },
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              target: "8.8.8.8",
              detectedIp: "8.8.8.8",
              asnHops: [
                {
                  asn: 15169,
                  name: "Google LLC",
                  country: "US",
                  latencyMs: 20,
                  suspicious: false,
                },
                {
                  asn: 3356,
                  name: "Level 3 Communications",
                  country: "US",
                  latencyMs: 15,
                  suspicious: false,
                },
              ],
              geolocation: { country: "US", region: "California", city: "Mountain View" },
              summaryScore: 92,
              grade: "A",
              details: "Route appears stable; latency within expected range; no suspicious ASNs detected.",
              recommendations: [],
            },
            meta: { timestamp: "2023-08-21T10:05:00Z", duration_ms: 800, api_version: "1.0.0" },
          },
        },
      ],
      parameters: [
        {
          name: "target",
          type: "string",
          description: "An IP address (IPv4 or IPv6) or domain name to analyze network routing information",
          required: true,
        },
      ],
      examples: [
        {
          name: "Basic preview",
          method: "GET",
          path: "/preview?target=8.8.8.8",
        },
        {
          name: "Paid full route analysis",
          method: "GET",
          path: "/route?target=1.1.1.1",
        },
      ],
    },
    pricing: {
      preview: "Free",
      fullRouteAnalysis: PRICE,
    },
  });
});

// 6) Free preview endpoint before paymentMiddleware
// Longer timeout 20s for preview
app.get("/preview", async (c) => {
  const rawTarget = c.req.query("target");
  if (!rawTarget || typeof rawTarget !== "string") {
    return c.json({ error: "Missing ?target= parameter (IP address or domain)" }, 400);
  }

  if (rawTarget.length > 255) {
    return c.json({ error: "Target parameter too long" }, 400);
  }

  try {
    // Using extended timeout 20_000 ms
    const result = await previewNetworkRoute(rawTarget.trim());
    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms: 0,
        api_version: "1.0.0",
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 7) Spend cap middleware
app.use("*", spendCapMiddleware());

// 8) Payment middleware for paid route
app.use(
  paymentMiddleware(
    {
      "GET /route": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive network route mapping and analysis: ASN hops, geolocation, latency, scoring, and actionable recommendations",
        {
          input: { target: "8.8.8.8" },
          inputSchema: {
            properties: {
              target: {
                type: "string",
                description: "An IP address (v4/v6) or domain name for network route analysis",
              },
            },
            required: ["target"],
          },
        }
      ),
    },
    resourceServer
  )
);

// 9) Paid route handler
app.get("/route", async (c) => {
  const rawTarget = c.req.query("target");
  if (!rawTarget || typeof rawTarget !== "string") {
    return c.json({ error: "Missing ?target= parameter (IP or domain)" }, 400);
  }

  if (rawTarget.length > 255) {
    return c.json({ error: "Target parameter too long" }, 400);
  }

  const start = performance.now();
  try {
    const data = await analyzeNetworkRoute(rawTarget.trim());
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data,
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

// 10) Error handler, must pass through HTTPExceptions (e.g. for 402 from x402)
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
