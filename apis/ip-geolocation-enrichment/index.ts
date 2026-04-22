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
import { safeFetch, validateExternalUrl } from "../../shared/ssrf";
import {
  EnrichmentResult,
  previewEnrichIp,
  fullEnrichIp,
} from "./enricher";

const app = new Hono();
const API_NAME = "ip-geolocation-enrichment";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit per specs
const PRICE_NUM = 0.01;
const API_VERSION = "1.0.0";

// CORS open to all origins
app.use("*",
  cors({
    origin: "*",
    allowMethods: ["GET"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// Health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit: low throttling for /enrich (paid), and global
app.use("/enrich", rateLimit("ip-geolocation-enrichment-enrich", 20, 60_000));
app.use("*", rateLimit("ip-geolocation-enrichment", 50, 60_000));

// Middleware chain: extract payer wallet, log API call with price
app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint before payments & caps
app.get("/", (c) => {
  const docs = {
    endpoints: [
      {
        method: "GET",
        path: "/enrich",
        description: "Enrich an IP address with detailed ASN, ISP, geolocation, and routing data.",
        parameters: [
          { name: "ip", type: "string", description: "IPv4 or IPv6 address to analyze", required: true },
        ],
        exampleResponse: {
          status: "ok",
          data: {
            ip: "8.8.8.8",
            asn: "AS15169",
            isp: "Google LLC",
            country: "United States",
            city: "Mountain View",
            latitude: 37.4056,
            longitude: -122.0775,
            routing: { prefix: "8.8.8.0/24", routeOrigin: "AS15169" },
            score: 95,
            grade: "A",
            details: "This IP is a well-known public DNS server by Google with stable routing and no suspicious history.",
            recommendations: [
              { issue: "None", severity: 0, suggestion: "No actions needed." }
            ]
          },
          meta: {
            timestamp: "2024-06-27T12:00:00Z",
            duration_ms: 145,
            api_version: "1.0.0"
          }
        }
      },
      {
        method: "GET",
        path: "/preview",
        description: "Preview endpoint: free limited info for an IP address; fast and reliable.",
        parameters: [
          { name: "ip", type: "string", description: "IPv4 or IPv6 address", required: true },
        ],
        exampleResponse: {
          status: "ok",
          data: {
            ip: "8.8.8.8",
            country: "United States",
            isp: "Google LLC",
            asn: "AS15169",
            checkedAt: "2024-06-27T12:00:00Z"
          },
          meta: {
            timestamp: "2024-06-27T12:00:00Z",
            duration_ms: 75,
            api_version: "1.0.0"
          }
        }
      }
    ],
    parameters: [
      { name: "ip", type: "string", description: "Target IP address (IPv4 or IPv6)" },
    ],
    examples: [
      { path: "/enrich?ip=8.8.8.8", description: "Full enrichment for Google's public DNS IPv4" },
      { path: "/preview?ip=8.8.8.8", description: "Quick preview info for Google's public DNS IPv4" }
    ]
  };

  const pricing = {
    endpoints: {
      "/enrich": PRICE,
      "/preview": "$0 (free)"
    },
    note: "Full enrich uses comprehensive audit pricing due to multiple free public data sources, scoring, and recommendations."
  };

  return c.json({ api: API_NAME, status: "healthy", version: API_VERSION, docs, pricing });
});

// Preview endpoint, free, reliable, 15s timeout
app.get("/preview", rateLimit("ip-geolocation-enrichment-preview", 30, 60_000), async (c) => {
  const ipRaw = c.req.query("ip");
  if (!ipRaw || typeof ipRaw !== "string") {
    return c.json({ error: "Missing required query parameter 'ip'" }, 400);
  }
  if (ipRaw.length > 45) { // max IPv6 length
    return c.json({ error: "IP address string too long" }, 400);
  }

  try {
    const start = performance.now();
    const result = await previewEnrichIp(ipRaw.trim(), AbortSignal.timeout(20_000));
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: API_VERSION,
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Spend cap middleware (after preview and info)
app.use("*", spendCapMiddleware());

// Payment middleware for /enrich only
app.use(
  paymentMiddleware(
    {
      "GET /enrich": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive enrichment of IP address with ASN, ISP, geolocation, routing, scoring, and recommendations",
        {
          input: { ip: "8.8.8.8" },
          inputSchema: {
            properties: {
              ip: { type: "string", description: "IPv4 or IPv6 address to enrich" },
            },
            required: ["ip"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid enrich endpoint
app.get("/enrich", async (c) => {
  const ipRaw = c.req.query("ip");
  if (!ipRaw || typeof ipRaw !== "string") {
    return c.json({ error: "Missing required query parameter 'ip'" }, 400);
  }
  if (ipRaw.length > 45) {
    return c.json({ error: "IP address string too long" }, 400);
  }

  try {
    const start = performance.now();
    const result = await fullEnrichIp(ipRaw.trim(), AbortSignal.timeout(10_000));
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: API_VERSION,
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
