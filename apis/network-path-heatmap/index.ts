import { Hono } from "hono";
import { cors } from "hono/cors";
import {
  paymentMiddleware,
  paidRouteWithDiscovery,
  resourceServer,
} from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { safeFetch, validateExternalUrl } from "../../shared/ssrf";
import {
  fullAnalysis,
  previewAnalysis,
  NetworkPathHeatmapResult,
  NetworkPathHeatmapPreview,
} from "./analyzer";

const app = new Hono();
const API_NAME = "network-path-heatmap";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit (5+ checks, scoring, detailed report)
const PRICE_NUM = 0.01;

// CORS open to all origins
app.use("*",
  cors({
    origin: "*",
    allowMethods: ["GET"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// Health endpoint (before rate limiter)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit: 15/min on /preview, 15/min on /analyze, global 45/min
app.use("/preview", rateLimit("network-path-heatmap-preview", 15, 60_000));
app.use("/analyze", rateLimit("network-path-heatmap-analyze", 15, 60_000));
app.use("*", rateLimit("network-path-heatmap", 45, 60_000));

app.use("*", extractPayerWallet());
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
          description:
            "Free preview: infer basic network path and geolocation info for an IP address.",
          parameters: [
            { name: "ip", type: "string", description: "Target IPv4 or IPv6 address" },
          ],
          exampleResponse: {
            status: "ok",
            data: {},
            meta: {},
          },
        },
        {
          method: "GET",
          path: "/analyze",
          description:
            "Paid endpoint: deep analysis of network path, ASN hops, geolocation maps, scoring, and recommendations.",
          parameters: [
            { name: "ip", type: "string", description: "Target IPv4 or IPv6 address" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              ip: "8.8.8.8",
              asnPath: [],
              geolocations: [],
              score: 85,
              grade: "B",
              recommendations: [],
              explanation: "Detailed explanation text",
            },
            meta: {},
          },
        },
      ],
      parameters: [
        { name: "ip", type: "string", description: "Target IP address to analyze" },
      ],
      examples: [
        {
          description: "Preview for 8.8.8.8",
          request: "/preview?ip=8.8.8.8",
        },
        {
          description: "Full analysis for 8.8.8.8",
          request: "/analyze?ip=8.8.8.8",
        },
      ],
    },
    pricing: {
      preview: "Free",
      analyze: PRICE,
      note: "Pricing based on comprehensive audit of network path, ASN hops, and geolocation",
    },
  });
});

// Free preview endpoint
app.get("/preview", async (c) => {
  const rawIp = c.req.query("ip");
  if (!rawIp || typeof rawIp !== "string") {
    return c.json({ error: "Missing ?ip= parameter." }, 400);
  }
  if (rawIp.length > 45) {
    return c.json({ error: "IP parameter length invalid." }, 400);
  }

  // Validate IP format
  const ipv4Regex = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;
  const ipv6Regex = /^([\da-f]{1,4}:){7}[\da-f]{1,4}$/i;
  if (!ipv4Regex.test(rawIp) && !ipv6Regex.test(rawIp)) {
    return c.json({ error: "Invalid IP address format." }, 400);
  }

  try {
    const start = performance.now();
    const previewResult: NetworkPathHeatmapPreview = await previewAnalysis(rawIp);
    const duration_ms = Math.round(performance.now() - start);

    return c.json({
      status: "ok",
      data: previewResult,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0",
      },
      note: "Free preview provides basic routing and geolocation info. Full paid analysis available via /analyze with scoring and recommendations.",
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Payment & spend cap middleware
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /analyze": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive audit: infer and visualize network routing paths, ASN hops, geolocation, scoring, and detailed report.",
        {
          input: { ip: "8.8.8.8" },
          inputSchema: {
            properties: {
              ip: { type: "string", description: "Target IPv4 or IPv6 address" },
            },
            required: ["ip"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid comprehensive analysis endpoint
app.get("/analyze", async (c) => {
  const rawIp = c.req.query("ip");
  if (!rawIp || typeof rawIp !== "string") {
    return c.json({ error: "Missing ?ip= parameter." }, 400);
  }
  if (rawIp.length > 45) {
    return c.json({ error: "IP parameter length invalid." }, 400);
  }

  // Validate IP format
  const ipv4Regex = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;
  const ipv6Regex = /^([\da-f]{1,4}:){7}[\da-f]{1,4}$/i;
  if (!ipv4Regex.test(rawIp) && !ipv6Regex.test(rawIp)) {
    return c.json({ error: "Invalid IP address format." }, 400);
  }

  try {
    const start = performance.now();
    const result: NetworkPathHeatmapResult = await fullAnalysis(rawIp);
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

// CRITICAL error handler — pass through HTTPExceptions for 402s
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
