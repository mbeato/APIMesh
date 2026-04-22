import { Hono } from "hono";
import { cors } from "hono/cors";
import {
  paymentMiddleware,
  paidRouteWithDiscovery,
  resourceServer
} from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl } from "../../shared/ssrf";
import {
  simulatePropagation,
  PropagationSimulationResult
} from "./simulator";

const app = new Hono();
const API_NAME = "dns-propagation-simulator";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // comprehensive audit pricing
const PRICE_NUM = 0.01;

// CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"]
}));

// Health endpoint (before rate limiting)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits
app.use("/simulate", rateLimit("dns-propagation-simulator-simulate", 10, 60_000));
app.use("*", rateLimit("dns-propagation-simulator", 30, 60_000));

// Extract payer wallet
app.use("*", extractPayerWallet());

// API logging with price
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
          path: "/simulate",
          description: "Simulate DNS record propagation across multiple DNS resolvers with delay estimation and misconfiguration detection.",
          parameters: [
            { name: "domain", type: "string", required: true, description: "Domain name to check (e.g. example.com)" },
            { name: "recordType", type: "string", required: false, description: "DNS record type to query (A, AAAA, CNAME, TXT, etc.). Defaults to A." }
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              recordType: "A",
              resolvedRecords: ["93.184.216.34"],
              resolverDetails: [],
              propagationScore: 87,
              grade: "B",
              recommendations: [
                {
                  issue: "Partial propagation delay",
                  severity: 60,
                  suggestion: "Wait up to 24 hours for full DNS propagation or verify TTL settings with your DNS provider."
                }
              ],
              details: "Most global DNS resolvers have updated the record within the last hour. Some variation exists likely due to TTL caching."
            },
            meta: { timestamp: "2024-01-01T00:00:00Z", duration_ms: 140, api_version: "1.0.0" }
          }
        }
      ],
      parameters: [
        {
          name: "domain",
          type: "string",
          required: true,
          description: "Domain name to simulate DNS propagation on."
        },
        {
          name: "recordType",
          type: "string",
          required: false,
          description: "Type of DNS record to query (e.g. A, AAAA, CNAME, TXT). Defaults to A."
        }
      ],
      examples: [
        {
          description: "Simulate A record propagation for example.com",
          request: "/simulate?domain=example.com&recordType=A",
          response: "Refer to exampleResponse above"
        }
      ]
    },
    pricing: {
      paidCall: PRICE,
      paymentProtocols: ["x402", "MPP"]
    },
  });
});

// Free preview endpoint (limited, no payment required, longer timeout, fewer checks)
app.get("/preview", rateLimit("dns-propagation-simulator-preview", 20, 60_000), async (c) => {
  const domain = c.req.query("domain");
  if (!domain || typeof domain !== "string") {
    return c.json({ error: "Provide ?domain= parameter with a valid domain name" }, 400);
  }
  const recordType = typeof c.req.query("recordType") === "string" ? c.req.query("recordType")!.toUpperCase() : "A";

  if (domain.length > 253) {
    return c.json({ error: "Domain name exceeds maximum length" }, 400);
  }

  try {
    // Preview uses simple quick simulation with standard DNS resolvers, fast but less detail
    const start = performance.now();
    const result = await simulatePropagation(domain.trim(), recordType, { previewMode: true });
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({
      status: "ok",
      data: {
        ...result,
        preview: true,
        note: "Preview provides quick insights with less detail and fewer resolvers. Full simulation available via paid /simulate endpoint."
      },
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0"
      }
    });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Receive payment and enforce spend cap
app.use("*", spendCapMiddleware());

app.use(
  paymentMiddleware(
    {
      "GET /simulate": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive DNS propagation simulation with multi-resolver queries, propagation scoring, grade, and detailed recommendations.",
        {
          input: { domain: "example.com", recordType: "A" },
          inputSchema: {
            properties: {
              domain: { type: "string", description: "Domain name to query" },
              recordType: { type: "string", description: "DNS record type (A, AAAA, CNAME, TXT, etc.)", default: "A" }
            },
            required: ["domain"]
          }
        }
      )
    },
    resourceServer
  )
);

// Paid full simulation endpoint
app.get("/simulate", async (c) => {
  const domainRaw = c.req.query("domain");
  if (!domainRaw || typeof domainRaw !== "string") {
    return c.json({ error: "Provide ?domain= parameter with a valid domain name" }, 400);
  }
  const recordType = typeof c.req.query("recordType") === "string" ? c.req.query("recordType")!.toUpperCase() : "A";

  if (domainRaw.length > 253) {
    return c.json({ error: "Domain name exceeds maximum length" }, 400);
  }

  try {
    const start = performance.now();
    const result = await simulatePropagation(domainRaw.trim(), recordType, { previewMode: false });
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
        api_version: "1.0.0"
      }
    });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// CRITICAL error handler - pass through HTTPException for 402s
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
  fetch: app.fetch
};
