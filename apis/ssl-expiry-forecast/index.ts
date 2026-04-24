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
  forecastSslExpiry,
  SslExpiryForecastResult,
  SslExpiryForecastPreviewResult,
} from "./analyzer";

const app = new Hono();
const API_NAME = "ssl-expiry-forecast";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit tier
const PRICE_NUMERIC = 0.01;

// CORS middleware (open to all origins)
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before rate limit
app.get("/health", (c) => {
  return c.json({ status: "ok" });
});

// Rate limits: 15 per minute on /check (multiple external calls), 45 per minute global
app.use("/check", rateLimit("ssl-expiry-forecast-check", 15, 60_000));
app.use("*", rateLimit("ssl-expiry-forecast", 45, 60_000));

// Extract payer wallet (x402)
app.use("*", extractPayerWallet());

// API logger with price as number
app.use("*", apiLogger(API_NAME, PRICE_NUMERIC));

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
          description: "Free preview that checks basic SSL expiry and DNS info for provided domains",
          parameters: [
            {
              name: "domains",
              type: "string",
              description: "Comma-separated list of domain names to preview (max 5 domains)",
              required: true,
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              results: [
                {
                  domain: "example.com",
                  expiryDate: "2024-12-31T23:59:59Z",
                  expiryDays: 120,
                  dnsARecords: ["93.184.216.34"],
                  score: 80,
                  grade: "B",
                  recommendations: [
                    {
                      issue: "ExpirySoon",
                      severity: 60,
                      suggestion: "Renew SSL certificate within 3 months to avoid expiration."
                    }
                  ],
                  details: "SSL certificate expires in 120 days, DNS A record present.",
                },
              ],
            },
            meta: {
              timestamp: "2024-06-20T18:00:00Z",
              duration_ms: 500,
              api_version: "1.0.0"
            },
          },
        },
        {
          method: "GET",
          path: "/check",
          description: "Paid endpoint combining certificate transparency logs, DNS, SSL cert data to forecast expiry across multiple domains",
          parameters: [
            {
              name: "domains",
              type: "string",
              description: "Comma-separated list of domain names to check (max 10 domains).",
              required: true,
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              results: [
                {
                  domain: "example.com",
                  expiryDate: "2024-12-31T23:59:59Z",
                  expiryDays: 120,
                  dnsARecords: ["93.184.216.34"],
                  certTransparencyEntries: 25,
                  ctFirstSeen: "2023-01-01T00:00:00Z",
                  ctLastSeen: "2024-05-01T00:00:00Z",
                  score: 90,
                  grade: "A",
                  recommendations: [
                    {
                      issue: "MonitorCT",
                      severity: 30,
                      suggestion: "Regularly monitor certificate transparency logs for unauthorized certificates."
                    },
                    {
                      issue: "RenewalReminder",
                      severity: 60,
                      suggestion: "Plan renewal before expiry in 120 days."
                    }
                  ],
                  details: "Certificate transparency confirms consistent issuance and renewal history.",
                },
              ],
            },
            meta: {
              timestamp: "2024-06-20T18:01:00Z",
              duration_ms: 1800,
              api_version: "1.0.0"
            },
          },
        }
      ],
      parameters: [
        {
          name: "domains",
          type: "string",
          description: "Comma-separated list of domain names (max count depends on endpoint), all valid domain names.",
        }
      ],
      examples: [
        {
          description: "Preview SSL expiry forecast for example.com and google.com",
          request: "/preview?domains=example.com,google.com",
        },
        {
          description: "Full paid SSL expiry forecast for example.com",
          request: "/check?domains=example.com",
        }
      ]
    },
    pricing: {
      paidEndpoint: "/check",
      price: PRICE,
      pricingModel: "Comprehensive audit combining certificate transparency logs, DNS info, SSL cert details."
    }
  });
});

// Free preview endpoint
app.get(
  "/preview",
  rateLimit("ssl-expiry-forecast-preview", 25, 60_000),
  async (c) => {
    const raw = c.req.query("domains");
    if (!raw || typeof raw !== "string") {
      return c.json({ error: "Missing or invalid ?domains= parameter" }, 400);
    }

    // Max 5 domains for preview
    const domains = raw.split(",").map((d) => d.trim().toLowerCase()).filter((d) => d.length > 0);
    if (domains.length === 0 || domains.length > 5) {
      return c.json({ error: "Provide 1 to 5 domains comma-separated" }, 400);
    }

    // Validate domains
    for (const d of domains) {
      if (!/^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?:[A-Za-z]{2,63})$/.test(d)) {
        return c.json({ error: `Invalid domain format: ${d}` }, 400);
      }
    }

    const start = performance.now();
    try {
      const result = await forecastSslExpiry(domains, true);
      const duration_ms = Math.round(performance.now() - start);
      return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
    } catch (e: unknown) {
      // catch fetch or analysis error
      const msg = e instanceof Error ? e.message : String(e);
      const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
      return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
    }
  }
);

// Paid endpoints require spend cap and payment
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Forecast SSL expiry dates by combining SSL cert data, DNS info, and certificate transparency logs for multiple domains",
        {
          input: { domains: "example.com,example.net" },
          inputSchema: {
            type: "object",
            properties: {
              domains: {
                type: "string",
                description: "Comma-separated list of domain names to analyze",
                maxLength: 1024,
              },
            },
            required: ["domains"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid check endpoint
app.get("/check", async (c) => {
  const raw = c.req.query("domains");
  if (!raw || typeof raw !== "string") {
    return c.json({ error: "Missing or invalid ?domains= parameter" }, 400);
  }

  const domains = raw
    .split(",")
    .map((d) => d.trim().toLowerCase())
    .filter((d) => d.length > 0);

  if (domains.length === 0 || domains.length > 10) {
    return c.json({ error: "Provide 1 to 10 domains comma-separated" }, 400);
  }

  for (const d of domains) {
    if (!/^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?:[A-Za-z]{2,63})$/.test(d)) {
      return c.json({ error: `Invalid domain format: ${d}` }, 400);
    }
  }

  const start = performance.now();
  try {
    // Comprehensive full forecast
    const result = await forecastSslExpiry(domains, false);
    const duration_ms = Math.round(performance.now() - start);
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Error handler that passes through 402 from x402 and logs internal errors
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
