import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl } from "../../shared/ssrf";
import { analyzeSubdomainResilience, SubdomainResilienceResult, analyzeSubdomainResiliencePreview } from "./analyzer";

const app = new Hono();
const API_NAME = "subdomain-resilience-score";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUM = 0.01;

// 1. CORS middleware open to all origins, only GET allowed
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// 2. Health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limits setup
app.use("/check", rateLimit("subdomain-resilience-score-check", 10, 60_000));
app.use("*", rateLimit("subdomain-resilience-score", 30, 60_000));

// 4. Extract payer wallet middleware
app.use("*", extractPayerWallet());

// 5. API logger middleware logs revenue at set price
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
          path: "/check",
          description: "Perform comprehensive subdomain resilience scoring for a given domain",
          parameters: [
            {
              name: "domain",
              type: "string",
              description: "The registered domain name to analyze (e.g. example.com)",
              required: true
            }
          ],
          exampleRequest: "/check?domain=example.com",
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              subdomains_found: 50,
              resilienceScore: 88.7,
              grade: "B",
              details: "Subdomain enumeration using DNS and certificate transparency logs found 50 subdomains; 12 had DNS configuration issues; 5 used outdated protocols; 3 exposed suspicious endpoints.",
              recommendations: [
                { issue: "DNS misconfiguration", severity: 70, suggestion: "Fix DNS entries for subdomains with missing or invalid records." },
                { issue: "Deprecated protocols", severity: 60, suggestion: "Disable old SSL/TLS versions and migrate endpoints to modern protocols." },
                { issue: "Exposed sensitive endpoint", severity: 90, suggestion: "Restrict access or remove sensitive endpoints exposed on public subdomains." }
              ]
            },
            meta: {
              timestamp: "2024-06-01T12:00:00Z",
              duration_ms: 1580,
              api_version: "1.0.0"
            }
          }
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview endpoint with limited subdomain enumeration and basic scoring",
          parameters: [
            {
              name: "domain",
              type: "string",
              description: "The registered domain to preview",
              required: true
            }
          ],
          exampleRequest: "/preview?domain=example.com",
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              subdomains_found: 10,
              sample_subdomains: ["www.example.com", "mail.example.com"],
              resilienceScore: 80,
              grade: "B",
              details: "Basic enumeration from DNS returned 10 subdomains. Limited analysis shows no critical issues detected.",
              recommendations: [
                { issue: "Limited scan", severity: 20, suggestion: "Run full scan by paying to detect deeper issues." }
              ]
            },
            meta: {
              timestamp: "2024-06-01T12:00:00Z",
              duration_ms: 320,
              api_version: "1.0.0"
            },
            note: "Preview results are limited; full scan available with payment."
          }
        }
      ],
      parameters: [
        {
          name: "domain",
          description: "A registered domain (e.g., example.com) without scheme or path.",
          type: "string"
        }
      ],
      examples: [
        "GET /check?domain=example.com",
        "GET /preview?domain=example.com"
      ]
    },
    pricing: {
      price: PRICE,
      description: "Comprehensive audit with 5+ checks including DNS enumeration, certificate transparency, protocol analysis, exposure detection, scoring, and detailed remediation."
    }
  });
});

// 7. Free preview endpoint before payment middleware
app.get("/preview", rateLimit("subdomain-resilience-score-preview", 15, 120_000), async (c) => {
  const domain = c.req.query("domain");
  if (!domain || typeof domain !== "string") {
    return c.json({ error: "Missing or invalid ?domain= parameter" }, 400);
  }
  if (domain.length > 253) {
    return c.json({ error: "Domain parameter exceeds maximum length" }, 400);
  }

  try {
    const start = performance.now();
    const result = await analyzeSubdomainResiliencePreview(domain.trim());
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0"
      },
      note: "Preview results are limited; pay for full comprehensive audit with detailed analysis and scoring."
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 8. Spend cap middleware
app.use("*", spendCapMiddleware());

// 9. Payment middleware + paid route with discovery
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Performs exhaustive subdomain enumeration via free DNS and certificate transparency logs, analyzing DNS misconfigurations, outdated protocols, and exposure of sensitive endpoints with scoring and detailed report",
        {
          input: { domain: "example.com" },
          inputSchema: {
            properties: {
              domain: { type: "string", description: "Registered domain name without scheme" }
            },
            required: ["domain"]
          }
        }
      ),
    },
    resourceServer
  )
);

// Paid endpoint
app.get("/check", async (c) => {
  const domain = c.req.query("domain");
  if (!domain || typeof domain !== "string") {
    return c.json({ error: "Missing or invalid ?domain= parameter" }, 400);
  }
  if (domain.length > 253) {
    return c.json({ error: "Domain parameter exceeds maximum length" }, 400);
  }

  try {
    const start = performance.now();
    const result: SubdomainResilienceResult = await analyzeSubdomainResilience(domain.trim());
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0"
      }
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 10. Error handler; pass through HTTPExceptions for 402s
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
