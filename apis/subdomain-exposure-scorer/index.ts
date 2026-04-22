import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { enumerateAndScoreSubdomains, previewEnumerateAndScore } from "./scorer";

const app = new Hono();
const API_NAME = "subdomain-exposure-scorer";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUM = 0.01;

// 1. CORS open to all
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"]
}));

// 2. Health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limiting
app.use("/check", rateLimit("subdomain-exposure-scorer-check", 15, 60_000)); // deep checks are expensive
app.use("*", rateLimit("subdomain-exposure-scorer-global", 45, 60_000));

// 4. extractPayerWallet
app.use("*", extractPayerWallet());

// 5. apiLogger
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// 6. Info endpoint
app.get("/", (c) =>
  c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/preview",
          description: "Free preview enumeration of subdomains with exposure sampling (truncated, limited scan)",
          parameters: [
            { name: "domain", type: "string", required: true, description: "Base domain (e.g. example.com)" }
          ],
          example_response: {
            status: "ok",
            data: {
              domain: "example.com",
              subdomains: ["www.example.com", "mail.example.com"],
              exposureSummary: {
                sensitiveExposed: ["dev.example.com"],
                deprecatedApis: [],
                highRiskCount: 1,
                score: 70,
                grade: "B"
              },
              explanation: "Preview limited to 4-6 subdomains, exposure checks truncated.",
              recommendations: [
                { issue: "Sensitive subdomain exposed", severity: 3, suggestion: "Restrict or decommission dev.example.com" }
              ]
            },
            meta: {
              timestamp: "2024-04-23T02:58:19Z",
              duration_ms: 800,
              api_version: "1.0.0"
            }
          }
        },
        {
          method: "GET",
          path: "/check",
          description: "Comprehensive enumeration and exposure scoring of all detected subdomains for a domain.",
          parameters: [
            { name: "domain", type: "string", required: true, description: "Base domain, e.g. example.com" }
          ],
          example_response: {
            status: "ok",
            data: {
              domain: "example.com",
              subdomains: ["www.example.com", "mail.example.com", "dev.example.com", "beta.example.com"],
              exposureReport: {
                highRisk: ["admin.example.com", "beta.example.com"],
                deprecatedEndpoints: ["oldmail.example.com"],
                sensitiveSubdomains: ["admin.example.com"],
                scoring: { score: 55, grade: "C" },
                exposureBreakdown: {
                  highRiskCount: 2,
                  deprecatedCount: 1,
                  sensitiveCount: 1
                }
              },
              explanation: "Found 9 subdomains via DNS and CT logs. 2 subdomains have high-risk exposure (public admin/beta), 1 uses deprecated legacy system.",
              recommendations: [
                { issue: "Public admin subdomain", severity: 5, suggestion: "Restrict admin.example.com to internal IPs or remove from DNS." },
                { issue: "Deprecated subdomain", severity: 3, suggestion: "Migrate or decommission oldmail.example.com." }
              ]
            },
            meta: {
              timestamp: "2024-04-23T02:57:12Z",
              duration_ms: 2010,
              api_version: "1.0.0"
            }
          }
        }
      ],
      parameters: [
        { name: "domain", type: "string", description: "Domain to enumerate (example.com)" }
      ],
      examples: [
        { method: "GET", path: "/preview?domain=example.com" },
        { method: "GET", path: "/check?domain=example.com" }
      ]
    },
    pricing: { endpoint: "/check", price: PRICE, unit: "per run" },
    preview: "/preview (free, sample only)"
  })
);

// 7. spendCapMiddleware
app.use("*", spendCapMiddleware());

// 8. paymentMiddleware (only /check is paid)
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive subdomain enumeration (DNS + CT logs) with exposure/priority scoring and remediation suggestions",
        {
          input: { domain: "example.com" },
          inputSchema: {
            properties: {
              domain: { type: "string", description: "The domain to scan (example.com)" }
            },
            required: ["domain"]
          }
        }
      )
    },
    resourceServer
  )
);

// 9. /preview (free, safe, generous timeout)
app.get("/preview", rateLimit("subdomain-exposure-scorer-preview", 10, 60_000), async (c) => {
  const rawDomain = c.req.query("domain");
  if (!rawDomain) return c.json({ error: "Missing domain parameter (?domain=)" }, 400);
  if (rawDomain.length > 253) return c.json({ error: "Domain exceeds max length" }, 400);
  const start = performance.now();
  try {
    const result = await previewEnumerateAndScore(rawDomain.trim());
    if ("error" in result) {
      return c.json({
        status: "error",
        error: result.error,
        detail: result.detail || result.error,
        meta: {
          timestamp: new Date().toISOString(),
          duration_ms: Math.round(performance.now() - start),
          api_version: "1.0.0"
        }
      }, 400);
    }
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
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({
      status: "error",
      error: "Analysis temporarily unavailable",
      detail: msg,
      meta: { timestamp: new Date().toISOString(), duration_ms: Math.round(performance.now() - start), api_version: "1.0.0" }
    }, status);
  }
});

// 10. /check (paid, full audit)
app.get("/check", async (c) => {
  const rawDomain = c.req.query("domain");
  if (!rawDomain) return c.json({ error: "Missing domain parameter (?domain=)" }, 400);
  if (rawDomain.length > 253) return c.json({ error: "Domain exceeds max length" }, 400);
  const start = performance.now();
  try {
    const result = await enumerateAndScoreSubdomains(rawDomain.trim());
    if ("error" in result) {
      return c.json({
        status: "error",
        error: result.error,
        detail: result.detail || result.error,
        meta: {
          timestamp: new Date().toISOString(),
          duration_ms: Math.round(performance.now() - start),
          api_version: "1.0.0"
        }
      }, 400);
    }
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
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({
      status: "error",
      error: "Analysis temporarily unavailable",
      detail: msg,
      meta: { timestamp: new Date().toISOString(), duration_ms: Math.round(performance.now() - start), api_version: "1.0.0" }
    }, status);
  }
});

// 11. Error handler: let Hono's HTTPException (e.g. 402 from x402) pass through
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
