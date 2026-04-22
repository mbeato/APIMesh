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
import { fullAudit, previewAudit, type FullAuditResult, type PreviewResult } from "./analyzer";

const app = new Hono();
const API_NAME = "security-headers-checker";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUM = 0.01;

// 1. CORS middleware open to all origins
app.use("*",
  cors({
    origin: "*",
    allowMethods: ["GET"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// 2. Health check BEFORE rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limits
// For preview: 15 per min per IP
app.use("/preview", rateLimit("security-headers-checker-preview", 15, 60_000));
// For check: 30 per min per payer
app.use("/check", rateLimit("security-headers-checker-check", 30, 60_000));
// Global limit 90 per min
app.use("*", rateLimit("security-headers-checker", 90, 60_000));

// 4. Extract payer wallet
app.use("*", extractPayerWallet());

// 5. API Logger with price for paid route
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
          description: "Perform a comprehensive security headers audit with detailed scoring and remediation",
          parameters: [
            { name: "url", type: "string", required: true, description: "Full URL starting with http(s)://" }
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              headers: [
                {
                  header: "Strict-Transport-Security",
                  present: true,
                  value: "max-age=31536000; includeSubDomains; preload",
                  rating: "A",
                  issues: []
                },
                {
                  header: "Content-Security-Policy",
                  present: true,
                  value: "default-src 'self'; script-src 'self'; style-src 'self'",
                  rating: "A",
                  issues: []
                },
                {
                  header: "X-Frame-Options",
                  present: true,
                  value: "DENY",
                  rating: "A",
                  issues: []
                },
                /* ... others ... */
              ],
              cspParsed: {"default-src": ["'self'"], "script-src": ["'self'"], "style-src": ["'self'"]},
              overallGrade: "A",
              remediation: ["Add missing headers..."],
              checkedAt: "2023-09-01T12:00:00.000Z"
            },
            meta: {
              timestamp: "2023-09-01T12:00:00.000Z",
              duration_ms: 120,
              api_version: "1.0.0"
            }
          }
        },
        {
          method: "GET",
          path: "/preview",
          description: "A faster, limited preview scan checking key headers",
          parameters: [
            { name: "url", type: "string", required: true, description: "Full URL starting with http(s)://" }
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              preview: true,
              headers: [
                { header: "Strict-Transport-Security", present: true, value: "max-age=31536000; includeSubDomains; preload", rating: "A", issues: [] },
                { header: "X-Frame-Options", present: true, value: "DENY", rating: "A", issues: [] },
                { header: "X-Content-Type-Options", present: true, value: "nosniff", rating: "A", issues: [] }
              ],
              overallGrade: "A",
              checkedAt: "2023-09-01T12:00:00.000Z",
              note: "Preview scans three key headers only. Full audit available via /check endpoint."
            },
            meta: {
              timestamp: "2023-09-01T12:00:00.000Z",
              duration_ms: 70,
              api_version: "1.0.0"
            }
          }
        }
      ],
      parameters: [
        { name: "url", type: "string", description: "The target URL to audit (must be a valid http or https URL)" }
      ],
      examples: [
        {
          description: "Full security headers audit",
          request: "/check?url=https://example.com"
        },
        {
          description: "Quick preview check",
          request: "/preview?url=https://example.com"
        }
      ]
    },
    pricing: {
      description: "Comprehensive audit with scoring and remediation",
      price: PRICE
    }
  });
});

// 7. Spend cap middleware
app.use("*", spendCapMiddleware());

// 8. Payment middleware for /check
app.use(
  "*",
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive HTTP security headers audit with detailed grading and actionable remediation",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "Full URL starting with http(s)://" },
            },
            required: ["url"],
          },
        }
      ),
    },
    resourceServer
  )
);

// 9. Paid /check route
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  try {
    const validated = validateExternalUrl(rawUrl.trim());
    if ("error" in validated) {
      return c.json({ error: validated.error }, 400);
    }
    const result = await fullAudit(validated.url.toString());
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    const start = performance.now();
    // duration computed internally in fullAudit is approximate; verify here, adjust meta on return
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms: duration_ms > 0 ? duration_ms : 1,
        api_version: "1.0.0"
      }
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 10. Free preview endpoint BEFORE paymentMiddleware
app.get("/preview", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  try {
    const validated = validateExternalUrl(rawUrl.trim());
    if ("error" in validated) {
      return c.json({ error: validated.error }, 400);
    }

    const start = performance.now();
    const result = await previewAudit(validated.url.toString());
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms: duration_ms > 0 ? duration_ms : 1,
        api_version: "1.0.0"
      },
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 11. Error handler - pass through HTTPExceptions from x402
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
