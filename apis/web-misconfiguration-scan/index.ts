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
  analyzeMisconfiguration,
  previewMisconfiguration,
} from "./analyzer";

const app = new Hono();
const API_NAME = "web-misconfiguration-scan";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUM = 0.01;

// Open CORS to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit: 10/minute on /scan, 30/minute global
app.use("/scan", rateLimit("web-misconfiguration-scan-scan", 10, 60_000));
app.use("*", rateLimit("web-misconfiguration-scan", 30, 60_000));

// Extract payer wallet before logging
app.use("*", extractPayerWallet());

// Log api usage with price number
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
          path: "/scan",
          description: "Run a comprehensive security misconfiguration scan against the specified URL",
          parameters: [
            { name: "url", type: "string", description: "Target URL to scan (http or https)" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              riskScore: 65,
              grade: "C",
              checks: [
                {
                  name: "Security Headers",
                  score: 80,
                  severity: "Medium",
                  details: "Most security headers are present but CSP is missing.",
                },
                {
                  name: "Environment Disclosure",
                  score: 50,
                  severity: "High",
                  details: "Server reveals backend version in 'Server' header.",
                },
                {
                  name: "File Presence",
                  score: 60,
                  severity: "Medium",
                  details: "/.git directory accessible.",
                },
                {
                  name: "Common Vulnerabilities",
                  score: 70,
                  severity: "Medium",
                  details: "X-XSS-Protection header missing, increasing risk of XSS attacks.",
                },
                {
                  name: "Open Ports",
                  score: 100,
                  severity: "Low",
                  details: "No open unnecessary ports detected.",
                },
              ],
              recommendations: [
                {
                  issue: "Missing Content-Security-Policy header",
                  severity: "High",
                  suggestion: "Add a robust CSP header to mitigate XSS attacks.",
                },
                {
                  issue: "Server header reveals backend version",
                  severity: "High",
                  suggestion: "Remove or obfuscate the Server header to prevent information leakage.",
                },
                {
                  issue: "Accessible /.git directory",
                  severity: "Medium",
                  suggestion: "Restrict access to .git and other sensitive directories.",
                },
                {
                  issue: "Missing X-XSS-Protection header",
                  severity: "Medium",
                  suggestion: "Add X-XSS-Protection header to enable built-in browser XSS filters.",
                },
                {
                  issue: "Regularly scan and patch the server to reduce vulnerabilities.",
                  severity: "Medium",
                  suggestion: "Keep all software up to date and apply security patches promptly.",
                }
              ],
              scannedAt: "2024-06-14T12:34:56.789Z"
            },
            meta: {
              timestamp: "2024-06-14T12:34:56.789Z",
              duration_ms: 1500,
              api_version: "1.0.0"
            }
          },
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview scan on limited checks (headers only, quick)",
          parameters: [
            { name: "url", type: "string", description: "Target URL to scan (http or https)" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              headerChecks: [
                {
                  name: "Strict-Transport-Security",
                  present: true,
                  value: "max-age=31536000; includeSubDomains; preload",
                  rating: "A",
                  issues: []
                },
                {
                  name: "X-Content-Type-Options",
                  present: true,
                  value: "nosniff",
                  rating: "A",
                  issues: []
                }
              ],
              riskScore: 70,
              grade: "B",
              scannedAt: "2024-06-14T12:30:00.000Z",
              note: "Preview scans only headers with limited depth. Full scan requires payment."
            },
            meta: {
              timestamp: "2024-06-14T12:30:00.000Z",
              duration_ms: 300,
              api_version: "1.0.0"
            }
          },
        },
      ],
      parameters: [
        { name: "url", type: "string", description: "URL to analyze. Must be http or https." }
      ],
      examples: [
        "GET /scan?url=https://example.com",
        "GET /preview?url=https://example.com"
      ],
    },
    pricing: {
      scan: PRICE,
      preview: "$0 (free, limited checks)"
    },
  });
});

// Free preview endpoint with extended timeout 15s
app.get("/preview", rateLimit("web-misconfiguration-scan-preview", 15, 60_000), async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing or invalid ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const check = validateExternalUrl(rawUrl.trim());
  if ("error" in check) {
    return c.json({ error: check.error }, 400);
  }

  try {
    const start = performance.now();
    const result = await previewMisconfiguration(check.url.toString());
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: result,
      meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" },
    });
  } catch (e: unknown) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Apply spend cap middleware before payment
app.use("*", spendCapMiddleware());

app.use(
  paymentMiddleware(
    {
      "GET /scan": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive security misconfiguration scan combining headers, environment, file presence, vulnerabilities, risk scoring, and remediation",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "URL to scan for security misconfigurations" },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer
  )
);

// Paid scan endpoint
app.get("/scan", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing or invalid ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const check = validateExternalUrl(rawUrl.trim());
  if ("error" in check) {
    return c.json({ error: check.error }, 400);
  }

  try {
    const start = performance.now();
    const result = await analyzeMisconfiguration(check.url.toString());
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: result,
      meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" },
    });
  } catch (e: unknown) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} scan error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Pass-through error handler with special handling for HTTPException
app.onError((err, c) => {
  if (typeof err === "object" && err !== null && "getResponse" in err) {
    return (err as any).getResponse();
  }
  console.error(`[${new Date().toISOString()}] ${API_NAME} uncaught error:`, err);
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
