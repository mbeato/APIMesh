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
  PreviewResult,
  AnalysisResult,
  previewAnalysis,
  fullAnalysis,
} from "./analyzer";

const app = new Hono();
const API_NAME = "privacy-policy-drift";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // comprehensive audit level
const PRICE_NUM = 0.01;
const API_VERSION = "1.0.0";

// CORS middleware - open to all origins
app.use("*",
  cors({
    origin: "*",
    allowMethods: ["GET"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// Health endpoint - before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit: preview restricted more strictly as it is free, paid endpoints have wider limits
app.use("/check", rateLimit("privacy-policy-drift-check", 30, 60_000));
app.use("/preview", rateLimit("privacy-policy-drift-preview", 20, 60_000));
app.use("*", rateLimit("privacy-policy-drift", 90, 60_000));

// Extract payer wallet for payment tracking
app.use("*", extractPayerWallet());

// API logger with the chosen price level
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: API_VERSION,
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/preview",
          description: "Free preview to fetch a privacy policy snapshot and minimal NLP summary",
          parameters: [
            { name: "url", type: "string", description: "Target website URL to fetch privacy policy from. Must be http(s)://..." },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com/privacy",
              snapshotHash: "abcde12345",
              summary: "Privacy policy summary snippet",
              lastFetchedAt: "2024-06-01T12:00:00.000Z",
              driftDetected: false
            },
            meta: {
              timestamp: "2024-06-01T12:00:00.000Z",
              duration_ms: 140,
              api_version: API_VERSION,
            }
          },
        },
        {
          method: "GET",
          path: "/check",
          description: "Factory-paid comprehensive privacy policy analysis, NLP drift detection, compliance scoring and remediation",
          parameters: [
            { name: "url", type: "string", description: "Target website URL to fetch privacy policies from." }
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com/privacy",
              snapshotHash: "abcde12345",
              driftScore: 15,
              complianceScore: 85,
              grade: "B",
              lastFetchedAt: "2024-06-01T12:00:00.000Z",
              recommendations: [
                { issue: "No explicit user data deletion clause", severity: 50, suggestion: "Add a user data deletion policy section as required by GDPR." },
                { issue: "Tracking cookies not disclosed", severity: 70, suggestion: "Disclose and obtain consent for all tracking cookies used." }
              ],
              details: "The analysis includes multi-source comparisons of current and prior polices, NLP-based drift detection, and compliance checks."
            },
            meta: {
              timestamp: "2024-06-01T12:00:00.000Z",
              duration_ms: 420,
              api_version: API_VERSION
            }
          }
        },
      ],
      parameters: [
        { name: "url", type: "string", description: "A valid http or https URL to a website hosting a privacy policy." }
      ],
      examples: [
        {
          description: "Basic preview call",
          request: "/preview?url=https://example.com/privacy",
          response: {/* see above preview example */}
        },
        {
          description: "Paid full analysis",
          request: "/check?url=https://example.com/privacy",
          response: {/* see above check example */}
        }
      ]
    },
    pricing: {
      preview: "Free",
      paid: PRICE,
      description: "$0.01 per call for comprehensive privacy policy audit with NLP and drift detection"
    }
  });
});

// Free preview endpoint - open requests with 20s timeout
app.get("/preview", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing ?url= parameter with http(s):// URL" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  // Validate the URL - disallow certain private/internal URLs
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) {
    return c.json({ error: `Invalid URL: ${check.error}` }, 400);
  }

  const start = performance.now();
  try {
    const result: PreviewResult = await previewAnalysis(check.url.toString());
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: result,
      meta: { timestamp: new Date().toISOString(), duration_ms, api_version: API_VERSION },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ status: "error", error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: API_VERSION } }, status);
  }
});

// Payment middleware
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Fetches, caches, and comprehensively analyzes privacy policies using multi-source data and NLP drift detection for compliance scoring and recommendations",
        {
          input: { url: "https://example.com/privacy" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "Target website URL with privacy policy" },
            },
            required: ["url"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid comprehensive check
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing ?url= parameter with http(s):// URL" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  // Validate the URL
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) {
    return c.json({ error: `Invalid URL: ${check.error}` }, 400);
  }

  const start = performance.now();
  try {
    const result: AnalysisResult = await fullAnalysis(check.url.toString());
    const duration_ms = Math.round(performance.now() - start);

    // If error returned by analyzer with no data, return 400 error
    if ("error" in result && !(result as any).url) {
      return c.json({ status: "error", error: result.error, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: API_VERSION } }, 400);
    }

    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: API_VERSION } });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ status: "error", error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: API_VERSION } }, status);
  }
});

// On error handler with pass-through for HTTPException 402 from payment gate
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
