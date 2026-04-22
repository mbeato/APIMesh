import { Hono } from "hono";
import { cors } from "hono/cors";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl, safeFetch } from "../../shared/ssrf";
import {
  analyzeContentShufflePreview,
  analyzeContentShuffleFull,
  PreviewResult,
  FullAnalysisResult,
} from "./analyzer";

const app = new Hono();
const API_NAME = "content-shuffle-detector";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // comprehensive audit with detailed scoring, 5+ checks
const PRICE_NUM = 0.01;

/*
Middleware order:
1. cors open to all origins
2. /health before rate limiting
3. rateLimit
4. extractPayerWallet
5. apiLogger
6. / info endpoint
7. spendCapMiddleware
8. paymentMiddleware
9. paid endpoints
10. onError
*/

// 1. CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// 2. Health endpoint (before any rate limit)
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limits
app.use("/check", rateLimit("content-shuffle-detector-check", 15, 60_000)); // 15 calls per minute on check due to 5 fetches
app.use("*", rateLimit("content-shuffle-detector", 45, 60_000)); // 45 calls per minute globally

// 4. Extract payer wallet
app.use("*", extractPayerWallet());

// 5. API Logger logs with numeric price
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// 6. Info endpoint - describe API, payment, usage
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
          description: "Free preview analysis of a URL's webpage content employing multiple fetches and NLP heuristics to detect content shuffling and obfuscation.",
          parameters: [{ name: "url", description: "The target URL (http(s)://...)" }],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              variationScore: 42.5,
              detectedObfuscations: ["captcha-injection"],
              grade: "C",
              recommendations: [
                { issue: "Dynamic content variation high", severity: 70, suggestion: "Investigate origins of content changes; consider caching or hardening." }
              ],
              explanation: "Preview scan found moderate content shuffle indicating possible unauthorized injection or obfuscation techniques.",
            },
            meta: {
              timestamp: "ISO8601 string",
              duration_ms: 3400,
              api_version: "1.0.0"
            }
          }
        },
        {
          method: "GET",
          path: "/check",
          description: "Paid comprehensive audit with multiple fetches, deep NLP content variation analysis, content diffing, and scoring. Returns detailed report, score (0-100), letter grade (A-F), and recommendations.",
          parameters: [{ name: "url", description: "The target URL (http(s)://...)" }],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              overallScore: 85,
              grade: "B",
              fetchCount: 7,
              detectedIssues: ["captcha-obfuscation", "content-injection"],
              recommendations: [
                { issue: "Frequent CAPTCHA detections", severity: 80, suggestion: "Implement CAPTCHA bypass handling or limit requests." },
                { issue: "Content injection risk", severity: 60, suggestion: "Audit scripts responsible for dynamic injections." }
              ],
              detailedReport: { /* complex structured object with diffs, NLP scores, fetch metadata */ },
              explanation: "Comprehensive multiple-fetch analysis detected suspicious content alterations consistent with unauthorized injections and CAPTCHAs.",
            },
            meta: { timestamp: "ISO8601 string", duration_ms: 8500, api_version: "1.0.0" }
          }
        }
      ],
      parameters: [
        { name: "url", type: "string", description: "A full URL starting with http:// or https:// to analyze." }
      ],
      examples: [
        { path: "/preview?url=https://example.com" },
        { path: "/check?url=https://example.com" }
      ]
    },
    pricing: { 
      preview: "$0 (free, limited checks)",
      "comprehensive-audit": PRICE,
      note: "Payment required via x402 or MPP for /check endpoint."
    },
  });
});

// 7. Spend cap middleware
app.use("*", spendCapMiddleware());

// 8. Payment middleware with paid route config
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive content integrity audit over multiple fetches with NLP-based dynamic content analysis and obfuscation detection",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            type: "object",
            properties: {
              url: { type: "string", description: "URL to analyze" },
            },
            required: ["url"],
          },
        }
      ),
    },
    resourceServer
  )
);

// 9. Free preview endpoint
app.get("/preview", rateLimit("content-shuffle-detector-preview", 10, 60_000), async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (provide a full http(s):// URL)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  // Validate URL externally
  const validation = validateExternalUrl(rawUrl.trim());
  if ("error" in validation) {
    return c.json({ error: validation.error }, 400);
  }
  const targetUrl = validation.url.toString();

  const start = performance.now();
  try {
    const result: PreviewResult = await analyzeContentShufflePreview(targetUrl);
    const duration_ms = Math.round(performance.now() - start);
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: unknown) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 9. Paid comprehensive check endpoint
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (provide a full http(s):// URL)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const validation = validateExternalUrl(rawUrl.trim());
  if ("error" in validation) {
    return c.json({ error: validation.error }, 400);
  }
  const targetUrl = validation.url.toString();

  const start = performance.now();
  try {
    const result: FullAnalysisResult = await analyzeContentShuffleFull(targetUrl);
    const duration_ms = Math.round(performance.now() - start);
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: unknown) {
    if (typeof e === "object" && e !== null && "getResponse" in e) {
      return (e as any).getResponse();
    }
    console.error(`[${new Date().toISOString()}] ${API_NAME} check error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 10. Global error handler passes through HTTPExceptions (including 402s)
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
