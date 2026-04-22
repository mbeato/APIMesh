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
import { fetchMultiple } from "./fetcher";
import { fullAnalysis } from "./analyzer";
import { previewAnalysis } from "./preview";
import type { PrivacyRiskScoreResponse } from "./types";
import type { FetchedSource } from "./fetcher";

const app = new Hono();
const API_NAME = "privacy-risk-score";
const PORT = Number(process.env.PORT) || 3001;

// Pricing choice: Comprehensive audit (5+ checks, scoring, detailed report): $0.01
const PRICE = "$0.01";
const PRICE_NUM = 0.01;

app.use("*",
  cors({
    origin: "*",
    allowMethods: ["GET"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// Health endpoint (before rate limiting)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits
app.use("/check", rateLimit("privacy-risk-score-check", 15, 60_000));
app.use("/preview", rateLimit("privacy-risk-score-preview", 20, 60_000));
app.use("*", rateLimit("privacy-risk-score", 60, 60_000));

// Extract payer wallet for billing
app.use("*", extractPayerWallet());

// API logging with price number
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
          path: "/check",
          description: "Paid endpoint for comprehensive privacy risk analysis of a domain's publicly available privacy policies and disclosures.",
          parameters: [
            { name: "url", required: true, description: "Public URL of the domain's homepage or privacy policy." },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              sources: [
                {
                  url: "https://example.com/privacy",
                  fetchedUrl: "https://example.com/privacy",
                  status: 200,
                  contentType: "text/html",
                  bodySnippet: "...",
                },
              ],
              disclosures: [
                {
                  type: "gdpr-notice",
                  text: "...",
                  confidence: 0.9,
                  severity: "high",
                },
              ],
              compliance: {
                gdprDetected: true,
                gdprScore: 85,
                ccpaDetected: false,
                ccpaScore: 0,
                dataSharingCount: 3,
              },
              riskScore: 40,
              grade: "C",
              recommendations: [
                {
                  issue: "CCPA compliance notices not detected",
                  severity: "medium",
                  suggestion: "Add CCPA or California privacy rights disclosures if applicable.",
                },
              ],
              explanation: "Privacy risk score is 40 out of 100 (higher means more risk). GDPR compliance signals detected with coverage score 85%. CCPA compliance signals not detected. Data sharing mentions count: 3. Consider recommendations to improve your privacy disclosures and reduce risks."
            },
            meta: {
              timestamp: "2024-04-01T12:00:00Z",
              duration_ms: 450,
              api_version: "1.0.0"
            }
          },
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview endpoint with basic keyword scans of given URL content snippets.",
          parameters: [
            { name: "url", required: true, description: "Public URL of the domain homepage for scanning." },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              fetchedUrl: "https://example.com/",
              preview: true,
              summary: "Fetched homepage for example.com. Content length: 12345 chars. Basic preview shows initial content snippet and checks for GDPR/CCPA keywords.",
              compliance: {
                gdprDetected: true,
                gdprScore: 50,
                ccpaDetected: false,
                ccpaScore: 0,
                dataSharingCount: 0
              },
              note: "Preview is free and shows minimal info with basic keyword scanning. Payment unlocks detailed multi-source privacy risk scoring."
            },
            meta: {
              timestamp: "2024-04-01T12:00:00Z",
              duration_ms: 300,
              api_version: "1.0.0"
            }
          },
        },
      ],
      parameters: [
        { name: "url", description: "Public URL (homepage or privacy policy) to analyze." },
      ],
      examples: [
        {
          request: "/check?url=https://example.com/privacy",
          response: {
            status: "ok",
            data: { /* structured detailed result as above */ },
            meta: { timestamp: "...", duration_ms: 400, api_version: "1.0.0" }
          }
        }
      ],
    },
    pricing: {
      tiers: [
        {
          level: "Comprehensive audit",
          price: "$0.01",
          description: "Multiple fetches, NLP privacy disclosures, scoring, grading, and actionable recommendations."
        }
      ]
    }
  });
});

// Free preview endpoint
app.get("/preview", async (c) => {
  const rawUrl = c.req.query("url");

  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }

  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  try {
    const result = await previewAnalysis(rawUrl.trim());

    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms: 0, // Duration not measured here
        api_version: "1.0.0",
      },
    });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Validate and normalize URL param for paid endpoint
function checkAndCleanUrl(rawUrl: string): { url: string } | { error: string } {
  if (!rawUrl || typeof rawUrl !== "string") return { error: "Missing URL parameter" };
  if (rawUrl.length > 2048) return { error: "URL exceeds maximum length" };

  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: `Invalid URL: ${check.error}` };

  return { url: check.url.toString() };
}

// Paid comprehensive endpoint
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive privacy risk analysis by fetching privacy policies and disclosures, NLP detection of GDPR/CCPA signals, data sharing practices, scoring and recommendations",
        {
          input: { url: "https://example.com/privacy" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "URL of the privacy policy or homepage for analysis" },
            },
            required: ["url"],
          },
        }
      ),
    },
    resourceServer
  )
);

app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  const check = checkAndCleanUrl(rawUrl);
  if ("error" in check) {
    return c.json({ error: check.error }, 400);
  }

  // For comprehensive audit, fetch multiple common privacy-related URLs, parallel fetch
  // Base URLs to try for multi-check
  const tryPaths = [
    "",
    "/privacy",
    "/privacy-policy",
    "/legal/privacy",
    "/privacy.html",
  ];

  // Compose URLs to fetch based on base domain
  let baseUrl: URL;
  try {
    baseUrl = new URL(check.url);
  } catch {
    return c.json({ error: "Invalid URL" }, 400);
  }

  const baseOrigin = baseUrl.origin;
  const domain = baseUrl.hostname;
  const urlsToFetch = tryPaths.map((path) => baseOrigin + path);

  const start = performance.now();

  try {
    const sources: FetchedSource[] = await fetchMultiple(urlsToFetch);
    const result = await fullAnalysis(domain, sources);

    const duration_ms = Math.round(performance.now() - start);

    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} check error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Error handler — pass through x402 HTTPExceptions for 402s
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
