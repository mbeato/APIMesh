import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl, safeFetch } from "../../shared/ssrf";
import { analyzePrivacyPolicies, PrivacyPolicyAnalysisResult } from "./analyzer";

const app = new Hono();
const API_NAME = "privacy-policy-qualify";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUMBER = 0.01;

// CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint (before rate limiter)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limiting
app.use("/check", rateLimit("privacy-policy-qualify-check", 10, 60_000));
app.use("*", rateLimit("privacy-policy-qualify", 30, 60_000));

// Extract payer wallet from headers
app.use("*", extractPayerWallet());

// Logger logs this API name with price in number format
app.use("*", apiLogger(API_NAME, PRICE_NUMBER));

// Info endpoint - exposes API status, docs, pricing
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
          description: "Fetch and analyze privacy policies across domains for GDPR/CCPA compliance and data sharing signals",
          parameters: [
            {
              name: "url",
              in: "query",
              required: true,
              description: "URL to privacy policy or site landing page (http or https)",
              schema: { type: "string" },
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com/privacy",
              complianceScore: 88.5,
              grade: "B",
              gdprSignals: { dataSubjectsRights: true, lawfulBasis: true, dataTransfers: false },
              ccpaSignals: { doNotSell: true, optOutMechanism: true },
              dataSharingDeclared: true,
              recommendations: [
                { issue: "Missing clear data retention policy", severity: 70, suggestion: "Add specific data retention periods and disclosure." },
                { issue: "No explicit details on third party sharing", severity: 60, suggestion: "Include list of partners and purposes for data sharing." },
              ],
              details: "The privacy policy was fetched from https://example.com/privacy and analyzed with multi-source NLP techniques including regex scans, content parsing, and entity extraction."
            },
            meta: {
              timestamp: "2024-06-01T12:00:00Z",
              duration_ms: 250,
              api_version: "1.0.0"
            }
          }
        },
      ],
      parameters: [
        {
          name: "url",
          required: true,
          description: "The full URL (http or https) to the privacy policy or main site domain to analyze.",
          type: "string",
          maxLength: 2048
        }
      ],
      examples: [
        {
          description: "Check privacy policy for example.com",
          method: "GET",
          path: "/check?url=https://example.com/privacy"
        }
      ]
    },
    pricing: {
      description: "Comprehensive audit (5+ checks, scoring, detailed report)",
      price: PRICE
    }
  });
});

// Free preview endpoint to allow initial test, rate limited more strictly
app.get("/preview", rateLimit("privacy-policy-qualify-preview", 15, 60_000), async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (typeof rawUrl !== "string") {
    return c.json({ error: "Invalid url parameter type" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const check = validateExternalUrl(rawUrl.trim());
  if ("error" in check) return c.json({ error: check.error }, 400);

  try {
    // Preview uses partial simpler analysis with longer timeout 20s
    const result = await analyzePrivacyPolicies(check.url.toString(), true);
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms: result.duration_ms || 0,
        api_version: "1.0.0"
      },
      preview: true,
      note: "Preview provides a quick high-level compliance signal with limited NLP passes. Pay via x402 for full comprehensive audit."
    });
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Spend cap enforcement middleware
app.use("*", spendCapMiddleware());

// Payment gate middleware, only /check is paid route
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive privacy policy audit combining fetch, multi-source content analysis, GDPR/CCPA compliance scoring, data sharing detection, and recommendations",
        {
          input: { url: "https://example.com/privacy" },
          inputSchema: {
            type: "object",
            properties: {
              url: { type: "string", description: "URL of the privacy policy or site to analyze" },
            },
            required: ["url"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid endpoint: full comprehensive analysis
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (typeof rawUrl !== "string") {
    return c.json({ error: "Invalid url parameter type" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const check = validateExternalUrl(rawUrl.trim());
  if ("error" in check) return c.json({ error: check.error }, 400);

  try {
    const start = performance.now();
    const result = await analyzePrivacyPolicies(check.url.toString(), false);
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
    console.error(`[${new Date().toISOString()}] ${API_NAME} check error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// CRITICAL error handler - must pass through x402 HTTPExceptions
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
