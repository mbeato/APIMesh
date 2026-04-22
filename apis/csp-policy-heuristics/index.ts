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
  runComprehensiveAudit,
  runPreviewAudit,
  CspPolicyAnalysisResult
} from "./analyzer";

const app = new Hono();
const API_NAME = "csp-policy-heuristics";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.010"; // Comprehensive audit price
const PRICE_NUM = 0.01;

// CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint (before rate limiter)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limiting:
// Allow 15 calls per minute for preview
// Allow 40 calls per minute for paid check
app.use("/preview", rateLimit("csp-policy-heuristics-preview", 15, 60_000));
app.use("/check", rateLimit("csp-policy-heuristics-check", 40, 60_000));
app.use("*", rateLimit("csp-policy-heuristics-global", 90, 60_000));

// Extract wallet from payment info
app.use("*", extractPayerWallet());

// API Logger logs with price number
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    description: "Analyzes website responses and resource loading to generate tailored Content Security Policies (CSP). Combines multi-source data to identify insecure resource usage and recommend strong, context-aware CSP.",
    docs: {
      endpoints: [
        {
          path: "/preview",
          method: "GET",
          description: "Free preview analysis with limited CSP heuristic checks and basic recommendations.",
          parameters: [
            { name: "url", in: "query", required: true, description: "Target URL to analyze" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              cspScore: 62,
              cspGrade: "B",
              insecureResourcesCount: 3,
              recommendations: [
                { issue: "Mixed content detected", severity: "high", suggestion: "Update all HTTP resource links to HTTPS." }
              ],
              details: "Analysis performed by scanning CSP headers and resource requests, highlighting mixed content and legacy directives."
            },
            meta: {
              timestamp: "2023-01-01T00:00:00.000Z",
              duration_ms: 150,
              api_version: "1.0.0"
            }
          }
        },
        {
          path: "/check",
          method: "GET",
          description: "Paid comprehensive audit with advanced heuristic analysis, web crawling, scoring, and detailed recommendations.",
          parameters: [
            { name: "url", in: "query", required: true, description: "Target URL to analyze" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              cspScore: 88,
              cspGrade: "A",
              insecureResourcesCount: 1,
              activeMixedContent: false,
              evaluations: {
                inlineScripts: 0,
                unsafeEvalUsage: false,
                wildcardSources: false,
                legacyDirectives: false
              },
              recommendations: [
                { issue: "Wildcard source in script-src", severity: "medium", suggestion: "Restrict script-src to specific domains." }
              ],
              details: "This comprehensive analysis includes crawling linked resources and inspecting CSP headers and runtime behavior to generate a detailed report."
            },
            meta: {
              timestamp: "2023-01-01T00:00:00.000Z",
              duration_ms: 1450,
              api_version: "1.0.0"
            }
          }
        }
      ],
      parameters: [
        { name: "url", in: "query", type: "string", description: "URL of the target website (must be http(s):// and max 2048 chars)" }
      ],
      examples: [
        { method: "GET", path: "/preview?url=https://example.com", description: "Get a quick preview analysis" },
        { method: "GET", path: "/check?url=https://example.com", description: "Get a paid comprehensive CSP policy heuristic audit" }
      ],
    },
    pricing: {
      preview: "$0.00",
      check: PRICE
    }
  });
});

// Free preview endpoint - lower rate limits, longer timeout
app.get("/preview", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  try {
    const result = await runPreviewAudit(rawUrl.trim());
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    const start = performance.now();
    const duration_ms = Math.round(performance.now() - start);
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: unknown) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Payment middleware
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive CSP policy heuristic audit including multi-source resource fetching and detailed actionable recommendations.",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "Target website URL" },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer
  ),
);

// Paid route
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  try {
    const start = performance.now();
    const result = await runComprehensiveAudit(rawUrl.trim());
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    const duration_ms = Math.round(performance.now() - start);
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: unknown) {
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
