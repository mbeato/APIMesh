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
  readBodyCapped,
} from "../../shared/ssrf";
import {
  analyzeConfigurations,
  ConfigFingerprintResult,
  analyzePreview,
} from "./analyzer";

const app = new Hono();
const API_NAME = "web-configuration-fingerprint";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // comprehensive audit (5+ checks, scoring, detailed report)
const PRICE_NUM = 0.01;

// CORS open to all origins
app.use("*",
  cors({
    origin: "*",
    allowMethods: ["GET"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// Health endpoint (before rate limiter)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits
app.use("/check", rateLimit("web-configuration-fingerprint-check", 20, 60_000));
app.use("*", rateLimit("web-configuration-fingerprint", 60, 60_000));

// Extract payer wallet
app.use("*", extractPayerWallet());

// Logger with price
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint providing documentation and pricing
app.get("/", async (c) => {
  const docs = {
    endpoints: [
      {
        method: "GET",
        path: "/check",
        description: "Analyze web server and framework configs by URL, returning a comprehensive fingerprint with scoring and fix recommendations",
        parameters: [
          { name: "url", type: "string", required: true, description: "URL to the base directory or site. Used to check common config files like nuxt.config.js, next.config.js, netlify.toml." }
        ],
        exampleResponse: {
          status: "ok",
          data: {
            url: "https://example.com",
            configsFound: ["nuxt.config.js", "netlify.toml"],
            framework: "Nuxt",
            deployment: "Netlify",
            score: 87,
            grade: "B",
            recommendations: [
              { issue: "Outdated Nuxt version", severity: 60, suggestion: "Upgrade to Nuxt 3.x for improved performance and security." },
              { issue: "Netlify redirects missing", severity: 40, suggestion: "Add _redirects file for better routing control." }
            ],
            details: "Detected Nuxt.js app deployed on Netlify with legacy redirects file missing. No next.config.js found suggesting no Next.js framework."
          },
          meta: {
            timestamp: "2024-06-01T12:34:56.789Z",
            duration_ms: 4567,
            api_version: "1.0.0"
          }
        }
      },
      {
        method: "GET",
        path: "/preview",
        description: "Snapshot preview of configuration files detected, quick and free",
        parameters: [
          { name: "url", type: "string", required: true, description: "URL to the site to analyze" }
        ],
        exampleResponse: {
          status: "ok",
          data: {
            url: "https://example.com",
            configsDetected: ["nuxt.config.js"],
            frameworkGuess: "Nuxt",
            note: "Preview mode does a quick check for presence of common config files only."
          },
          meta: {
            timestamp: "2024-06-01T12:30:00.123Z",
            duration_ms: 1200,
            api_version: "1.0.0"
          }
        }
      }
    ],
    parameters: [
      { name: "url", type: "string", description: "URL of the site or directory to analyze" }
    ],
    examples: [
      { request: "/check?url=https://example.com", description: "Comprehensive web configuration fingerprint" },
      { request: "/preview?url=https://example.com", description: "Quick preview of detected configs" }
    ],
  };

  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs,
    pricing: {
      type: "comprehensive audit",
      price: PRICE,
      description: "Per-call cost for deep multi-file, multi-framework analysis with scoring and recommendations",
    },
  });
});

// Free preview endpoint (quick config file presence check, open to all, 20s timeout)
app.get("/preview", rateLimit("web-configuration-fingerprint-preview", 15, 60_000), async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const validated = validateExternalUrl(rawUrl.trim());
  if ("error" in validated) {
    return c.json({ error: validated.error }, 400);
  }

  try {
    const start = performance.now();
    const result = await analyzePreview(validated.url);
    const duration_ms = Math.round(performance.now() - start);

    return c.json({
      status: "ok",
      data: result,
      meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Spend cap enforcement
app.use("*", spendCapMiddleware());

// Payment middleware with paidRouteWithDiscovery for the /check endpoint
app.use(
  "*",
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Deep analysis combining detection of Nuxt, Next.js, Netlify, and others; scoring and actionable recommendations",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "URL to analyze, expected root or base directory" },
            },
            required: ["url"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid comprehensive fingerprint check
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const validated = validateExternalUrl(rawUrl.trim());
  if ("error" in validated) {
    return c.json({ error: validated.error }, 400);
  }

  try {
    const start = performance.now();
    const result = await analyzeConfigurations(validated.url);
    const duration_ms = Math.round(performance.now() - start);

    // In case of partial failure but partial data, still return ok with explanation
    if ("error" in result && Object.keys(result).length === 1) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// On error handler (pass-through 402 and others)
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
