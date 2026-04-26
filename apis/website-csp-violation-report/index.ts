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
  safeFetch,
  validateExternalUrl,
  readBodyCapped,
} from "../../shared/ssrf";
import type { ReportAnalysis, InfoEndpointResponse } from "./types";
import { analyzeCspPayload, fetchAndAnalyzeReportUri } from "./analyzer";

const app = new Hono();
const API_NAME = "website-csp-violation-report";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUM = 0.01; // For apiLogger

// 1. CORS, open to all origins and allow GET, POST, OPTIONS
app.use("*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// 2. Health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limits (mild, e.g., 20 per minute global, 10 per minute for check)
app.use("/analyze-report", rateLimit("website-csp-analyze-report-post", 10, 60_000));
app.use("/fetch-analyze", rateLimit("website-csp-fetch-analyze-get", 20, 60_000));
app.use("*", rateLimit("website-csp-global", 60, 60_000));

// 4. Extract payer wallet
app.use("*", extractPayerWallet());

// 5. API logger
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// 6. Info endpoint
app.get("/", (c) => {
  const infoResp: InfoEndpointResponse = {
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs: {
      endpoints: [
        {
          method: "POST",
          path: "/analyze-report",
          description: "Analyze a CSP violation report JSON payload from a POSTed report",
          parameters: [
            {
              name: "body",
              description: "CSP violation report JSON payload (application/json) in request body",
              required: true,
              type: "object",
            },
          ],
          example_response: {
            status: "ok",
            data: {
              score: 30,
              grade: "D",
              severity: "critical",
              summary: "CSP violation of directive 'script-src' with severity critical.",
              details: "...",
              recommendations: [
                {
                  issue: "Violation of critical directive 'script-src'.",
                  severity: "critical",
                  suggestion: "Review your CSP directives for 'script-src' to remove unsafe sources.",
                },
              ],
              rawReport: { /* csp-report data */ },
            },
            meta: {
              timestamp: "ISO8601",
              duration_ms: 120,
              api_version: "1.0.0",
            },
          },
        },
        {
          method: "GET",
          path: "/fetch-analyze",
          description: "Fetch a CSP violation report JSON from a site's report URI endpoint and analyze it",
          parameters: [
            {
              name: "reportUri",
              description: "Full https:// URL of the CSP violation report endpoint to fetch",
              required: true,
              type: "string",
            },
          ],
          example_response: {
            status: "ok",
            data: {
              score: 45,
              grade: "C",
              severity: "warning",
              summary: "CSP violation of directive 'style-src' with severity warning.",
              details: "...",
              recommendations: [
                {
                  issue: "Violation of important directive 'style-src'.",
                  severity: "warning",
                  suggestion: "Tighten your CSP to restrict style sources to trusted domains only.",
                },
              ],
              rawReport: { /* csp-report data */ },
            },
            meta: {
              timestamp: "ISO8601",
              duration_ms: 900,
              api_version: "1.0.0",
            },
          },
        },
      ],
      parameters: [
        {
          name: "reportUri",
          description: "URL to fetch CSP report JSON from",
          required: true,
          type: "string",
        },
      ],
      examples: [
        {
          description: "Analyze a sample CSP violation report JSON payload",
          request: "POST /analyze-report with JSON body",
          response: {
            status: "ok",
            data: {
              score: 25,
              grade: "D",
              severity: "critical",
              summary: "...",
              details: "...",
              recommendations: [
                {
                  issue: "...",
                  severity: "critical",
                  suggestion: "...",
                },
              ],
            },
            meta: {
              timestamp: "...",
              duration_ms: 150,
              api_version: "1.0.0",
            },
          },
        },
        {
          description: "Fetch and analyze CSP reports from a report URI",
          request: "GET /fetch-analyze?reportUri=https://example.com/csp-report-endpoint",
          response: {
            status: "ok",
            data: { /* analysis */ },
            meta: { /* timing etc */ },
          },
        },
      ],
    },
    pricing: {
      preview: "$0.000 (preview endpoint, free)",
      paid: PRICE,
    },
  };

  return c.json(infoResp);
});

// 7. Free preview endpoint - example analyzing a submitted payload (no payment)
app.post("/preview", rateLimit("website-csp-violation-report-preview", 20, 60_000), async (c) => {
  try {
    // Accept JSON body
    const body = await c.req.json();
    const start = performance.now();
    const analysis = await analyzeCspPayload(body);
    const duration_ms = Math.round(performance.now() - start);
    if ("error" in analysis) {
      return c.json({
        status: "error",
        error: analysis.error,
        detail: "Invalid CSP violation report payload",
        meta: {
          timestamp: new Date().toISOString(),
          duration_ms,
          api_version: "1.0.0",
        },
      }, 400);
    }
    return c.json({
      status: "ok",
      data: analysis,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0",
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, status);
  }
});

// 8. Payment middleware and spend cap
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "POST /analyze-report": paidRouteWithDiscovery(
        PRICE,
        "Analyze submitted CSP violation report payload with detailed security grading and fix recommendations",
        {
          input: { reportPayload: "{}" },
          inputSchema: {
            properties: {
              reportPayload: {
                type: "object",
                description: "JSON payload of CSP violation report POST body",
              },
            },
            required: ["reportPayload"],
          },
        },
      ),
      "GET /fetch-analyze": paidRouteWithDiscovery(
        PRICE,
        "Fetch and analyze CSP violation report from a provided report URI endpoint",
        {
          input: { reportUri: "https://example.com/csp-report-endpoint" },
          inputSchema: {
            properties: {
              reportUri: {
                type: "string",
                description: "Full HTTPS URL of the CSP violation report endpoint",
              },
            },
            required: ["reportUri"],
          },
        },
      ),
    },
    resourceServer
  ),
);

// 9a. Paid analyze-report endpoint: accept JSON payload in POST body
app.post("/analyze-report", async (c) => {
  try {
    const jsonBody = await c.req.json();
    const start = performance.now();

    const analysis = await analyzeCspPayload(jsonBody);
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in analysis) {
      return c.json(
        {
          status: "error",
          error: analysis.error,
          detail: "Invalid CSP report payload",
          meta: {
            timestamp: new Date().toISOString(),
            duration_ms,
            api_version: "1.0.0",
          },
        },
        400
      );
    }

    return c.json({
      status: "ok",
      data: analysis,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0",
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, status);
  }
});

// 9b. Paid fetch-and-analyze endpoint: GET with ?reportUri= parameter, fetches and analyzes
app.get("/fetch-analyze", async (c) => {
  const reportUri = c.req.query("reportUri");
  if (!reportUri || typeof reportUri !== "string") {
    return c.json({ error: "Missing ?reportUri= parameter (https://...)" }, 400);
  }
  if (reportUri.length > 2048) {
    return c.json({ error: "reportUri parameter too long" }, 400);
  }
  try {
    const start = performance.now();
    const analysis = await fetchAndAnalyzeReportUri(reportUri.trim());
    const duration_ms = Math.round(performance.now() - start);
    if ("error" in analysis) {
      return c.json(
        {
          status: "error",
          error: analysis.error,
          detail: "Failed to fetch or analyze CSP report",
          meta: {
            timestamp: new Date().toISOString(),
            duration_ms,
            api_version: "1.0.0",
          },
        },
        400
      );
    }
    return c.json({
      status: "ok",
      data: analysis,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0",
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, status);
  }
});

// 10. CRITICAL error handler - pass through x402 HTTPExceptions
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
