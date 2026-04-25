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
import { validateExternalUrl, safeFetch, readBodyCapped } from "../../shared/ssrf";
import {
  analyzeHeaders,
  analyzeHtmlContent,
  analyzeCspHeader,
  computeOverallScore,
  generateRecommendations,
  ContentSecurityAnalysisResult,
  HeaderAnalysis,
  Recommendation,
  Grade,
  DetailedAnalysisResult,
  PreviewAnalysisResult,
} from "./analyzer";

const app = new Hono();
const API_NAME = "content-security-policy-check";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUM = 0.01;

// CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint (before rate limiting)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits
app.use(
  "/check",
  rateLimit("content-security-policy-check-check", 15, 60_000),
);
app.use("*", rateLimit("content-security-policy-check", 60, 60_000));

// Extract payer wallet and log API usage
app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint
app.get("/", (c) =>
  c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/check",
          description:
            "Perform a comprehensive security header and content security policy audit",
          parameters: [
            {
              name: "url",
              type: "string",
              required: true,
              description: "The full HTTPS or HTTP URL of the site to analyze",
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              overallScore: 85,
              overallGrade: "B",
              headers: [
                {
                  header: "content-security-policy",
                  present: true,
                  value: "default-src 'self'; script-src 'self';",
                  rating: "A",
                  issues: [],
                },
              ],
              cspDirectives: {
                "default-src": ["'self'"],
                "script-src": ["'self'"]
              },
              recommendations: [
                {
                  issue: "Missing 'frame-ancestors' directive",
                  severity: 50,
                  suggestion: "Add 'frame-ancestors' directive to restrict framing attackers",
                },
              ],
              analysisDetails: "The CSP is generally strong with no unsafe-inline or unsafe-eval, but lacks 'frame-ancestors' directive, which could allow clickjacking.",
            },
            meta: {
              timestamp: "2024-04-01T12:00:00.000Z",
              duration_ms: 1350,
              api_version: "1.0.0",
            },
          },
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview of CSP header analysis and basic HTTP headers",
          parameters: [
            {
              name: "url",
              type: "string",
              required: true,
              description: "URL to preview analyze",
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com",
              preview: true,
              overallScore: 70,
              overallGrade: "C",
              headers: [
                {
                  header: "content-security-policy",
                  present: true,
                  value: "default-src 'self';",
                  rating: "C",
                  issues: ["Missing 'script-src' directive."],
                },
              ],
              recommendations: [
                {
                  issue: "Missing 'script-src' directive",
                  severity: 70,
                  suggestion: "Add 'script-src' to restrict execution sources.",
                },
              ],
              note: "Preview checks CSP header and critical headers only.",
            },
            meta: {
              timestamp: "2024-04-01T12:00:00.000Z",
              duration_ms: 750,
              api_version: "1.0.0",
            },
          },
        },
      ],
      parameters: [
        { name: "url", type: "string", required: true, description: "Website URL (http or https)" },
      ],
      examples: [
        {
          description: "Full paid CSP security audit",
          request: "/check?url=https://example.com",
          response: {},
        },
        {
          description: "Free preview of CSP security audit",
          request: "/preview?url=https://example.com",
          response: {},
        },
      ],
    },
    pricing: {
      paidEndpoint: "/check",
      price: PRICE,
      description:
        "Comprehensive audit with multiple header checks, CSP parsing, content analysis, scoring, and remediation recommendations",
    },
  })
);

// Free preview endpoint - less strict rate limit and longer timeout
app.get(
  "/preview",
  rateLimit("content-security-policy-check-preview", 30, 60_000),
  async (c) => {
    const rawUrl = c.req.query("url");
    if (!rawUrl || typeof rawUrl !== "string") {
      return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
    }
    if (rawUrl.length > 2048) {
      return c.json({ error: "URL exceeds maximum length" }, 400);
    }

    const check = validateExternalUrl(rawUrl.trim());
    if ("error" in check) return c.json({ error: check.error }, 400);

    try {
      const start = performance.now();
      const result: PreviewAnalysisResult = await analyzeHeaders(check.url.toString());
      const duration_ms = Math.round(performance.now() - start);
      return c.json({
        status: "ok",
        data: result,
        meta: {
          timestamp: new Date().toISOString(),
          duration_ms,
          api_version: "1.0.0",
        },
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
      return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
    }
  },
);

// Payment and spend cap middleware
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive audit combining multiple HTTP headers, CSP parsing and grading, HTML CSP directive detection, scoring, and actionable remediation recommendations",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            type: "object",
            properties: {
              url: { type: "string", description: "The target URL to audit" },
            },
            required: ["url"],
            additionalProperties: false,
          },
        },
      ),
    },
    resourceServer,
  ),
);

// Paid comprehensive check endpoint
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const check = validateExternalUrl(rawUrl.trim());
  if ("error" in check) return c.json({ error: check.error }, 400);

  try {
    const start = performance.now();
    const result: DetailedAnalysisResult = await performFullAudit(check.url.toString());
    const duration_ms = Math.round(performance.now() - start);

    return c.json({
      status: "ok",
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms,
        api_version: "1.0.0",
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

/**
 * Perform the full multi-source audit by fetching headers and content.
 * This performs multiple network calls and intensive analysis.
 */
async function performFullAudit(url: string): Promise<DetailedAnalysisResult> {
  // Validate the URL before fetch
  const validated = validateExternalUrl(url);
  if ("error" in validated) {
    throw new Error(validated.error);
  }

  // Fetch headers with GET to allow reading body
  // Limit total fetch time to 10s for each fetch call
  // We do multiple fetches: HEAD for headers, GET for content

  // Use Promise.all to do HEAD and GET in parallel when possible

  // 1. Fetch HEAD for headers snapshot (8s timeout)
  // 2. Fetch GET for content (10s timeout)

  // If HEAD fails, fallback to GET only

  let headResponse: Response | null = null;
  let getResponse: Response | null = null;

  try {
    headResponse = await safeFetch(url, {
      method: "HEAD",
      timeoutMs: 8000,
      headers: { "User-Agent": "content-security-policy-check/1.0 apimesh.xyz" },
    });
  } catch {
    // ignore; fallback to GET
  }

  if (!headResponse || !headResponse.ok) {
    try {
      getResponse = await safeFetch(url, {
        method: "GET",
        timeoutMs: 10000,
        headers: { "User-Agent": "content-security-policy-check/1.0 apimesh.xyz" },
      });
    } catch (e) {
      throw e;
    }
  } else {
    // Fetch GET in parallel with HEAD
    try {
      getResponse = await safeFetch(url, {
        method: "GET",
        timeoutMs: 10000,
        headers: { "User-Agent": "content-security-policy-check/1.0 apimesh.xyz" },
      });
    } catch (e) {
      // Could still use HEAD alone if GET fails
      getResponse = null;
    }
  }

  // Choose primary headers source
  const headers = (headResponse && headResponse.headers) || (getResponse && getResponse.headers);
  if (!headers) {
    throw new Error("Failed to fetch headers from target URL");
  }

  // Parse headers analysis
  const headerAnalysis = analyzeHeaders(headers);

  // Read body content from GET response
  let body = "";
  if (getResponse && getResponse.ok) {
    try {
      body = await readBodyCapped(getResponse, 200_000); // 200 KB cap
    } catch {
      // Do nothing, body remain empty
    }
  }

  // Analyze CSP header from headers
  const cspHeaderValue = headers.get("content-security-policy") || headers.get("content-security-policy-report-only") || "";
  const cspAnalysis = analyzeCspHeader(cspHeaderValue);

  // Analyze CSP from HTML content as well
  const htmlCspDirectives = analyzeHtmlContent(body);

  // Compute overall score and grade
  const overallScore = computeOverallScore(headerAnalysis, cspAnalysis, htmlCspDirectives);
  const overallGrade = gradeFromScore(overallScore);

  // Generate actionable recommendations
  const recommendations: Recommendation[] = generateRecommendations(
    headerAnalysis,
    cspAnalysis,
    htmlCspDirectives
  );

  // Assemble result
  const result: DetailedAnalysisResult = {
    url,
    overallScore,
    overallGrade,
    headers: headerAnalysis,
    cspDirectives: cspAnalysis.directives,
    htmlCspDirectives: htmlCspDirectives.directives,
    recommendations,
    analysisDetails: generateDetailsText(headerAnalysis, cspAnalysis, htmlCspDirectives),
    scannedAt: new Date().toISOString(),
  };

  return result;
}

// Helper to convert numeric score to letter grade
function gradeFromScore(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

// Helper to create combined human-readable details
function generateDetailsText(
  headers: HeaderAnalysis[],
  csp: ContentSecurityAnalysisResult,
  htmlCsp: ContentSecurityAnalysisResult
): string {
  const lines: string[] = [];
  lines.push("Header Analysis:");
  for (const h of headers) {
    lines.push(`- ${h.header}: rating ${h.rating} - ${h.issues.length ? h.issues.join(", ") : "No issues detected."}`);
  }
  if (csp && csp.directives) {
    lines.push("Content Security Policy Header Directives:");
    for (const dir of Object.keys(csp.directives)) {
      lines.push(`- ${dir}: ${csp.directives[dir].join(" ")}`);
    }
  }
  if (htmlCsp && htmlCsp.directives) {
    lines.push("Content Security Policy Directives Found in HTML:");
    if (Object.keys(htmlCsp.directives).length === 0) {
      lines.push("- None found.");
    } else {
      for (const dir of Object.keys(htmlCsp.directives)) {
        lines.push(`- ${dir}: ${htmlCsp.directives[dir].join(" ")}`);
      }
    }
  }
  return lines.join("\n");
}

// Error handling must pass through HTTPException for 402s.
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
