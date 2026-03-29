import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { validateExternalUrl, safeFetch } from "../../shared/ssrf";

const app = new Hono();
const API_NAME = "website-security-header-info";
const PRICE = "$0.01"; // Price per call in USD
const PORT = Number(process.env.PORT) || 3001;

// 1. CORS middleware open to all origins
app.use("*", cors({ origin: "*", allowMethods: ["GET"], allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"] }));

// 2. Health check endpoint (before rate limit)
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limiting middleware
app.use("*", rateLimit("website-security-header-info", 60, 60000)); // 60 requests per minute globally

// 4. Wallet extraction middleware
app.use("*", extractPayerWallet());

// 5. API logger middleware
app.use("*", apiLogger(API_NAME, 0.01)); // $0.01 per call

// 6. Info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    docs: "GET /?url=website.com",
    pricing: PRICE + " per call"
  });
});

// 7. Spend cap middleware
app.use("*", spendCapMiddleware());

// 8. Payment middleware with discovery
app.use("*", paymentMiddleware({
  "GET /": paidRouteWithDiscovery(
    PRICE,
    "Analyze security-related HTTP headers of a website",
    {
      input: { url: "https://example.com" },
      inputSchema: {
        properties: {
          url: { type: "string", description: "Target website URL" }
        },
        required: ["url"]
      }
    }
  )
}, resourceServer));

// 9. Main endpoint: analyze headers
app.get("/", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing or invalid ?url= parameter" }, 400);
  }

  // Validate and sanitize URL
  const validationResult = validateExternalUrl(rawUrl);
  if ("error" in validationResult) {
    return c.json({ error: "Invalid external URL" }, 400);
  }

  const { url } = validationResult;

  try {
    const res = await safeFetch(url, { redirect: "manual" });
    // Fetch headers
    const headers = res.headers;

    // Extract security headers
    const csp = headers.get("content-security-policy") || headers.get("content-security-policy-report-only") || "";
    const hsts = headers.get("strict-transport-security") || "";
    const xContentTypeOptions = headers.get("x-content-type-options") || "";
    const xFrameOptions = headers.get("x-frame-options") || "";
    const xXssProtection = headers.get("x-xss-protection") || "";
    const referrerPolicy = headers.get("referrer-policy") || "";
    const permissionsPolicy = headers.get("permissions-policy") || headers.get("feature-policy") || "";

    // Analyze headers for security strengths
    const issues: string[] = [];

    if (!csp) issues.push("Missing Content-Security-Policy");
    else {
      if (csp.toLowerCase().includes("unsafe-inline")) issues.push("Content-Security-Policy allows unsafe-inline");
      if (csp.toLowerCase().includes("unsafe-eval")) issues.push("Content-Security-Policy allows unsafe-eval");
    }

    if (!hsts) issues.push("Missing Strict-Transport-Security");

    if (xContentTypeOptions.toLowerCase() !== "nosniff") issues.push("X-Content-Type-Options is not nosniff");

    if (xFrameOptions && xFrameOptions.toLowerCase() === "sameorigin") {
      // ok
    } else {
      issues.push("X-Frame-Options missing or not sameorigin");
    }

    if (xXssProtection && xXssProtection !== "0") {
      // ok or disable
    } else {
      issues.push("X-XSS-Protection is disabled or missing");
    }

    if (referrerPolicy.toLowerCase() === "no-referrer") {
      // good
    } else {
      issues.push("Referrer-Policy not set to no-referrer");
    }

    if (permissionsPolicy && permissionsPolicy !== "") {
      if (permissionsPolicy.toLowerCase().includes("geolocation") || permissionsPolicy.toLowerCase().includes("microphone")) {
        issues.push("Permissions-Policy allows geolocation or microphone");
      }
    } else {
      issues.push("Permissions-Policy header missing");
    }

    // Compose result
    const result = {
      headers, // raw headers for reference
      issues,
      url,
    };

    return c.json(result);
  } catch (err) {
    // On fetch error
    return c.json({ error: "Failed to fetch URL or network error" }, 500);
  }
});

// Error handler: pass through HTTPException errors, handle others
app.onError((err, c) => {
  if ("getResponse" in err) return (err).getResponse();
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

// 10. 404 handler
app.notFound((c) => c.json({ error: "Not found" }, 404));

// Export app
export { app };

// Run server if main
if (import.meta.main) {
  console.log(`${API_NAME} listening on port ${PORT}`);
}

// Default export for serverless
export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};