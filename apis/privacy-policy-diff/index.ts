import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl } from "../../shared/ssrf";
import { analyzePolicyDiff, previewFetchPolicy, fetchAndAnalyze } from "./analyzer";
import { DiffResult, PreviewResult } from "./types";

const app = new Hono();
const API_NAME = "privacy-policy-diff";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Deep scan with extensive crawling, multi-layered analysis
const PRICE_NUMBER = 0.01;

// CORS open
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint (no rate limit)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits
app.use("/diff", rateLimit("privacy-policy-diff-diff", 5, 60_000));
app.use("/preview", rateLimit("privacy-policy-diff-preview", 20, 60_000));
app.use("*", rateLimit("privacy-policy-diff", 50, 60_000));

// Wallet extraction
app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, PRICE_NUMBER));

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
          path: "/preview",
          description: "Fetch latest privacy policy snippet for domain (free preview).",
          parameters: [{ name: "domain", type: "string", description: "Domain to analyze (e.g. example.com)" }],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              latestPolicyIndexUrl: "https://example.com/privacy-policy",
              previewTextSnippet: "Privacy Policy This is the privacy statement...",
              previewTimestamp: "2024-06-01T12:00:00Z",
              note: "This preview retrieves latest policy text snippet. Paid diff and compliance analysis requires payment."
            },
            meta: {
              timestamp: "2024-06-01T12:15:00Z",
              duration_ms: 150,
              api_version: "1.0.0"
            }
          }
        },
        {
          method: "GET",
          path: "/diff",
          description: "Fetch privacy policy versions and compare them for compliance and changes.",
          parameters: [
            { name: "domain", type: "string", description: "Domain to analyze (e.g. example.com)" },
            { name: "oldUrl", type: "string", description: "Optional: direct URL of previous policy version" },
            { name: "newUrl", type: "string", description: "Optional: direct URL of current policy version" }
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              policyOld: { url: "https://example.com/privacy_policy", fetchedAt: "2023-12-01T10:00:00Z", rawText: "Older policy text..." },
              policyNew: { url: "https://example.com/privacy_policy", fetchedAt: "2024-05-01T10:00:00Z", rawText: "Newer policy text..." },
              diff: {
                fetchedAtOld: "2023-12-01T10:00:00Z",
                fetchedAtNew: "2024-05-01T10:00:00Z",
                changesSummary: "Added 3 paragraph(s), removed 1 paragraph(s), total changes 4",
                severityScore: 75,
                grade: "B",
                complianceSignals: [ { id: "compliance-improved", description: "New compliance-related addition.", severity: 70, scoreImpact: 15 } ],
                recommendations: [ { issue: "New compliance-related addition.", severity: 70, suggestion: "Ensure these statements are communicated..." } ],
                detailedChanges: []
              },
              analysisDate: "2024-06-01T12:30:00Z",
              processingTimeMs: 2200
            },
            meta: { timestamp: "2024-06-01T12:30:05Z", duration_ms: 2200, api_version: "1.0.0" }
          }
        }
      ],
      parameters: [
        { name: "domain", type: "string", description: "Domain name to analyze (e.g. example.com)" },
        { name: "oldUrl", type: "string", description: "(Optional) Previous policy URL to compare" },
        { name: "newUrl", type: "string", description: "(Optional) Current policy URL to compare" }
      ],
      examples: [
        "/preview?domain=example.com",
        "/diff?domain=example.com",
        "/diff?domain=example.com&oldUrl=https://example.com/privacy-2023.html&newUrl=https://example.com/privacy-2024.html"
      ]
    },
    pricing: {
      paidEndpoint: "/diff",
      price: PRICE,
      description: "Deep scan with extensive crawling, multi-layered policy text comparison, compliance scoring, and actionable recommendations.",
    }
  });
});

// Free preview (no payment needed)
app.get("/preview", async (c) => {
  const domain = c.req.query("domain");
  if (!domain || typeof domain !== "string") {
    return c.json({ error: "Missing ?domain= parameter (example.com)" }, 400);
  }
  if (domain.length > 253) {
    return c.json({ error: "Domain length exceeds maximum allowed" }, 400);
  }

  // Validate domain
  const validUrlCheck = validateExternalUrl(`https://${domain}`);
  if ("error" in validUrlCheck) {
    return c.json({ error: `Invalid domain: ${validUrlCheck.error}` }, 400);
  }

  try {
    const result = await previewFetchPolicy(domain.trim());
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms: result.processingTimeMs, api_version: "1.0.0" } });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, status);
  }
});

// Payment gating
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /diff": paidRouteWithDiscovery(
        PRICE,
        "Deep scan with multiple privacy policy fetches, NLP diff, compliance analysis, scoring, and recommendations.",
        {
          input: { domain: "example.com", oldUrl: "https://example.com/privacy-2023.html", newUrl: "https://example.com/privacy-2024.html" },
          inputSchema: {
            type: "object",
            properties: {
              domain: { type: "string", description: "Domain to analyze (example.com)" },
              oldUrl: { type: "string", description: "Optional older privacy policy URL" },
              newUrl: { type: "string", description: "Optional newer privacy policy URL" },
            },
            required: ["domain"],
          },
        },
      ),
    },
    resourceServer
  ),
);

// Paid deep diff with analysis
app.get("/diff", async (c) => {
  const domainRaw = c.req.query("domain");
  const oldUrlRaw = c.req.query("oldUrl");
  const newUrlRaw = c.req.query("newUrl");

  if (!domainRaw || typeof domainRaw !== "string") {
    return c.json({ error: "Missing ?domain= parameter (example.com)" }, 400);
  }
  if (domainRaw.length > 253) {
    return c.json({ error: "Domain length exceeds maximum allowed" }, 400);
  }

  try {
    const result = await fetchAndAnalyze(domainRaw.trim(), typeof oldUrlRaw === "string" ? oldUrlRaw.trim() : undefined, typeof newUrlRaw === "string" ? newUrlRaw.trim() : undefined);
    if ("error" in result) {
      return c.json({ error: result.error, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, 400);
    }
    const duration_ms = result.processingTimeMs || 0;
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, status);
  }
});

// Not found handler
app.notFound((c) => c.json({ error: "Not found" }, 404));

// Critical error handler: pass through HTTPExceptions for 402s
app.onError((err, c) => {
  if (typeof err === "object" && err !== null && "getResponse" in err) {
    return (err as any).getResponse();
  }
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

export { app };

if (import.meta.main) console.log(`${API_NAME} listening on port ${PORT}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
