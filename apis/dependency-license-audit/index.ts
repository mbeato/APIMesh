import { Hono } from "hono";
import { cors } from "hono/cors";
import {
  paymentMiddleware,
  paidRouteWithDiscovery,
  resourceServer,
} from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { validateExternalUrl, safeFetch, readBodyCapped } from "../../shared/ssrf";
import {
  runDependencyLicenseAudit,
  DependencyLicenseAuditResult,
  DependencyLicensePreviewResult
} from "./analyzer";

const app = new Hono();
const API_NAME = "dependency-license-audit";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit, 5+ checks, detailed report
const PRICE_NUM = 0.01;

// CORS open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint (before rate limiting)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limiting
app.use("/audit", rateLimit("dependency-license-audit-audit", 20, 60_000));
app.use("*", rateLimit("dependency-license-audit", 60, 60_000));

// Extract wallet then log API usage
app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// Info endpoint - describes the API, docs and pricing
app.get("/", (c) =>
  c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/",
          description: "API info, usage guide, pricing and documentation",
          parameters: [],
          example_response: {
            api: API_NAME,
            status: "healthy",
            version: "1.0.0",
            docs: { endpoints: [], parameters: [], examples: [] },
            pricing: { audit: PRICE },
          },
        },
        {
          method: "GET",
          path: "/preview",
          description: "Preview analysis for a project manifest file URL (FREE, headers only, limited checks)",
          parameters: [
            {
              name: "manifest_url",
              type: "string",
              description: "Public URL to fetch a project dependency manifest (package.json, requirements.txt, etc.)",
              required: true,
            },
          ],
          example_response: {
            status: "ok",
            data: {
              manifest_url: "https://raw.githubusercontent.com/user/repo/main/package.json",
              licenses_found: [
                { name: "MIT", occurrences: 15 },
                { name: "Apache-2.0", occurrences: 3 }
              ],
              summary: {
                total_dependencies: 20,
                unique_licenses: 2,
                high_risk_count: 0
              },
              explanations: "Preview fetched manifest and identified license types with summary.",
            },
            meta: {
              timestamp: "2024-01-01T00:00:00.000Z",
              duration_ms: 100,
              api_version: "1.0.0"
            },
          },
        },
        {
          method: "GET",
          path: "/audit",
          description: "Perform a comprehensive license audit on multiple project manifests and license databases",
          parameters: [
            {
              name: "manifest_urls",
              type: "string",
              description: "Comma-separated list of public URLs to project manifest files (package.json, requirements.txt, pom.xml, etc.)",
              required: true,
            },
            {
              name: "includeDev",
              type: "boolean",
              description: "Optional flag to include devDependencies or test dependencies",
              required: false,
            }
          ],
          example_response: {
            status: "ok",
            data: {
              scanned_manifests: 3,
              total_dependencies: 154,
              license_counts: { MIT: 80, BSD_3_Clause: 30, GPL_3_0: 2, Proprietary: 5 },
              risk_score: 12.5,
              grade: "B",
              recommendations: [
                { issue: "GPL-3.0 dependencies detected", severity: 70, suggestion: "Consider replacing with permissive licenses to avoid viral constraints." },
                { issue: "5 packages with Proprietary licenses", severity: 50, suggestion: "Review license terms for commercial use compliance." }
              ],
              details: "Detailed license mapping across manifests with risk scoring and actionable recommendations."
            },
            meta: {
              timestamp: "2024-01-01T00:00:00.000Z",
              duration_ms: 1423,
              api_version: "1.0.0"
            }
          }
        }
      ],
      parameters: [
        { name: "manifest_url", description: "URL to a project manifest file (package.json, requirements.txt, etc.)", type: "string" },
        { name: "manifest_urls", description: "Comma-separated URLs to multiple manifests", type: "string" },
        { name: "includeDev", description: "Boolean flag to include dev/test dependencies", type: "boolean" }
      ],
      examples: [
        "GET /preview?manifest_url=https://raw.githubusercontent.com/user/repo/main/package.json",
        "GET /audit?manifest_urls=https://path/package.json,https://path2/requirements.txt&includeDev=true"
      ]
    },
    pricing: { audit: PRICE },
  })
);

// Free Preview - lightweight check for one manifest URL
app.get("/preview", rateLimit("dependency-license-audit-preview", 15, 120_000), async (c) => {
  const rawUrl = c.req.query("manifest_url");
  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing ?manifest_url= parameter with a valid URL" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const check = validateExternalUrl(rawUrl.trim());
  if ("error" in check) {
    return c.json({ error: check.error }, 400);
  }

  try {
    const start = performance.now();
    const result = await runDependencyLicenseAudit(check.url.toString(), { previewOnly: true });
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e?.message ?? e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Payment & Spend Cap Middlewares
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /audit": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive license audit combining multiple manifests, public license databases, scoring, grading, and actionable recommendations",
        {
          input: {
            manifest_urls: "https://example.com/package.json,https://example.com/requirements.txt",
            includeDev: false
          },
          inputSchema: {
            properties: {
              manifest_urls: {
                type: "string",
                description: "Comma-separated list of URLs to manifest files (package.json, requirements.txt, etc.)",
              },
              includeDev: {
                type: "boolean",
                description: "Include development/test dependencies in audit",
              },
            },
            required: ["manifest_urls"],
          },
        },
      ),
    },
    resourceServer,
  ),
);

interface AuditQuery {
  manifest_urls?: string;
  includeDev?: string;
}

// Paid route - perform full dependency license audit
app.get("/audit", async (c) => {
  const query = c.req.query() as AuditQuery;
  if (!query.manifest_urls || typeof query.manifest_urls !== "string") {
    return c.json({ error: "Missing required ?manifest_urls= parameter with one or more URLs" }, 400);
  }

  const includeDev = query.includeDev === "true";

  const rawUrls = query.manifest_urls.split(",").map((s) => s.trim()).filter(Boolean);
  if (rawUrls.length === 0) {
    return c.json({ error: "No valid manifest URLs provided" }, 400);
  }

  // Validate all URLs early
  const validatedUrls = [] as URL[];
  for (const raw of rawUrls) {
    const check = validateExternalUrl(raw);
    if ("error" in check) {
      return c.json({ error: `Invalid URL ${raw}: ${check.error}` }, 400);
    }
    validatedUrls.push(check.url);
  }

  try {
    const start = performance.now();
    const result = await runDependencyLicenseAudit(validatedUrls.map(u => u.toString()), { includeDev, previewOnly: false });
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: any) {
    if (typeof e === "object" && e !== null && "getResponse" in e) {
      return (e as any).getResponse();
    }
    console.error(`[${new Date().toISOString()}] ${API_NAME} audit error:`, e?.message ?? e);
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
