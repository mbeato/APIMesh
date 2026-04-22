import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl, safeFetch } from "../../shared/ssrf";
import {
  analyzeSpecLint,
  analyzeImplementationLint,
  analyzeConsistencyLint,
  LintCheckResult,
  ApiLintingResult,
  LintLetterGrade,
  LintIssue,
} from "./linting";

const app = new Hono();
const API_NAME = "api-linting";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // comprehensive audit price
const PRICE_NUM = 0.01; // float price for apiLogger

// 1. CORS
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// 2. /health BEFORE rateLimiter
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limits
app.use("/lint", rateLimit("api-linting-lint", 20, 60_000));
app.use("*", rateLimit("api-linting", 60, 60_000));

// 4. extract payer wallet + 5. apiLogger
app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// 6. info endpoint
app.get("/", (c) => {
  // Compose docs
  const docs = {
    endpoints: [
      {
        method: "GET",
        path: "/lint",
        description: "Run a comprehensive linting and validation on provided OpenAPI spec and implementation URLs.",
        parameters: [
          {
            name: "spec_url",
            type: "string",
            description: "URL to the OpenAPI specification document (JSON or YAML).",
            required: true
          },
          {
            name: "impl_url",
            type: "string",
            description: "URL to the live API endpoint to test actual implementation.",
            required: true
          }
        ],
        example_response: {
          status: "ok",
          data: {
            overallScore: 85,
            overallGrade: "B",
            checks: [
              { type: "spec", score: 90, grade: "A", issues: [] },
              { type: "implementation", score: 80, grade: "B", issues: [] },
              { type: "consistency", score: 85, grade: "B", issues: [] }
            ],
            recommendations: [
              { issue: "Add missing descriptions to endpoints.", severity: 50, suggestion: "Provide detailed descriptions for all API paths and parameters." }
            ]
          },
          meta: { timestamp: "2024-06-01T12:00:00Z", duration_ms: 2500, api_version: "1.0.0" }
        }
      },
      {
        method: "GET",
        path: "/preview",
        description: "Free preview of spec lint issues on a given OpenAPI spec URL.",
        parameters: [
          {
            name: "spec_url",
            type: "string",
            description: "URL to the OpenAPI specification document (JSON or YAML).",
            required: true
          }
        ],
        example_response: {
          status: "ok",
          data: {
            overallScore: 75,
            overallGrade: "C",
            checks: [
              { type: "spec", score: 75, grade: "C", issues: [] }
            ],
            recommendations: [
              { issue: "Some endpoints have missing examples.", severity: 60, suggestion: "Add example request and response bodies to improve client understanding." }
            ]
          },
          meta: { timestamp: "2024-06-01T12:00:00Z", duration_ms: 1200, api_version: "1.0.0" }
        }
      }
    ],
    parameters: [
      {
        name: "spec_url",
        type: "string",
        description: "URL to OpenAPI spec, JSON or YAML format, max 2048 chars."
      },
      {
        name: "impl_url",
        type: "string",
        description: "URL to live API endpoint to test implementation, max 2048 chars."
      }
    ],
    examples: [
      {
        endpoint: "/lint",
        description: "Complete linting with both spec and implementation analysis.",
        example_request: "/lint?spec_url=https://example.com/openapi.json&impl_url=https://api.example.com",
        example_response: "see endpoints[0].example_response"
      },
      {
        endpoint: "/preview",
        description: "Free spec lint preview with fewer checks.",
        example_request: "/preview?spec_url=https://example.com/openapi.yaml",
        example_response: "see endpoints[1].example_response"
      }
    ],
  };

  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs,
    pricing: {
      preview: "FREE",
      paid: {
        endpoint: "/lint",
        price: PRICE,
        description: "Comprehensive linting of API spec and implementation combining multiple analyses with actionable recommendations."
      }
    }
  });
});

// 7. Free preview BEFORE payment middleware
app.get("/preview", rateLimit("api-linting-preview", 15, 60_000), async (c) => {
  const rawSpecUrl = c.req.query("spec_url");
  if (!rawSpecUrl || typeof rawSpecUrl !== "string") {
    return c.json({ error: "Missing required ?spec_url= parameter with full http(s):// URL" }, 400);
  }
  if (rawSpecUrl.length > 2048) {
    return c.json({ error: "spec_url exceeds maximum length of 2048 characters" }, 400);
  }

  const check = validateExternalUrl(rawSpecUrl.trim());
  if ("error" in check) {
    return c.json({ error: check.error }, 400);
  }

  const start = performance.now();

  try {
    const result = await analyzeSpecLint(check.url.toString());
    const duration_ms = Math.round(performance.now() - start);
    return c.json({
      status: "ok",
      data: result,
      meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" }
    });
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 8. Payment middleware
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /lint": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive linting combining OpenAPI spec validation, live endpoint checks, and consistency validation with scoring and actionable fixes",
        {
          input: { spec_url: "https://example.com/openapi.json", impl_url: "https://api.example.com" },
          inputSchema: {
            type: "object",
            properties: {
              spec_url: { type: "string", description: "URL to OpenAPI spec JSON/YAML" },
              impl_url: { type: "string", description: "URL to live API endpoint for implementation checking" },
            },
            required: ["spec_url", "impl_url"],
          },
        },
      ),
    },
    resourceServer,
  ),
);

// 9. Paid route
app.get("/lint", async (c) => {
  const rawSpecUrl = c.req.query("spec_url");
  const rawImplUrl = c.req.query("impl_url");
  if (!rawSpecUrl || typeof rawSpecUrl !== "string" || !rawImplUrl || typeof rawImplUrl !== "string") {
    return c.json({ error: "Missing required ?spec_url= and ?impl_url= parameters with valid URLs" }, 400);
  }
  if (rawSpecUrl.length > 2048 || rawImplUrl.length > 2048) {
    return c.json({ error: "spec_url or impl_url parameter exceeds maximum length of 2048 characters" }, 400);
  }

  // Validate URLs
  const checkSpec = validateExternalUrl(rawSpecUrl.trim());
  if ("error" in checkSpec) {
    return c.json({ error: `Invalid spec_url: ${checkSpec.error}` }, 400);
  }
  const checkImpl = validateExternalUrl(rawImplUrl.trim());
  if ("error" in checkImpl) {
    return c.json({ error: `Invalid impl_url: ${checkImpl.error}` }, 400);
  }

  const start = performance.now();

  try {
    // Run the three major lint analyses in parallel with timeout
    // 10s timeout on each safeFetch inside analyze functions
    const [specLint, implLint, consistencyLint] = await Promise.all([
      analyzeSpecLint(checkSpec.url.toString()),
      analyzeImplementationLint(checkImpl.url.toString()),
      analyzeConsistencyLint(checkSpec.url.toString(), checkImpl.url.toString()),
    ]);

    // Combine scores by weighted average
    // SpecLint 35%, ImplLint 40%, Consistency 25%
    const weightedScore = Math.round(
      specLint.overallScore * 0.35 + implLint.overallScore * 0.4 + consistencyLint.overallScore * 0.25
    );

    // Compute letter grade for overall
    const overallGrade = computeLetterGrade(weightedScore);

    // Aggregate all issues and recommendations
    const allIssues: LintIssue[] = [
      ...specLint.issues,
      ...implLint.issues,
      ...consistencyLint.issues,
    ];

    const allRecommendations = [
      ...specLint.recommendations,
      ...implLint.recommendations,
      ...consistencyLint.recommendations,
    ];

    const result: ApiLintingResult = {
      overallScore: weightedScore,
      overallGrade,
      checks: [
        { type: "spec", score: specLint.overallScore, grade: specLint.overallGrade, issues: specLint.issues },
        { type: "implementation", score: implLint.overallScore, grade: implLint.overallGrade, issues: implLint.issues },
        { type: "consistency", score: consistencyLint.overallScore, grade: consistencyLint.overallGrade, issues: consistencyLint.issues },
      ],
      recommendations: allRecommendations,
    };

    const duration_ms = Math.round(performance.now() - start);

    return c.json({
      status: "ok",
      data: result,
      meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" },
    });
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} lint error:`, e);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 10. Error handler with 402 pass-through
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

// Helper function
function computeLetterGrade(score: number): LintLetterGrade {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}
