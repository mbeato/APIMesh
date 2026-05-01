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
import { safeFetch, validateExternalUrl } from "../../shared/ssrf";
import {
  previewAssessment,
  fullAssessment,
  SubdomainRiskAssessmentResult,
} from "./analyzer";

const app = new Hono();
const API_NAME = "subdomain-risk-assessment";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUM = 0.01;

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits: more strict on check endpoint
app.use("/check", rateLimit("subdomain-risk-assessment-check", 10, 60_000));
app.use("*", rateLimit("subdomain-risk-assessment", 30, 60_000));

app.use("*", extractPayerWallet());
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
          path: "/preview?domain={domain}",
          description:
            "Free preview of subdomain enumeration and initial risk scoring",
          parameters: [
            {
              name: "domain",
              type: "string",
              description: "Root domain to analyze (e.g., example.com)",
              required: true,
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              subdomainsCount: 25,
              summary: {
                misconfigurations: 2,
                outdatedServices: 1,
                exposedEndpoints: 3,
                sensitiveExposure: 1,
              },
              score: 68,
              grade: "D",
              recommendations: [
                {
                  issue: "Exposed admin panel on sub.admin.example.com",
                  severity: 70,
                  suggestion: "Restrict access to admin panel via firewall or VPN",
                },
              ],
              details: "Preview limited to passive enumeration and basic checks.",
            },
            meta: {
              timestamp: "2024-01-01T00:00:00.000Z",
              duration_ms: 1380,
              api_version: "1.0.0",
            },
          },
        },
        {
          method: "GET",
          path: "/check?domain={domain}",
          description: "Comprehensive subdomain enumeration and security risk analysis",
          parameters: [
            {
              name: "domain",
              type: "string",
              description: "Root domain to analyze (e.g., example.com)",
              required: true,
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              subdomainsCount: 68,
              detailedSubdomains: [
                {
                  subdomain: "beta.example.com",
                  ip: "192.0.2.45",
                  misconfigurations: ["CORS wildcard enabled"],
                  outdatedService: "Apache 2.2",
                  exposedEndpoints: ["/debug"],
                  sensitiveExposure: false,
                },
              ],
              score: 80,
              grade: "B",
              recommendations: [
                {
                  issue: "Outdated Apache version detected",
                  severity: 65,
                  suggestion:
                    "Upgrade Apache to latest stable version to patch vulnerabilities",
                },
              ],
              details: "Includes passive and active enumeration, multi-source correlation, and heuristic-based risk scoring.",
            },
            meta: {
              timestamp: "2024-01-01T00:00:00.000Z",
              duration_ms: 7025,
              api_version: "1.0.0",
            },
          },
        },
      ],
      parameters: [
        {
          name: "domain",
          type: "string",
          description: "Root domain to analyze. No protocol or path, e.g., example.com",
          required: true,
        },
      ],
      examples: [
        {
          request: "GET /preview?domain=example.com",
          description: "Free preview of subdomain risks",
        },
        {
          request: "GET /check?domain=example.com",
          description: "Paid comprehensive subdomain risk assessment",
        },
      ],
    },
    pricing: {
      preview: "Free, limited checks",
      fullCheck: PRICE,
      currency: "USD",
      paymentMethods: ["x402", "MPP"],
      note: "Price per call depends on analysis depth",
    },
  });
});

// Free preview endpoint - generous timeout 20s
app.get(
  "/preview",
  rateLimit("subdomain-risk-assessment-preview", 15, 60_000),
  async (c) => {
    const rawDomain = c.req.query("domain");
    if (!rawDomain || typeof rawDomain !== "string") {
      return c.json({ error: "Missing ?domain= parameter" }, 400);
    }

    if (rawDomain.length > 253) {
      return c.json({ error: "Domain length exceeds maximum allowed" }, 400);
    }

    // Basic validation: domain only, no protocol or paths
    const domain = rawDomain.trim().toLowerCase();
    if (!/^[a-z0-9.-]+$/.test(domain) || domain.startsWith("-") || domain.endsWith("-") || domain.includes("..") || domain.startsWith(".") || domain.endsWith(".")) {
      return c.json({ error: "Invalid domain format" }, 400);
    }

    try {
      const result = await previewAssessment(domain);
      return c.json(result);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
      return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
    }
  }
);

app.use("*", spendCapMiddleware());

app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive subdomain enumeration and risk analysis combining DNS, certificate transparency, and heuristic scanning",
        {
          input: { domain: "example.com" },
          inputSchema: {
            properties: {
              domain: { type: "string", description: "Root domain for assessment" },
            },
            required: ["domain"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid full subdomain risk assessment
app.get("/check", async (c) => {
  const rawDomain = c.req.query("domain");
  if (!rawDomain || typeof rawDomain !== "string") {
    return c.json({ error: "Missing ?domain= parameter" }, 400);
  }

  if (rawDomain.length > 253) {
    return c.json({ error: "Domain length exceeds maximum allowed" }, 400);
  }

  const domain = rawDomain.trim().toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(domain) || domain.startsWith("-") || domain.endsWith("-") || domain.includes("..") || domain.startsWith(".") || domain.endsWith(".")) {
    return c.json({ error: "Invalid domain format" }, 400);
  }

  try {
    const result = await fullAssessment(domain);
    return c.json(result);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// OnError handler - passes through HTTPExceptions (e.g. 402)
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
