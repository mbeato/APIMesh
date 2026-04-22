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
import { enumerateAndAnalyze, previewEnumeration, type HeatmapPreviewResult, type HeatmapAuditResult } from "./analyzer";

const app = new Hono();
const API_NAME = "subdomain-exposure-heatmap";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit (5+ checks, scoring, report)
const PRICE_NUM = 0.01;

// --- CORS ---
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// --- Health check ---
app.get("/health", (c) => c.json({ status: "ok" }));

// --- Rate limiting (stronger on main audit due to resource requirements) ---
app.use("/heatmap", rateLimit("subdomain-exposure-heatmap-heatmap", 5, 60_000));
app.use("*", rateLimit("subdomain-exposure-heatmap", 30, 60_000));

// --- Wallet extraction and request logging ---
app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// --- Info endpoint
app.get("/", (c) => c.json({
  api: API_NAME,
  status: "healthy",
  version: "1.0.0",
  docs: {
    endpoints: [
      {
        method: "GET",
        path: "/preview",
        description: "Free preview of possible subdomains and initial surface, lightweight enumeration only.",
        parameters: [
          { name: "domain", type: "string", description: "Root domain to enumerate (e.g. example.com)" }
        ],
        example_response: {
          status: "ok",
          data: {
            domain: "example.com",
            foundSubdomains: ["www", "mail", "dev"],
            total: 3,
            note: "Preview: lightweight search on public sources only; pay for exhaustive scan and exposure heatmap."
          },
          meta: {
            timestamp: "2023-01-01T00:00:00.000Z",
            duration_ms: 654,
            api_version: "1.0.0"
          }
        },
      },
      {
        method: "GET",
        path: "/heatmap",
        description: "Paid: Exhaustive subdomain enumeration from multiple sources, risk analysis, exposure scoring, recommendations and heatmap report.",
        parameters: [
          { name: "domain", type: "string", description: "Root domain to audit (e.g. example.com)" }
        ],
        example_response: {
          status: "ok",
          data: {
            domain: "example.com",
            totalSubdomains: 18,
            riskScore: 76,
            letterGrade: "C",
            subdomains: [
              { name: "mail.example.com", exposureLevel: 80, grade: "C", issues: ["SMTP banner leak", "Open port 25"] },
              { name: "test.example.com", exposureLevel: 95, grade: "F", issues: ["HTTP listed, no SSL", "Default Apache page"] }
            ],
            explanation: "18 subdomains found. 3 are legacy, 2 are high-risk, several return error responses. Multiple endpoints with security misconfigurations.",
            recommendations: [
              {
                issue: "Legacy endpoint 'dev.example.com' is exposed.",
                severity: "high",
                suggestion: "Decommission or protect legacy subdomains, restrict access via firewall/VPN."
              }
            ]
          },
          meta: {
            timestamp: "2023-01-01T00:00:00.000Z",
            duration_ms: 1934,
            api_version: "1.0.0"
          }
        },
      }
    ],
    parameters: [
      { name: "domain", type: "string", description: "Root domain to check (e.g. example.com)" }
    ],
    examples: [
      { path: "/preview?domain=example.com" },
      { path: "/heatmap?domain=example.com" }
    ]
  },
  pricing: {
    "/preview": "FREE",
    "/heatmap": PRICE
  }
}));

// --- Preview: free, lightweight subdomain enumeration ---
app.get("/preview", rateLimit("subdomain-exposure-heatmap-preview", 10, 60_000), async (c) => {
  const domain = c.req.query("domain");
  if (!domain) {
    return c.json({ error: "Missing ?domain= parameter (e.g. example.com)" }, 400);
  }
  if (typeof domain !== "string" || domain.length > 255) {
    return c.json({ error: "Domain name too long" }, 400);
  }
  const start = performance.now();
  try {
    const result: HeatmapPreviewResult = await previewEnumeration(domain.trim());
    const duration_ms = Math.round(performance.now() - start);
    return c.json({ status: "ok", data: result, meta: {
      timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0"
    }});
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ status: "error", error: "Analysis temporarily unavailable", detail: msg, meta: {
      timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0"
    } }, status);
  }
});

// ---- Payment middleware ----
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /heatmap": paidRouteWithDiscovery(
        PRICE,
        "Enumerate all public subdomains, perform exposure risk analysis with scoring, grading, and actionable recommendations.",
        {
          input: { domain: "example.com" },
          inputSchema: {
            properties: {
              domain: { type: "string", description: "Root domain" },
            },
            required: ["domain"],
          },
        },
      ),
    },
    resourceServer
  ),
);

// --- Paid: Deep enumeration, risk scoring, full heatmap ---
app.get("/heatmap", async (c) => {
  const domain = c.req.query("domain");
  if (!domain) {
    return c.json({ error: "Missing ?domain= parameter (e.g. example.com)" }, 400);
  }
  if (typeof domain !== "string" || domain.length > 255) {
    return c.json({ error: "Domain name too long" }, 400);
  }
  const start = performance.now();
  try {
    const result: HeatmapAuditResult = await enumerateAndAnalyze(domain.trim());
    const duration_ms = Math.round(performance.now() - start);
    return c.json({ status: "ok", data: result, meta: {
      timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0"
    }});
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ status: "error", error: "Analysis temporarily unavailable", detail: msg, meta: {
      timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0"
    } }, status);
  }
});

// --- OnError (pass through HTTPException for x402 402s) ---
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
