import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { safeFetch, validateExternalUrl } from "../../shared/ssrf";
import {
  analyzeSslTlsData,
  aggregateScanData,
  ScoreGrade,
  ThreatAssessmentResult,
  scanMultipleApis,
  previewAssessment,
} from "./threatAnalyzer";

const app = new Hono();
const API_NAME = "ssl-tls-threat-assessment";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUMBER = 0.01;

// CORS open to all origins first
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint (before rate limiter)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit:
// Preview endpoint (free) is less restrictive
app.use("/preview", rateLimit("ssl-tls-threat-assessment-preview", 15, 60_000));
// Main endpoints rate limit
app.use("/assess", rateLimit("ssl-tls-threat-assessment-assess", 30, 60_000));
app.use("*", rateLimit("ssl-tls-threat-assessment", 90, 60_000));

// Extract payer wallet for payment middleware
app.use("*", extractPayerWallet());

// API logger middleware with fixed price
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
          description: "Free preview assessment of SSL/TLS security for a domain/hostname.",
          parameters: [
            {
              name: "domain",
              required: true,
              description: "The domain or hostname to assess SSL/TLS configurations for",
              schema: { type: "string" },
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              sslProtocols: {
                tls1_2: true,
                tls1_3: true,
                sslv3: false,
              },
              cipherStrengthScore: 85,
              vulnerabilitiesFound: ["POODLE vulnerability not present"],
              overallScore: 82,
              overallGrade: "B",
              recommendations: [
                {
                  issue: "Deprecated support for TLS 1.0",
                  severity: "medium",
                  suggestion: "Disable TLS 1.0 and older protocols to improve security.",
                },
              ],
              explanation: "This domain supports modern TLS versions with strong ciphers. Disable legacy protocols for better security.",
            },
            meta: {
              timestamp: "2024-06-01T12:00:00Z",
              duration_ms: 150,
              api_version: "1.0.0"
            }
          }
        },
        {
          method: "GET",
          path: "/assess",
          description: "Comprehensive TLS security threat assessment for a domain. Requires payment.",
          parameters: [
            {
              name: "domain",
              required: true,
              description: "The domain or hostname to assess SSL/TLS configurations for",
              schema: { type: "string" },
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              domain: "example.com",
              sslProtocols: {
                sslv3: false,
                tls1_0: false,
                tls1_1: false,
                tls1_2: true,
                tls1_3: true
              },
              cipherSuites: [
                { name: "TLS_AES_128_GCM_SHA256", strength: 90 },
                { name: "ECDHE-RSA-AES128-GCM-SHA256", strength: 85 },
              ],
              knownVulnerabilities: ["Heartbleed: Not vulnerable"],
              overallScore: 93,
              overallGrade: "A",
              recommendations: [
                { issue: "No issues detected.", severity: "low", suggestion: "Maintain current configuration." }
              ],
              details: {
                cipherStrengthScore: 88,
                protocolSupportScore: 95,
                vulnerabilitiesScore: 100
              },
              explanation: "The SSL/TLS configuration is strong, supporting only TLS 1.2 and 1.3 with strong ciphers and no known critical vulnerabilities."
            },
            meta: {
              timestamp: "2024-06-01T12:01:14Z",
              duration_ms: 450,
              api_version: "1.0.0"
            }
          }
        }
      ],
      parameters: [
        { name: "domain", type: "string", required: true, description: "Hostname or domain to assess SSL/TLS security for" },
      ],
      examples: [
        "GET /preview?domain=example.com",
        "GET /assess?domain=example.com"
      ],
    },
    pricing: {
      preview: "Free",
      assess: PRICE,
      description: "Comprehensive audit with multiple data sources, scoring, grading, and actionable recommendations"
    }
  });
});

// --- Preview endpoint (free) ---
app.get("/preview", async (c) => {
  const domain = c.req.query("domain");
  if (!domain || typeof domain !== "string") {
    return c.json({ error: "Missing ?domain= parameter (example.com)" }, 400);
  }
  if (domain.length > 253) {
    return c.json({ error: "Domain parameter too long" }, 400);
  }

  try {
    const start = performance.now();
    const result = await previewAssessment(domain.trim());
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }

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

// --- Paid assessment endpoint ---
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /assess": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive SSL/TLS threat assessment combining multiple free scan sources with scoring, grading, and detailed recommendations",
        {
          input: { domain: "example.com" },
          inputSchema: {
            type: "object",
            properties: {
              domain: { type: "string", description: "Domain or hostname to assess" },
            },
            required: ["domain"],
          },
        },
      ),
    },
    resourceServer
  )
);

app.get("/assess", async (c) => {
  const domain = c.req.query("domain");
  if (!domain || typeof domain !== "string") {
    return c.json({ error: "Missing ?domain= parameter (example.com)" }, 400);
  }
  if (domain.length > 253) {
    return c.json({ error: "Domain parameter too long" }, 400);
  }

  try {
    const start = performance.now();
    const result = await scanMultipleApis(domain.trim());
    const duration_ms = Math.round(performance.now() - start);

    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }

    // Analyze and aggregate results into threat assessment
    const assessment = analyzeSslTlsData(result);

    return c.json({
      status: "ok",
      data: assessment,
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

// CRITICAL error handler to pass through HTTPExceptions like 402 from x402
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
