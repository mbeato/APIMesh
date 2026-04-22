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
import { validateExternalUrl } from "../../shared/ssrf";
import { fullEnrich, EnricherResult } from "./analyzer";

const app = new Hono();
const API_NAME = "privacy-policy-enricher";
const PORT = Number(process.env.PORT) || 3001;
const PRICE_STRING = "$0.01"; // Comprehensive audit price
const PRICE_NUMBER = 0.01;

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint (before rate limiting)
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limiting
app.use("/enrich", rateLimit("privacy-policy-enricher-enrich", 15, 60_000));
app.use("*", rateLimit("privacy-policy-enricher", 50, 60_000));

app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, PRICE_NUMBER));

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
          path: "/enrich",
          description: "Fetch and analyze privacy policy URL, combining multiple signals for GDPR and CCPA compliance, data sharing practices, and privacy features.",
          parameters: [
            {
              name: "url",
              type: "string",
              description: "Public URL of privacy policy page to analyze (HTTP or HTTPS).",
              required: true,
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com/privacy",
              gdprDetected: true,
              ccpaDetected: false,
              dataSharingPractices: {
                thirdPartyTrackersFound: true,
                sharedDataTypes: ["email", "ip address"],
                detail: "Privacy policy mentions sharing data with third parties such as advertising networks or analytics. Data types shared described: email, ip address.",
              },
              privacyFeatures: {
                cookieControlPresent: true,
                optOutMechanismPresent: true,
                encryptionMentioned: true,
                dataRetentionPolicyPresent: false,
                detail: "Cookie control present: true, opt-out mechanism: true, encryption mentioned: true, data retention policy: false.",
              },
              score: 85,
              grade: "B",
              recommendations: [
                {
                  issue: "Data retention policies missing",
                  severity: "medium",
                  suggestion: "Specify how long user data is retained and deletion procedures.",
                },
              ],
              explanation: "This privacy policy was analyzed for GDPR and CCPA compliance mentions, data sharing declarations, and key privacy features. GDPR-related information was found. No CCPA mentions detected. Third-party data sharing is present, with data types including: email, ip address. Key privacy features such as cookie control (true), opt-out mechanisms (true), encryption (true), and data retention policies (false) were evaluated.",
              checkedAt: "2024-06-01T12:00:00.000Z",
            },
            meta: {
              timestamp: "2024-06-01T12:00:01.234Z",
              duration_ms: 2500,
              api_version: "1.0.0",
            },
          },
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview shows whether GDPR or CCPA keywords are present.",
          parameters: [
            {
              name: "url",
              type: "string",
              description: "Public URL for privacy policy to preview-analyze.",
              required: true,
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              url: "https://example.com/privacy",
              gdprDetected: true,
              ccpaDetected: false,
              checkedAt: "2024-06-01T12:00:00.000Z",
            },
            meta: {
              timestamp: "2024-06-01T12:00:00.500Z",
              duration_ms: 500,
              api_version: "1.0.0",
            },
          },
        },
      ],
      parameters: [
        {
          name: "url",
          type: "string",
          description: "URL to a publicly accessible privacy policy page, HTTP or HTTPS",
          required: true,
        },
      ],
      examples: [
        "GET /enrich?url=https://example.com/privacy",
        "GET /preview?url=https://example.com/privacy"
      ],
    },
    pricing: {
      enrich: PRICE_STRING,
      preview: "$0 (free)"
    }
  })
);

// Free preview endpoint - basic keyword check only
app.get(
  "/preview",
  rateLimit("privacy-policy-enricher-preview", 20, 60_000),
  async (c) => {
    const rawUrl = c.req.query("url");
    if (!rawUrl || typeof rawUrl !== "string") {
      return c.json(
        { error: "Missing ?url= parameter (http(s)://...)" },
        400
      );
    }

    if (rawUrl.length > 2048) {
      return c.json({ error: "URL exceeds maximum length" }, 400);
    }

    const check = validateExternalUrl(rawUrl);
    if ("error" in check) {
      return c.json({ error: check.error }, 400);
    }

    const url = check.url.toString();

    // Fetch with longer timeout (20s)
    try {
      const res = await fetch(url, {
        signal: AbortSignal.timeout(20000),
        headers: { "User-Agent": "privacy-policy-enricher-preview/1.0 apimesh.xyz" },
      });
      if (!res.ok) {
        return c.json({ error: `HTTP error fetching ${url}: ${res.status}` }, 400);
      }

      const contentType = res.headers.get("content-type") || "";
      if (!contentType.includes("text/html")) {
        return c.json({
          error: `Expected text/html content-type but got ${contentType}`,
        }, 400);
      }

      // Read max 128kB body
      const maxBytes = 128 * 1024;
      const reader = res.body?.getReader();
      if (!reader) return c.json({ error: "No body reader available" }, 500);

      const chunks: Uint8Array[] = [];
      let readBytes = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          chunks.push(value);
          readBytes += value.length;
          if (readBytes >= maxBytes) break;
        }
      }

      const uint8All = new Uint8Array(readBytes);
      let offset = 0;
      for (const chunk of chunks) {
        uint8All.set(chunk, offset);
        offset += chunk.length;
      }
      const text = new TextDecoder("utf-8").decode(uint8All);

      // Basic extract text
      const cleanText = text.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, " ")
        .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/g, " ")
        .replace(/[\s\n\r]+/g, " ")
        .trim();

      const gdprDetected = GDPR_KEYWORDS.some(k => cleanText.toLowerCase().includes(k));
      const ccpaDetected = CCPA_KEYWORDS.some(k => cleanText.toLowerCase().includes(k));

      const duration_ms = 20000; // Approximated due to AbortSignal.timeout

      return c.json({
        status: "ok",
        data: {
          url,
          gdprDetected,
          ccpaDetected,
          checkedAt: new Date().toISOString(),
        },
        meta: {
          timestamp: new Date().toISOString(),
          duration_ms: duration_ms,
          api_version: "1.0.0",
        },
      });
    } catch (e: any) {
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
      "GET /enrich": paidRouteWithDiscovery(
        PRICE_STRING,
        "Fetches privacy policies from domains, analyzes GDPR/CCPA signals, data sharing, privacy features, with scoring, grading, and recommendations.",
        {
          input: { url: "https://example.com/privacy" },
          inputSchema: {
            properties: {
              url: {
                type: "string",
                description: "Public URL to the privacy policy page.",
              },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer
  )
);

app.get("/enrich", async (c) => {
  const rawUrl = c.req.query("url");

  if (!rawUrl || typeof rawUrl !== "string") {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }

  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  try {
    const result = await fullEnrich(rawUrl.trim());
    if ("error" in result) {
      return c.json({ error: result.error }, 400);
    }
    const duration_ms = 0; // The analyzer returns timestamps, avoid double counting
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Error handler, passes through x402 402 HTTPExceptions
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
