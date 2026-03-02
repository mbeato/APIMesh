import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl } from "../../shared/ssrf";
import { detectFull, detectPreview } from "./detector";

function sanitizeError(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  if (/^Only http|^Private|^Invalid URL|^URL returned|^Too many redirect|^Response body too large/.test(msg)) return msg;
  return "Failed to fetch or process the URL";
}

const app = new Hono();
const API_NAME = "tech-stack";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.003";

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health check — before rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits
app.use("/check", rateLimit("tech-stack-check", 15, 60_000));
app.use("*", rateLimit("tech-stack", 60, 60_000));
app.use("*", apiLogger(API_NAME, 0.003));

// Info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    docs: "GET /check?url={url}",
    preview: "GET /preview?url={url} (free, HTTP headers only)",
    pricing: `${PRICE} per call via x402`,
  });
});

// Free preview — headers only (HEAD request)
app.get("/preview", rateLimit("tech-stack-preview", 15, 60_000), async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (provide a full http(s):// URL)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const check = validateExternalUrl(rawUrl.trim());
  if ("error" in check) {
    return c.json({ error: check.error }, 400);
  }

  try {
    const result = await detectPreview(check.url.toString());
    return c.json({
      ...result,
      preview: true,
      note: "Preview detects technologies from HTTP headers only. Pay via x402 for full HTML analysis with CMS, framework, and library detection.",
    });
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e?.message ?? e);
    return c.json({ error: sanitizeError(e) }, 502);
  }
});

// x402 payment gate — only /check is paid
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Detect website technology stack: CMS, frameworks, languages, analytics, CDN, hosting, and more from HTTP headers and HTML analysis",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "URL to analyze for technology stack" },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer,
  ),
);

// Paid full check
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (provide a full http(s):// URL)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const check = validateExternalUrl(rawUrl.trim());
  if ("error" in check) {
    return c.json({ error: check.error }, 400);
  }

  try {
    const result = await detectFull(check.url.toString());
    return c.json(result);
  } catch (e: any) {
    if (typeof e === "object" && e !== null && "getResponse" in e) {
      return (e as any).getResponse();
    }
    console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, e?.message ?? e);
    return c.json({ error: sanitizeError(e) }, 502);
  }
});

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
