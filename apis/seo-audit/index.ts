import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl } from "../../shared/ssrf";
import { auditFull, auditPreview } from "./auditor";

function sanitizeError(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  if (/^Only http|^Private|^Invalid URL|^URL returned non-HTML|^URL returned empty|^Too many redirect|^Response body too large/.test(msg)) return msg;
  return "Failed to fetch or process the URL";
}

const app = new Hono();
const API_NAME = "seo-audit";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.003";

// 1. CORS
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// 2. Health check BEFORE rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limits then logger
app.use("/check", rateLimit("seo-audit-check", 20, 60_000));
app.use("*", rateLimit("seo-audit", 60, 60_000));
app.use("*", apiLogger(API_NAME, 0.003));

// 4. Info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    docs: "GET /check?url={url}",
    pricing: `${PRICE} per call via x402`,
  });
});

// 5. Free preview BEFORE paymentMiddleware
app.get("/preview", rateLimit("seo-audit-preview", 15, 60_000), async (c) => {
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
    const result = await auditPreview(check.url.toString());
    return c.json(result);
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e?.message ?? e);
    return c.json({ error: sanitizeError(e) }, 502);
  }
});

// 6. Payment middleware
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive on-page SEO audit with title, meta, headings, images, links, structured data, and 0-100 score",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "URL to audit for on-page SEO" },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer,
  ),
);

// 7. Paid route
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
    const result = await auditFull(check.url.toString());
    return c.json(result);
  } catch (e: any) {
    if (typeof e === "object" && e !== null && "getResponse" in e) {
      return (e as any).getResponse();
    }
    console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, e?.message ?? e);
    return c.json({ error: sanitizeError(e) }, 502);
  }
});

// 8. Error handling - pass through x402 HTTPExceptions
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
