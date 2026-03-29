import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl } from "../../shared/ssrf";
import { analyzeFullReport, analyzePreview } from "./analyzer";

const app = new Hono();
const API_NAME = "core-web-vitals";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.005";

// 1. CORS
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// 2. Health check BEFORE rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limits then logger
app.use("/check", rateLimit("core-web-vitals-check", 30, 60_000));
app.use("*", rateLimit("core-web-vitals", 90, 60_000));
app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, 0.005));

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
app.get("/preview", rateLimit("core-web-vitals-preview", 15, 60_000), async (c) => {
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
    const result = await analyzePreview(check.url.toString());
    return c.json(result);
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, msg);
    const status = msg.includes("timeout") || msg.includes("timed out") ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// 6. Payment middleware
app.use("*", spendCapMiddleware());
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Get Core Web Vitals, Lighthouse scores, and loading metrics for any URL",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "URL to check Core Web Vitals for" },
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
    const result = await analyzeFullReport(check.url.toString());
    return c.json(result);
  } catch (e: any) {
    if (typeof e === "object" && e !== null && "getResponse" in e) {
      return (e as any).getResponse();
    }
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, msg);
    const status = msg.includes("timeout") || msg.includes("timed out") ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
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
