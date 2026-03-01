import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { fullAudit, previewAudit } from "./analyzer";

const app = new Hono();
const API_NAME = "security-headers";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.005";

// CORS first
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health before rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits then logger
app.use("/check", rateLimit("security-headers-check", 30, 60_000));
app.use("*", rateLimit("security-headers", 90, 60_000));
app.use("*", apiLogger(API_NAME, 0.005));

// Info endpoint
app.get("/", (c) => c.json({
  api: API_NAME,
  status: "healthy",
  docs: "GET /check?url={url}",
  pricing: `${PRICE} per call via x402`,
}));

// Free preview BEFORE paymentMiddleware
app.get("/preview", rateLimit("security-headers-preview", 15, 60_000), async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  try {
    const result = await previewAudit(rawUrl.trim());
    if ("error" in result && !("preview" in result)) {
      return c.json({ error: result.error }, 400);
    }
    return c.json(result);
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} preview error:`, e);
    return c.json({ error: "Failed to analyze URL" }, 502);
  }
});

// Payment middleware
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Audit HTTP security headers of any URL with A+ to F grading, CSP parsing, and remediation suggestions",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "URL to audit security headers for" },
            },
            required: ["url"],
          },
        },
      ),
    },
    resourceServer,
  ),
);

// Paid route
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  try {
    const result = await fullAudit(rawUrl.trim());
    if ("error" in result && !("headers" in result)) {
      return c.json({ error: result.error }, 400);
    }
    return c.json(result);
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] ${API_NAME} check error:`, e);
    return c.json({ error: "Failed to analyze URL" }, 502);
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
