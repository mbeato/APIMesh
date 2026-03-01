import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { fullCheck, previewCheck } from "./checker";

const app = new Hono();
const API_NAME = "indexability";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.001";

// 1. CORS first
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// 2. Health before rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limits
app.use("/check", rateLimit("indexability-check", 30, 60_000));
app.use("*", rateLimit("indexability", 90, 60_000));

// 4. Logger
app.use("*", apiLogger(API_NAME, 0.001));

// 5. Info endpoint
app.get("/", (c) => c.json({
  api: API_NAME,
  status: "healthy",
  docs: "GET /check?url={url}",
  preview: "GET /preview?url={url} (free, limited checks)",
  pricing: `${PRICE} per call via x402`,
  checks: [
    "robots.txt — allowed/blocked for Googlebot",
    "HTTP status — 2xx/3xx/4xx/5xx classification",
    "Meta robots — noindex/nofollow directives",
    "X-Robots-Tag — HTTP header directives",
    "Canonical — self-referencing or pointing elsewhere",
  ],
}));

// 6. Free preview BEFORE paymentMiddleware
app.get("/preview", rateLimit("indexability-preview", 20, 60_000), async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  try {
    const result = await previewCheck(rawUrl.trim());
    if ("error" in result && !("preview" in result)) {
      return c.json({ error: result.error }, 400);
    }

    return c.json(result);
  } catch {
    return c.json({ error: "Internal server error" }, 500);
  }
});

// 7. Payment middleware
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Check if a URL is indexable by search engines — 5-layer analysis: robots.txt, HTTP status, meta robots, X-Robots-Tag, canonical",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string", description: "URL to check indexability for" },
            },
            required: ["url"],
          },
          output: {
            example: {
              indexable: true,
              blocking_reason: null,
              checks: {
                robots_txt: { allowed: true, reason: "No blocking rule found" },
                http_status: { status: 200, indexable: true },
                meta_robots: { found: false, noindex: false },
                x_robots_tag: { found: false, noindex: false },
                canonical: { found: true, isSelf: true },
              },
            },
          },
        },
      ),
    },
    resourceServer,
  ),
);

// 8. Paid route — full 5-layer check
app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing ?url= parameter (http(s)://...)" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  try {
    const result = await fullCheck(rawUrl.trim());
    if ("error" in result && !("checks" in result)) {
      return c.json({ error: result.error }, 400);
    }

    return c.json(result);
  } catch {
    return c.json({ error: "Internal server error" }, 500);
  }
});

// 9. Error handler — MUST pass through x402 HTTPExceptions
app.onError((err, c) => {
  if (typeof err === "object" && err !== null && "getResponse" in err) {
    return (err as any).getResponse();
  }
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

// 10. Not found
app.notFound((c) => c.json({ error: "Not found" }, 404));

export { app };

if (import.meta.main) console.log(`${API_NAME} listening on port ${PORT}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
