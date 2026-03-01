import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { validateDomain, previewExtract, fullExtract } from "./extractor";

const app = new Hono();
const API_NAME = "brand-assets";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.002";

// 1. CORS
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// 2. Health check — before rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limits
app.use("/check", rateLimit("brand-assets-check", 30, 60_000));
app.use("*", rateLimit("brand-assets", 90, 60_000));

// 4. API logger
app.use("*", apiLogger(API_NAME, 0.002));

// 5. Info endpoint
app.get("/", (c) => c.json({
  api: API_NAME,
  status: "healthy",
  docs: "GET /check?domain=example.com — full brand asset extraction",
  preview: "GET /preview?domain=example.com — free preview (favicon + theme-color)",
  pricing: `${PRICE} per /check via x402`,
  example: "/check?domain=github.com",
}));

// 6. Free preview — BEFORE paymentMiddleware, with its own rate limit
app.get("/preview", rateLimit("brand-assets-preview", 20, 60_000), async (c) => {
  const rawDomain = c.req.query("domain");
  if (!rawDomain) {
    return c.json({ error: "Missing ?domain= parameter (bare domain, e.g. example.com)" }, 400);
  }
  if (rawDomain.length > 253) {
    return c.json({ error: "Domain exceeds maximum length" }, 400);
  }

  const check = validateDomain(rawDomain);
  if ("error" in check) {
    return c.json({ error: check.error }, 400);
  }

  const result = previewExtract(check.domain);
  return c.json(result);
});

// 7. Payment middleware
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Extract brand assets (logo, favicon, colors, og:image, site name) from any domain",
        {
          input: { domain: "github.com" },
          inputSchema: {
            properties: {
              domain: { type: "string", description: "Bare domain to extract brand assets from (e.g. github.com)" },
            },
            required: ["domain"],
          },
          output: {
            example: {
              domain: "github.com",
              logo: "https://github.githubassets.com/favicons/favicon.svg",
              favicon: { url: "https://github.githubassets.com/favicons/favicon.svg", format: "svg" },
              colors: { primary: "#1f6feb", secondary: null },
              theme_color: "#1e2327",
              og_image: "https://github.githubassets.com/images/modules/site/social-cards/campaign-social.png",
              site_name: "GitHub",
            },
          },
        },
      ),
    },
    resourceServer,
  ),
);

// 8. Paid route — full extraction
app.get("/check", async (c) => {
  const rawDomain = c.req.query("domain");
  if (!rawDomain) {
    return c.json({ error: "Missing ?domain= parameter (bare domain, e.g. example.com)" }, 400);
  }
  if (rawDomain.length > 253) {
    return c.json({ error: "Domain exceeds maximum length" }, 400);
  }

  const check = validateDomain(rawDomain);
  if ("error" in check) {
    return c.json({ error: check.error }, 400);
  }

  try {
    const result = await fullExtract(check.domain);
    return c.json(result);
  } catch (e: any) {
    if (typeof e === "object" && e !== null && "getResponse" in e) {
      return e.getResponse();
    }
    console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, e);
    return c.json({ error: "Extraction failed" }, 500);
  }
});

// 9. Error handler — MUST pass through x402 HTTPExceptions
app.onError((err, c) => {
  if (typeof err === "object" && err !== null && "getResponse" in err) return (err as any).getResponse();
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Unexpected error processing request" }, 500);
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
