import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { checkPresence, checkDns } from "./checker";

const app = new Hono();
const API_NAME = "web-checker";
const PORT = 3001;

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health check — before rate limiter for localhost monitoring
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit: 20/min for /check (each spawns 9 outbound calls), 60/min global
app.use("/check", rateLimit("web-checker-check", 20, 60_000));
app.use("*", rateLimit("web-checker", 60, 60_000));
app.use("*", apiLogger(API_NAME, 0.005));

// Info endpoint — after rate limiter so it's metered
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    docs: "GET /check?name=yourname",
    pricing: "$0.005 per check via x402",
  });
});

// Free preview — .com domain check only (no payment required)
app.get("/preview", rateLimit("web-checker-preview", 30, 60_000), async (c) => {
  const name = c.req.query("name");
  if (!name) {
    return c.json({ error: "Provide ?name= parameter (2-50 alphanumeric characters)" }, 400);
  }

  const slug = name.toLowerCase().replace(/[^a-z0-9-]/g, "");
  if (slug.length < 2 || slug.length > 50) {
    return c.json({ error: "Name must contain 2-50 alphanumeric characters (a-z, 0-9, hyphen)" }, 400);
  }
  if (slug.startsWith("-") || slug.endsWith("-")) {
    return c.json({ error: "Name cannot start or end with a hyphen" }, 400);
  }

  const domainResult = await checkDns(`${slug}.com`);

  return c.json({
    query: slug,
    preview: true,
    results: [domainResult],
    checkedAt: new Date().toISOString(),
    note: "Preview checks .com only. Pay via x402 for full sweep across 5 TLDs + GitHub, npm, PyPI, Reddit.",
  });
});

app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        "$0.005",
        "Check brand/product name availability across domains, GitHub, npm, PyPI, Reddit",
        {
          input: { name: "example" },
          inputSchema: {
            properties: {
              name: { type: "string", description: "Brand/product name to check" },
            },
            required: ["name"],
          },
        }
      ),
    },
    resourceServer
  )
);

app.get("/check", async (c) => {
  const name = c.req.query("name");
  if (!name) {
    return c.json({ error: "Provide ?name= parameter (2-50 alphanumeric characters)" }, 400);
  }

  // Sanitize first, then validate the result
  const slug = name.toLowerCase().replace(/[^a-z0-9-]/g, "");

  if (slug.length < 2 || slug.length > 50) {
    return c.json({ error: "Name must contain 2-50 alphanumeric characters (a-z, 0-9, hyphen)" }, 400);
  }
  if (slug.startsWith("-") || slug.endsWith("-")) {
    return c.json({ error: "Name cannot start or end with a hyphen" }, 400);
  }

  const result = await checkPresence(slug);
  return c.json(result);
});

app.onError((err, c) => {
  // Let Hono's HTTPException (e.g. 402 from x402) pass through
  if ("getResponse" in err) return (err as any).getResponse();
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
