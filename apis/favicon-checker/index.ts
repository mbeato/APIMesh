import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRoute, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { checkFavicon } from "./checker";

const app = new Hono();
const API_NAME = "favicon-checker";
const PORT = Number(process.env.PORT) || 3001;

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health check — should be before rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// /check: 10 req/min/IP (favicon pulls), with 60/min global after
app.use("/check", rateLimit("favicon-checker-check", 10, 60_000));
app.use("*", rateLimit("favicon-checker", 60, 60_000));
app.use("*", apiLogger(API_NAME, 0.002));

// Info endpoint — open price and docs
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    docs: "GET /check?url=https://example.com",
    pricing: "$0.002 per /check via x402",
    example: "/check?url=https://bun.sh",
  });
});

// Paid endpoint
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRoute(
        "$0.002",
        "Check if a given website URL has a favicon, returns favicon's existence, URL, and HTTP status."
      ),
    },
    resourceServer
  )
);

app.get("/check", async (c) => {
  let url = c.req.query("url");
  if (!url) {
    return c.json({ error: "Missing ?url= (http(s)://...)" }, 400);
  }
  // Basic normalize
  url = url.trim();
  // Accept http/https only, strip fragment/query
  let parsed: URL | null = null;
  try {
    parsed = new URL(url);
  } catch {
    return c.json({ error: "Invalid URL" }, 400);
  }
  if (!/^https?:$/.test(parsed.protocol)) {
    return c.json({ error: "Only http(s):// URLs are allowed." }, 400);
  }
  // Remove fragment/query
  parsed.hash = "";
  parsed.search = "";

  // Don't allow localhost or private IPs (abuse guard)
  const hostname = parsed.hostname;
  if (/^(localhost|127\.|0\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/i.test(hostname)) {
    return c.json({ error: "Private or local addresses not allowed." }, 400);
  }

  try {
    const result = await checkFavicon(parsed.origin);
    return c.json(result);
  } catch (e: any) {
    if (typeof e === "object" && e && "getResponse" in e) {
      // Hono HTTPException (for e.g. PaymentRequired)
      //@ts-ignore
      return e.getResponse();
    }
    console.error(`[${new Date().toISOString()}] favicon-checker error:`, e);
    return c.json({ error: "Internal server error" }, 500);
  }
});

app.onError((err, c) => {
  if ("getResponse" in err) return (err as any).getResponse();
  console.error(`[${new Date().toISOString()}] favicon-checker error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

app.notFound((c) => c.json({ error: "Not found" }, 404));

export { app };

if (import.meta.main) console.log(`favicon-checker listening on port ${PORT}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
