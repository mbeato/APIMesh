import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRoute, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { checkStatusCode } from "./status-checker";

const app = new Hono();
const API_NAME = "status-code-checker";
const PORT = Number(process.env.PORT) || 3001;
const PRICING = "$0.001";

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint (before rate limiter)
app.get("/health", c => c.json({ status: "ok" }));

// Specific rate limit for /check (bot/burst containment)
app.use("/check", rateLimit("status-code-checker-check", 30, 60_000)); // 30/min on /check
app.use("*", rateLimit("status-code-checker-global", 180, 60_000)); // 180/min all others
app.use("*", apiLogger(API_NAME, 0.001));

// Info endpoint (after rate limiter)
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    docs: "GET /check?url=https://site.com",
    pricing: `${PRICING} per check via x402`,
    subdomain: "status-code-checker.apimesh.xyz",
    description: "Checks the status code of any valid URL, returning accessibility and HTTP response info.",
    params: { url: "The URL to check. Required. Must include https:// or http://." },
    example: "/check?url=https://apimesh.xyz"
  });
});

app.use(
  paymentMiddleware(
    {
      "GET /check": paidRoute(
        PRICING,
        "Checks the HTTP status code of a given URL, returning accessibility and metadata."
      ),
    },
    resourceServer
  )
);

app.get("/check", async (c) => {
  const url = c.req.query("url");
  if (!url || typeof url !== "string" || url.length > 512) {
    return c.json({ error: "Provide ?url= parameter (2-512 chars)" }, 400);
  }

  // Validate URL: must be http(s), sensible domain
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
    if (!/^https?:$/.test(parsedUrl.protocol)) {
      return c.json({ error: "Only http and https URLs are supported." }, 400);
    }
    // Disallow localhost and 0.0.0.0-like addresses
    if (/(^localhost(\.|:|$))|^(127|0)\./.test(parsedUrl.hostname)) {
      return c.json({ error: "Local/internal addresses are not allowed." }, 400);
    }
    // Optionally block private subnet ranges (RFC1918)
    const privRanges = [
      /^10\./, /^192\.168\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./
    ];
    if (privRanges.some(r => r.test(parsedUrl.hostname))) {
      return c.json({ error: "Private network URLs are not allowed." }, 400);
    }
  } catch (e) {
    return c.json({ error: "Invalid URL: must include protocol (https://host)" }, 400);
  }

  const result = await checkStatusCode(parsedUrl.toString());
  return c.json(result);
});

app.onError((err, c) => {
  // Allow Hono HTTPExceptions (402, 429, etc) to pass
  if ("getResponse" in err) return (err as any).getResponse();
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

app.notFound((c) => c.json({ error: "Not found" }, 404));

export { app };

if (import.meta.main) {
  console.log(`${API_NAME} listening on port ${PORT}`);
}

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
