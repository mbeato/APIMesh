import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRoute, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { analyzeUserAgent, type UserAgentResult } from "./parser";

const app = new Hono();
const API_NAME = "user-agent-analyzer";
const PRICE = 0.002; // $0.002 per call
const PRICE_LABEL = "$0.002 per analysis via x402";
const PORT = Number(process.env.PORT) || 3001;

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint before rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits (20/min endpoint, 60/min global).
app.use("/analyze", rateLimit(API_NAME + "-analyze", 20, 60_000));
app.use("*", rateLimit(API_NAME, 60, 60_000));
app.use("*", apiLogger(API_NAME, PRICE));

// Info endpoint
app.get("/", (c) =>
  c.json({
    api: API_NAME,
    status: "healthy",
    docs: "GET /analyze?ua=User-Agent or set User-Agent HTTP header",
    pricing: PRICE_LABEL,
    subdomain: "user-agent-analyzer.apimesh.xyz",
    example: { usage: "/analyze?ua=Mozilla/5.0 ..." },
  })
);

app.use(
  paymentMiddleware(
    {
      "GET /analyze": paidRoute(
        "$0.002",
        "Analyze and extract browser/os information from a User-Agent string"
      ),
    },
    resourceServer
  )
);

app.get("/analyze", async (c) => {
  // Accept ?ua= or User-Agent header
  let ua = c.req.query("ua");
  if (!ua) {
    ua = c.req.header("user-agent") || "";
  }

  ua = ua?.toString().trim() ?? "";

  if (!ua) {
    return c.json({ error: "Provide ?ua= parameter or User-Agent HTTP header." }, 400);
  }
  if (ua.length < 6 || ua.length > 512) {
    return c.json({ error: "User-Agent string must be 6-512 characters." }, 400);
  }
  
  let result: UserAgentResult;
  try {
    result = analyzeUserAgent(ua);
  } catch (err) {
    return c.json({ error: "Failed to parse user-agent." }, 400);
  }
  return c.json({
    input: ua,
    ...result,
    analyzedAt: new Date().toISOString(),
  });
});

app.onError((err, c) => {
  // Let Hono's HTTPException pass
  if (typeof err === "object" && err && "getResponse" in err) return (err as any).getResponse();
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
