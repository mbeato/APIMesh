import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRoute, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { generateMockJwt } from "./jwt";

const app = new Hono();
const API_NAME = "mock-jwt-generator";
const SUBDOMAIN = "mock-jwt-generator.apimesh.xyz";
const PRICE_PER_CALL = 0.001; // $0.001 per call
const PORT = Number(process.env.PORT) || 3001;

// CORS — open to all origins
app.use("*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// /health — before rate limiters
app.get("/health", (c) => c.json({ status: "ok" }));

// / (info) and generation routes — rate limited, metered
// Allow up to 60/min for all routes, 30/min for JWT generation (overrides global)
app.use("/generate", rateLimit("mock-jwt-generator-generate", 30, 60_000));
app.use("*", rateLimit("mock-jwt-generator", 60, 60_000));
app.use("*", apiLogger(API_NAME, PRICE_PER_CALL));

// Info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    subdomain: SUBDOMAIN,
    status: "healthy",
    docs: "POST /generate — body: { payload, secret, [header], [expiresInSeconds] }",
    pricing: "$0.001 per token generated (POST /generate)",
    usage: {
      generate: {
        method: "POST",
        path: "/generate",
        body: {
          payload: "Record<string, unknown> — JWT payload claims",
          secret: "string — HMAC secret (for dev only)",
          header: "Record<string, unknown> (optional)",
          expiresInSeconds: "number (optional) — unix seconds expiry; default: 3600 s"
        },
        notes: [
          "For local testing purposes only. Tokens are signed with HS256 and developer-provided secret.",
          "NEVER use in production."
        ]
      },
    },
    caution: "For development/testing only — not for production use. Never use these tokens for real authentication.",
  });
});

// Payment — /generate is paid
app.use(
  paymentMiddleware(
    {
      "POST /generate": paidRoute(
        "$0.001",
        "Generate a mock JWT signed by supplied secret (HS256) for development/testing."
      ),
    },
    resourceServer
  )
);

// POST /generate — issue JWT per options
app.post("/generate", async (c) => {
  try {
    // Limit body size — 16KB limit
    const buf = await c.req.raw.arrayBuffer();
    if (buf.byteLength > 16 * 1024)
      return c.json({ error: "Request body too large (max 16KB)." }, 413);
    let body: any;
    try {
      body = JSON.parse(new TextDecoder().decode(buf));
    } catch (e) {
      return c.json({ error: "Invalid JSON body." }, 400);
    }

    const { payload, secret, header, expiresInSeconds } = body ?? {};
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      return c.json({ error: "Missing or invalid 'payload' (must be object)." }, 400);
    }
    if (!secret || typeof secret !== "string" || secret.length < 3) {
      return c.json({ error: "Missing or invalid 'secret' (must be string, min 3 chars)." }, 400);
    }
    if (header && (typeof header !== "object" || Array.isArray(header))) {
      return c.json({ error: "Invalid 'header' (must be object if provided)." }, 400);
    }
    let exp: number | undefined = undefined;
    if (expiresInSeconds !== undefined) {
      if (typeof expiresInSeconds !== "number" || !Number.isFinite(expiresInSeconds) || expiresInSeconds < 10 || expiresInSeconds > 86400 * 7)
        return c.json({ error: "'expiresInSeconds' must be number between 10 and 604800 (7 days)." }, 400);
      exp = Math.floor(Date.now() / 1000) + Math.floor(expiresInSeconds);
    } else {
      exp = Math.floor(Date.now() / 1000) + 3600;
    }

    // Add exp claim unless user set it themselves
    let payloadOut: Record<string, any> = { ...payload };
    if (!('exp' in payloadOut)) {
      payloadOut.exp = exp;
    }
    const headerOut = { alg: "HS256", typ: "JWT", ...header };

    const { token, error } = await generateMockJwt(payloadOut, secret, headerOut);
    if (error) return c.json({ error }, 400);
    return c.json({
      token,
      header: headerOut,
      payload: payloadOut,
      warning: "This JWT is for development/testing only. Never use in production.",
    });
  } catch (e) {
    return c.json({ error: "Unexpected internal error." }, 500);
  }
});

app.onError((err, c) => {
  // Let Hono's HTTPException (e.g. 402 from x402) pass through
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
