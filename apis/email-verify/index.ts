import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { validateEmail, fullCheck, previewCheck } from "./checker";

const app = new Hono();
const API_NAME = "email-verify";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.001";

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health check — before rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits
app.use("/check", rateLimit("email-verify-check", 30, 60_000));
app.use("*", rateLimit("email-verify", 60, 60_000));
app.use("*", apiLogger(API_NAME, 0.001));

// Info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    docs: "GET /check?email={email}",
    preview: "GET /preview?email={email} (free, syntax + disposable check only)",
    pricing: `${PRICE} per call via x402`,
  });
});

// Free preview — syntax, disposable, role-address only (no DNS)
app.get("/preview", rateLimit("email-verify-preview", 20, 60_000), async (c) => {
  const raw = c.req.query("email");
  if (!raw) {
    return c.json({ error: "Provide ?email= parameter. Example: ?email=user@example.com" }, 400);
  }
  if (raw.length > 254) {
    return c.json({ error: "Email exceeds maximum length" }, 400);
  }

  const validation = validateEmail(raw);
  if (!validation.valid) {
    return c.json({ error: validation.error }, 400);
  }

  try {
    const result = await previewCheck(validation.email!);
    return c.json({
      ...result,
      preview: true,
      note: "Preview checks syntax, disposable, and role-address only. Pay via x402 for full MX verification and deliverability assessment.",
    });
  } catch (e: any) {
    return c.json({ error: "Failed to verify email" }, 500);
  }
});

// x402 payment gate — only /check is paid
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Verify email address: syntax validation, MX record check, disposable domain detection, role-address detection, deliverability assessment",
        {
          input: { email: "user@example.com" },
          inputSchema: {
            properties: {
              email: { type: "string", description: "Email address to verify" },
            },
            required: ["email"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid full check
app.get("/check", async (c) => {
  const raw = c.req.query("email");
  if (!raw) {
    return c.json({ error: "Provide ?email= parameter. Example: ?email=user@example.com" }, 400);
  }
  if (raw.length > 254) {
    return c.json({ error: "Email exceeds maximum length" }, 400);
  }

  const validation = validateEmail(raw);
  if (!validation.valid) {
    return c.json({ error: validation.error }, 400);
  }

  try {
    const result = await fullCheck(validation.email!);
    return c.json(result);
  } catch (e: any) {
    const msg = e?.message ?? "";
    const safeMsg = msg.includes("timeout") ? "Request timed out"
      : msg.includes("DNS") ? "DNS lookup failed"
      : "Failed to verify email";
    return c.json({ error: safeMsg }, 500);
  }
});

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
