import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { validateDomain, previewCheck, fullCheck } from "./checker";

const app = new Hono();
const API_NAME = "email-security";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health check — before rate limiter for localhost monitoring
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit: 20/min for /check (each spawns many DNS queries), 60/min global
app.use("/check", rateLimit("email-security-check", 20, 60_000));
app.use("*", rateLimit("email-security", 60, 60_000));
app.use("*", apiLogger(API_NAME, 0.01));

// Info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    docs: "GET /check?domain={domain}",
    preview: "GET /preview?domain={domain} (free, SPF+DMARC only)",
    pricing: `${PRICE} per call via x402`,
  });
});

// Free preview — SPF + DMARC only (no DKIM probing, no MX)
app.get("/preview", rateLimit("email-security-preview", 15, 60_000), async (c) => {
  const raw = c.req.query("domain");
  if (!raw) {
    return c.json({ error: "Provide ?domain= parameter. Example: ?domain=example.com" }, 400);
  }

  if (raw.length > 253) {
    return c.json({ error: "Domain exceeds maximum length" }, 400);
  }

  const validation = validateDomain(raw);
  if (!validation.valid) {
    return c.json({ error: validation.error }, 400);
  }

  try {
    const result = await previewCheck(validation.domain!);

    return c.json({
      ...result,
      preview: true,
      note: "Preview checks SPF and DMARC only. Pay via x402 for full analysis with DKIM probing and MX provider detection.",
    });
  } catch (e: any) {
    const msg = e?.message ?? "";
    const safeMsg = msg.includes("timeout")
      ? "Request timed out"
      : msg.includes("DNS")
        ? "DNS lookup failed"
        : "Failed to check domain";
    return c.json({ error: safeMsg }, 500);
  }
});

// x402 payment gate — only /check is paid
app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Audit email domain security: SPF, DKIM, DMARC records with parsing, grading, and MX provider detection",
        {
          input: { domain: "example.com" },
          inputSchema: {
            properties: {
              domain: { type: "string", description: "Domain to check email security for" },
            },
            required: ["domain"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Paid full check — SPF + DMARC + DKIM + MX
app.get("/check", async (c) => {
  const raw = c.req.query("domain");
  if (!raw) {
    return c.json({ error: "Provide ?domain= parameter. Example: ?domain=example.com" }, 400);
  }

  if (raw.length > 253) {
    return c.json({ error: "Domain exceeds maximum length" }, 400);
  }

  const validation = validateDomain(raw);
  if (!validation.valid) {
    return c.json({ error: validation.error }, 400);
  }

  try {
    const result = await fullCheck(validation.domain!);
    return c.json(result);
  } catch (e: any) {
    const msg = e?.message ?? "";
    const safeMsg = msg.includes("timeout")
      ? "Request timed out"
      : msg.includes("DNS")
        ? "DNS lookup failed"
        : "Failed to check domain";
    return c.json({ error: safeMsg }, 500);
  }
});

app.onError((err, c) => {
  // Let Hono's HTTPException (e.g. 402 from x402) pass through
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
