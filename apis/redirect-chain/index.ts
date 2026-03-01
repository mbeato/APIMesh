import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl } from "../../shared/ssrf";
import { traceRedirectChain } from "./tracer";

function sanitizeError(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  if (/^Only http|^Private|^Invalid URL|^Too many redirect|^Redirect chain contains|^Failed to reach|^Redirect to unsupported|^Redirect at hop|^Redirect chain exceeded|^URL exceeds/.test(msg)) return msg;
  return "Failed to trace redirect chain";
}

const app = new Hono();
const API_NAME = "redirect-chain";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.001";

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health check
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limiting
app.use("/check", rateLimit("redirect-chain-check", 30, 60_000));
app.use("*", rateLimit("redirect-chain", 90, 60_000));
app.use("*", apiLogger(API_NAME, 0.001));

// Info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    docs: "GET /check?url={url}",
    pricing: `${PRICE} per call via x402`,
    preview: "GET /preview?url={url} (free, max 5 hops, no canonical)",
  });
});

// Free preview — before paymentMiddleware
app.get("/preview", rateLimit("redirect-chain-preview", 20, 60_000), async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing required ?url parameter" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const check = validateExternalUrl(rawUrl);
  if ("error" in check) {
    return c.json({ error: check.error }, 400);
  }

  try {
    const result = await traceRedirectChain(check.url.toString(), {
      maxHops: 5,
      extractCanonical: false,
    });

    return c.json({
      preview: true,
      ...result,
      note: "Preview limited to 5 hops, no canonical extraction. Use /check with x402 payment for full analysis.",
    });
  } catch (err: unknown) {
    return c.json({ error: sanitizeError(err) }, 400);
  }
});

app.use(
  paymentMiddleware(
    {
      "GET /check": paidRouteWithDiscovery(
        PRICE,
        "Trace the full HTTP redirect chain of any URL with per-hop latency, redirect types, canonical alignment, and loop detection",
        {
          input: { url: "https://example.com" },
          inputSchema: {
            properties: {
              url: { type: "string" },
            },
            required: ["url"],
          },
        }
      ),
    },
    resourceServer
  )
);

app.get("/check", async (c) => {
  const rawUrl = c.req.query("url");
  if (!rawUrl) {
    return c.json({ error: "Missing required ?url parameter" }, 400);
  }
  if (rawUrl.length > 2048) {
    return c.json({ error: "URL exceeds maximum length" }, 400);
  }

  const check = validateExternalUrl(rawUrl);
  if ("error" in check) {
    return c.json({ error: check.error }, 400);
  }

  try {
    const result = await traceRedirectChain(check.url.toString(), {
      maxHops: 20,
      extractCanonical: true,
    });

    return c.json(result);
  } catch (err: unknown) {
    return c.json({ error: sanitizeError(err) }, 400);
  }
});

app.onError((err, c) => {
  if (typeof err === "object" && err !== null && "getResponse" in err) return (err as any).getResponse();
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
