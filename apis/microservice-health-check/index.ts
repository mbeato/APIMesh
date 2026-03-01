import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { checkServicesHealth } from "./service-checker";
import { validateExternalUrl } from "../../shared/ssrf";

const app = new Hono();
const API_NAME = "microservice-health-check";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.003"; // $0.003 per health check, fair for per-call presence and latency

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET", "POST"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health check — before rate limiter
app.get("/health", c => c.json({ status: "ok" }));

// /check: 30 per minute per key, global 100/min
app.use("/check", rateLimit("microservice-health-check-check", 30, 60_000));
app.use("*", rateLimit("microservice-health-check", 100, 60_000));
app.use("*", apiLogger(API_NAME, 0.003));

// Info endpoint (metered for analytics)
app.get("/", c => c.json({
  api: API_NAME,
  status: "healthy",
  docs: "POST /check with JSON { services: [urls...] }",
  pricing: `${PRICE} per call via x402`,
  usage: "POST /check with { services: [ array of URLs ] }"
}));

// Free preview — check 1 service health (no payment required)
app.get("/preview", rateLimit("microservice-health-preview", 15, 60_000), async (c) => {
  const url = c.req.query("url");
  if (!url) {
    return c.json({ error: "Provide ?url= parameter" }, 400);
  }

  const check = validateExternalUrl(url);
  if ("error" in check) {
    return c.json({ error: `Invalid URL: ${check.error}` }, 400);
  }

  try {
    const report = await checkServicesHealth([url]);
    return c.json({
      ...report,
      preview: true,
      note: "Preview checks 1 service. Pay via x402 to check up to 10 services in parallel.",
    });
  } catch {
    return c.json({ error: "Error checking service health" }, 500);
  }
});

app.use(
  paymentMiddleware(
    {
      "POST /check": paidRouteWithDiscovery(
        PRICE,
        "Monitor health and response times of up to 10 microservices per call. Accessible via POST /check with JSON { services: [urls...] }.",
        {
          bodyType: "json",
          input: { services: ["https://example.com/health"] },
          inputSchema: {
            properties: {
              services: { type: "array", items: { type: "string" } },
            },
            required: ["services"],
          },
        }
      ),
    },
    resourceServer
  )
);

app.post("/check", async c => {
  let body: any;
  try {
    body = await c.req.json();
  } catch (e) {
    return c.json({ error: "Invalid JSON body" }, 400);
  }
  const services = Array.isArray(body?.services) ? body.services : undefined;
  if (!services || !Array.isArray(services) || services.length === 0) {
    return c.json({ error: "Provide a `services` array of URLs in JSON body" }, 400);
  }
  if (services.length > 10) {
    return c.json({ error: "Maximum 10 services per request" }, 400);
  }

  // Validate each URL (protocol + comprehensive SSRF protection)
  for (const url of services) {
    if (typeof url !== "string") {
      return c.json({ error: "All entries in `services` must be strings" }, 400);
    }
    const check = validateExternalUrl(url);
    if ("error" in check) {
      return c.json({ error: `Invalid service URL "${url}": ${check.error}` }, 400);
    }
  }
  const sanitized = services;

  try {
    const report = await checkServicesHealth(sanitized as string[]);
    return c.json(report);
  } catch (e) {
    return c.json({ error: "Internal error checking services" }, 500);
  }
});

app.onError((err, c) => {
  if (typeof err === "object" && err !== null && "getResponse" in err) return (err as any).getResponse();
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

app.notFound(c => c.json({ error: "Not found" }, 404));

export { app };

if (import.meta.main) console.log(`${API_NAME} listening on port ${PORT}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
