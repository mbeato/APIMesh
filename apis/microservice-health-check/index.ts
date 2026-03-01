import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRoute, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { checkServicesHealth } from "./service-checker";

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

app.use(
  paymentMiddleware(
    {
      "POST /check": paidRoute(
        PRICE,
        "Monitor health and response times of up to 10 microservices per call. Accessible via POST /check with JSON { services: [urls...] }."
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

  // Basic URL format check
  const sanitized = services.map((url: string) => {
    if (typeof url !== "string" || !/^https?:\/\//i.test(url)) return null;
    // Disallow localhost, 127.0.0.1, ::1
    try {
      const parsed = new URL(url);
      if (["localhost", "127.0.0.1", "::1"].includes(parsed.hostname)) return null;
      return url;
    } catch {
      return null;
    }
  });
  if (sanitized.includes(null)) {
    return c.json({ error: "All entries in `services` must be valid, non-local HTTP/HTTPS URLs" }, 400);
  }

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
