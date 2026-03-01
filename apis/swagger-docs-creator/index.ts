import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRoute, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { generateSwagger } from "./swagger";

const API_NAME = "swagger-docs-creator";
const PORT = Number(process.env.PORT) || 3001;

const app = new Hono();

app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// Health check — before rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limiting: (conservative) 30/min per endpoint, 90/min global
app.use("/generate", rateLimit("swagger-docs-creator-generate", 30, 60_000));
app.use("*", rateLimit("swagger-docs-creator", 90, 60_000));

app.use("*", apiLogger(API_NAME, 0.002));

// Info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    description: "Generate basic Swagger (OpenAPI 3.0.x) documentation for your API endpoint.",
    usage: {
      method: "POST",
      path: "/generate",
      body: {
        path: "/your/api/path",
        method: "GET | POST | PUT | DELETE ...",
        summary: "Short summary",
        description: "Full description (optional)",
        parameters: [{ name: "id", in: "query", required: false, schema: { type: "string" } }],
        requestBody: { description: "(optional)", content: { "application/json": { schema: {} } } },
        responses: { "200": { description: "Success" } }
      }
    },
    pricing: "$0.002 per call via x402",
    docs: "POST /generate with endpoint details to receive Swagger JSON."
  });
});

app.use(
  paymentMiddleware(
    {
      "POST /generate": paidRoute(
        "$0.002",
        "Generate basic Swagger documentation for an API path or endpoint."
      ),
    },
    resourceServer
  )
);

app.post("/generate", async (c) => {
  try {
    const body = await c.req.json();
    const swagger = generateSwagger(body);
    return c.json(swagger);
  } catch (e: any) {
    if (e && e.name === "SyntaxError") {
      return c.json({ error: "Invalid JSON. Provide valid JSON body." }, 400);
    }
    // Validation errors forwarded from generateSwagger
    if (e && typeof e.status === "number") {
      return c.json({ error: e.message }, e.status);
    }
    console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, e);
    return c.json({ error: "Internal server error" }, 500);
  }
});

app.onError((err, c) => {
  // Let Hono's HTTPException (e.g. 402 from x402) pass through
  if ("getResponse" in err) return (err as any).getResponse();
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

app.notFound((c) =>
  c.json({ error: "Not found" }, 404)
);

export { app };

if (import.meta.main) console.log(`${API_NAME} listening on port ${PORT}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
