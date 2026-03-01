import { Hono } from "hono";
import { cors } from "hono/cors";
import {
  paymentMiddleware,
  paidRoute,
  resourceServer
} from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { validateYaml } from "./validate";

const app = new Hono();
const API_NAME = "yaml-validator";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.002"; // $0.002 per validation call

app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  })
);

// Health check — before rate limiter
app.get("/health", c => c.json({ status: "ok" }));

// Rate limit: 30/min for /validate (YAML checks are low cost, but protect backend)
app.use("/validate", rateLimit("yaml-validator-validate", 30, 60_000));
app.use("*", rateLimit("yaml-validator", 120, 60_000));
app.use("*", apiLogger(API_NAME, 0.002));

// Info endpoint
app.get("/", c => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    docs: "POST /validate with JSON: { yaml: string }",
    pricing: `${PRICE} per validation via x402`,
    subdomain: "yaml-validator.apimesh.xyz",
    example:
      {
        endpoint: "/validate",
        method: "POST",
        body: { yaml: "foo: bar" },
      },
    repo: "https://github.com/apimesh/apis/tree/main/apis/yaml-validator"
  });
});

app.use(
  paymentMiddleware(
    {
      "POST /validate": paidRoute(
        PRICE,
        "YAML syntax and schema validation (returns errors or parsed output)"
      ),
    },
    resourceServer
  )
);

app.post("/validate", async c => {
  let body: { yaml?: string };
  try {
    body = await c.req.json<{ yaml?: string }>();
  } catch (e) {
    return c.json({ error: "Invalid JSON body" }, 400);
  }
  if (!body || typeof body.yaml !== "string") {
    return c.json({ error: "Missing 'yaml' string field in request body" }, 400);
  }
  if (body.yaml.trim().length === 0) {
    return c.json({ error: "Blank YAML input" }, 400);
  }

  try {
    const result = validateYaml(body.yaml);
    return c.json(result);
  } catch (e: any) {
    // Defensive: should never throw, but catch parser bugs
    return c.json({ error: "Internal error during YAML validation" }, 500);
  }
});

app.onError((err, c) => {
  if ("getResponse" in err) return (err as any).getResponse();
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
