import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRoute, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { checkPresence } from "./checker";

const app = new Hono();
const API_NAME = "web-checker";
const PORT = 3001;

app.use("*", cors());
app.use("*", apiLogger(API_NAME));

app.use(
  paymentMiddleware(
    {
      "GET /check": paidRoute(
        "$0.005",
        "Check brand/product name availability across domains, GitHub, npm, PyPI, Reddit"
      ),
    },
    resourceServer
  )
);

app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    version: "1.0.0",
    status: "healthy",
    docs: "GET /check?name=yourname",
    pricing: "$0.005 per check via x402",
  });
});

app.get("/check", async (c) => {
  const name = c.req.query("name");
  if (!name || name.length < 2 || name.length > 50) {
    return c.json({ error: "Provide ?name= parameter (2-50 characters)" }, 400);
  }
  const result = await checkPresence(name);
  return c.json(result);
});

console.log(`${API_NAME} listening on port ${PORT}`);

export default {
  port: PORT,
  fetch: app.fetch,
};
