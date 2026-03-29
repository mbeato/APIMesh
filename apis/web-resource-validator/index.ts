import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRoute, resourceServer, WALLET_ADDRESS, NETWORK } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";

// Initialize Hono app
const app = new Hono();
const API_NAME = "web-resource-validator";
const PORT = Number(process.env.PORT) || 3001;

// CORS: open to all origins
app.use("*", cors({ origin: "*", allowMethods: ["GET"], allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"] }));

// Health check endpoint — before rate limiting
app.get("/health", (c) => c.json({ status: "ok" }));

// Info endpoint
app.get("/", (c) => {
  return c.json({
    api: "web-resource-validator",
    description: "Validate presence and correctness of common web resources like robots.txt, sitemap.xml, openapi.json, agent.json",
    version: "1.0",
    docs: "Check /robots.txt, /sitemap.xml, /openapi.json, /agent.json",
    pricing: "$0.001-$0.01 per call",
  });
});

// Apply rate limit for all routes
app.use("*", rateLimit("web-resource-validator", 60, 60000));

// Wallet extraction middleware placeholder
// Assuming extractPayerWallet is a function to extract wallet info from request
import { extractPayerWallet } from "../../shared/x402-wallet";
app.use("*", extractPayerWallet);

// Apply API logger
app.use("*", apiLogger(API_NAME, 0.005));

// Payment middleware applying x402 and MPP
app.use(
  paymentMiddleware(
    {
      "GET /robots.txt":
        paidRoute(
          "$0.001",
          "Validate robots.txt presence",
          {
            input: { url: "robots.txt" },
            inputSchema: {
              type: "object",
              properties: { url: { type: "string" } },
              required: ["url"],
            },
          }
        ),
      "GET /sitemap.xml":
        paidRoute(
          "$0.002",
          "Validate sitemap.xml presence",
          {
            input: { url: "sitemap.xml" },
            inputSchema: {
              type: "object",
              properties: { url: { type: "string" } },
              required: ["url"],
            },
          }
        ),
      "GET /openapi.json":
        paidRoute(
          "$0.002",
          "Validate openapi.json presence",
          {
            input: { url: "openapi.json" },
            inputSchema: {
              type: "object",
              properties: { url: { type: "string" } },
              required: ["url"],
            },
          }
        ),
      "GET /agent.json":
        paidRoute(
          "$0.002",
          "Validate agent.json presence",
          {
            input: { url: "agent.json" },
            inputSchema: {
              type: "object",
              properties: { url: { type: "string" } },
              required: ["url"],
            },
          }
        ),
    },
    resourceServer
  )
);

// Helper functions to check presence of resources
async function checkResource(resourcePath: string): Promise<{available: boolean; error?: string}> {
  const url = `https://${cReq.hostname}${resourcePath}`;
  try {
    const res = await fetch(url, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(5000) });
    return { available: res.status === 200 };
  } catch (e) {
    return { available: false, error: String(e) };
  }
}

// Main route handling resource validation with payment
app.get("/validate", async (c) => {
  const resource = c.req.query("resource");
  if (!resource || !['robots.txt','sitemap.xml','openapi.json','agent.json'].includes(resource)) {
    return c.json({ error: "Invalid resource" }, 400);
  }

  // Reconstruct URL assuming host is same as request host
  const host = c.req.host;
  const url = `https://${host}/${resource}`;

  // Authorization info (wallet extraction)
  const wallet = c.get("wallet") || "";

  const result = await checkResource(`/${resource}`);
  // Price per call varies, pick a mid-range value
  const pricePerCall = 0.005; // $0.005
  // Return result
  return c.json({
    url,
    available: result.available,
    error: result.error,
    price_per_call: `$${pricePerCall.toFixed(3)}`,
  });
});

// Error handling
app.onError((err, c) => {
  if ("getResponse" in err) return (err as any).getResponse();
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

// 404 handler
app.notFound((c) => c.json({ error: "Not found" }, 404));

// Export the Hono app
export { app };

// Default export configuration
if (import.meta.main) console.log(`${API_NAME} listening on port ${PORT}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};