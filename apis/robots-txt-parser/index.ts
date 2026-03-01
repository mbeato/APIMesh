import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRoute, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";
import { parseRobotsTxt, analyzeRobotsTxt } from "./parser";

const app = new Hono();
const API_NAME = "robots-txt-parser";
const PORT = Number(process.env.PORT) || 3001;

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health check
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limit: 15/min per IP for /analyze, 60/min global
app.use("/analyze", rateLimit("robots-txt-parser-analyze", 15, 60_000));
app.use("*", rateLimit("robots-txt-parser", 60, 60_000));
app.use("*", apiLogger(API_NAME, 0.002));

// Info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    docs: "GET /analyze?url=https://example.com",
    pricing: "$0.002 per call via x402",
    repo: "https://github.com/apimesh/api-examples",
    example: "/analyze?url=https://apimesh.xyz",
  });
});

app.use(
  paymentMiddleware(
    {
      "GET /analyze": paidRoute(
        "$0.002",
        "Fetch, parse and analyze the robots.txt of a given website"
      ),
    },
    resourceServer
  )
);

app.get("/analyze", async (c) => {
  const urlParam = c.req.query("url");
  if (!urlParam || typeof urlParam !== "string" || urlParam.length < 8) {
    return c.json({ error: "Query parameter ?url=https://example.com is required" }, 400);
  }

  let robotsUrl: URL;
  try {
    // Ensure protocol present, sanitize
    robotsUrl = new URL(urlParam);
    robotsUrl.pathname = "/robots.txt";
    robotsUrl.search = "";
    robotsUrl.hash = "";
  } catch {
    return c.json({ error: "Invalid URL. Provide absolute URL including protocol (http/https)" }, 400);
  }

  // Fetch robots.txt (timeout, 8s max)
  let res: Response;
  try {
    res = await fetch(robotsUrl.toString(), { redirect: "follow", signal: AbortSignal.timeout(8000), headers: { "User-Agent": "robots-txt-parser/1.0 apimesh.xyz" } });
  } catch (e: any) {
    return c.json({ error: `Failed to fetch robots.txt: ${e?.name === 'TimeoutError' ? 'timeout' : (e?.message || 'network error')}` }, 500);
  }

  if (!res.ok) {
    return c.json({ error: `robots.txt not found or not accessible: HTTP ${res.status}` }, res.status);
  }

  let lines: string[];
  try {
    const text = await res.text();
    if (!text || text.length === 0) {
      return c.json({ error: "robots.txt is empty." }, 400);
    }
    // Defensive: cap file size (512 KB)
    if (text.length > 512 * 1024) {
      return c.json({ error: "robots.txt too large (max 512 KB supported)" }, 413);
    }
    lines = text.split(/\r?\n/).slice(0, 2000); // defensive: max 2000 lines
  } catch {
    return c.json({ error: "Failed to read robots.txt contents" }, 500);
  }

  try {
    const parsed = parseRobotsTxt(lines);
    const analysis = analyzeRobotsTxt(parsed);
    return c.json({
      url: robotsUrl.toString(),
      fetchedAt: new Date().toISOString(),
      parsed,
      analysis
    });
  } catch (e: any) {
    return c.json({ error: "Failed to parse/analyze robots.txt", detail: e?.message }, 500);
  }
});

app.onError((err, c) => {
  if ("getResponse" in err) return (err as any).getResponse();
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
