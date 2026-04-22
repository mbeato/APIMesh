import { Hono } from "hono";
import { cors } from "hono/cors";
import {
  paymentMiddleware,
  paidRouteWithDiscovery,
  resourceServer,
} from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { safeFetch, validateExternalUrl } from "../../shared/ssrf";
import {
  PortScanInput,
  PortScanResult,
  PortScanPreviewResult,
  AggregatedPortScanResult,
  PortScanRecommendation,
  performDeepPortScan,
  performPreviewPortScan,
} from "./scanner";

const app = new Hono();
const API_NAME = "port-scanner-aggregate";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = 0.02; // Deep scan pricing (extensive crawling, multi-layered analysis)
const PRICE_STR = "$0.02";

// Allowed HTTP methods
const allowedMethods = ["GET", "POST"];

// CORS middleware (apply first)
app.use("*", cors({
  origin: "*",
  allowMethods: allowedMethods,
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// Health endpoint - before rate limit
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limiting: stricter on preview and check for abuse prevention
app.use("/preview", rateLimit("port-scanner-aggregate-preview", 20, 60_000));
app.use("/scan", rateLimit("port-scanner-aggregate-scan", 15, 60_000));
app.use("*", rateLimit("port-scanner-aggregate", 60, 60_000));

// Extract payer's wallet from request
app.use("*", extractPayerWallet());

// API logger with price in usd
app.use("*", apiLogger(API_NAME, PRICE));

// Info endpoint with comprehensive API documentation after rate limiting
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    description:
      "Performs deep port scans on target IP addresses by querying free DNS, IP info, and open port data sources. Collates open ports, services, and potential vulnerabilities across IP ranges for security assessment.",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/preview",
          description: "Free preview scan of a single IP to quickly detect basic open ports and services.",
          parameters: [
            { name: "ip", type: "string", required: true, description: "Target IPv4 or IPv6 address" },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              ip: "8.8.8.8",
              openPorts: [22, 53],
              services: ["ssh", "dns"],
              score: 75,
              grade: "B",
              details: "Basic ports scanned, found standard services.",
              recommendations: [
                {
                  issue: "Port 22 open",
                  severity: 70,
                  suggestion: "Verify SSH access policies and limit exposed IPs.",
                },
              ],
            },
            meta: { timestamp: "...", duration_ms: 142, api_version: "1.0.0" },
          },
        },
        {
          method: "POST",
          path: "/scan",
          description: "Deep scan of a list of IP addresses or CIDR ranges with multi-source aggregation and vulnerability scoring.",
          parameters: [
            {
              name: "targets",
              type: "string[]",
              required: true,
              description: "List of IP addresses (IPv4 or v6) or CIDR ranges to scan.",
            },
            {
              name: "maxPorts",
              type: "number",
              required: false,
              description: "Optional limit on number of top common ports to scan per host (default 100).",
            },
          ],
          exampleResponse: {
            status: "ok",
            data: {
              scanId: "scan-abc123",
              totalHosts: 3,
              scannedHosts: 3,
              overallScore: 60,
              grade: "C",
              hosts: [
                {
                  ip: "192.168.1.1",
                  openPorts: [80, 443],
                  services: ["http", "https"],
                  vulnerabilities: ["CVE-2020-12345"],
                  score: 55,
                  grade: "C",
                  recommendations: [
                    {
                      issue: "Outdated web server version",
                      severity: 65,
                      suggestion: "Upgrade HTTP server to latest version to patch CVE-2020-12345.",
                    },
                  ],
                },
                {
                  ip: "192.168.1.2",
                  openPorts: [22],
                  services: ["ssh"],
                  vulnerabilities: [],
                  score: 85,
                  grade: "B",
                  recommendations: [],
                },
              ],
              details: "Aggregated scan combining DNS PTR, port query databases, and IP info sources.",
              completedAt: "...",
            },
            meta: { timestamp: "...", duration_ms: 2000, api_version: "1.0.0" },
          },
        },
      ],
      parameters: [
        { name: "ip", type: "string", description: "IPv4 or IPv6 address to scan" },
        { name: "targets", type: "string[]", description: "List of IPs or CIDRs" },
        { name: "maxPorts", type: "number", description: "Optional max top ports to scan" },
      ],
      examples: [
        { method: "GET", path: "/preview?ip=8.8.8.8" },
        {
          method: "POST",
          path: "/scan",
          body: { targets: ["8.8.8.8", "1.1.1.1"], maxPorts: 50 },
        },
      ],
    },
    pricing: {
      preview: "$0.000 (free preview, limited to one IP)",
      scan: PRICE_STR + " (Deep scan with multi-source analysis)",
    },
    subdomain: "port-scanner-aggregate.apimesh.xyz",
  });
});

// Free preview endpoint (GET /preview?ip=...)
app.get("/preview", async (c) => {
  const ip = c.req.query("ip");
  if (!ip || typeof ip !== "string") {
    return c.json(
      { error: "Missing ?ip= parameter with valid IPv4 or IPv6 address" },
      400
    );
  }
  // Limit IP string length
  if (ip.length > 45) {
    return c.json({ error: "IP address too long" }, 400);
  }

  try {
    const start = performance.now();
    const result: PortScanPreviewResult = await performPreviewPortScan(ip);
    const duration_ms = Math.round(performance.now() - start);
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Paid deep scan endpoint (POST /scan)
// JSON body: { targets: string[], maxPorts?: number }
app.post("/scan", async (c) => {
  try {
    const reqJson = await c.req.json();
    if (!reqJson || typeof reqJson !== "object") {
      return c.json({ error: "Invalid JSON body" }, 400);
    }
    const targets = reqJson.targets;
    if (!Array.isArray(targets) || targets.length === 0) {
      return c.json({ error: "Missing or empty targets array" }, 400);
    }
    if (targets.length > 50) {
      // Limit number of targets to prevent abuse
      return c.json({ error: "Too many targets - max 50" }, 400);
    }
    for (const t of targets) {
      if (typeof t !== "string" || t.length > 50) {
        return c.json({ error: "Invalid target IP or CIDR" }, 400);
      }
    }
    const maxPorts = Number(reqJson.maxPorts) || 100;
    if (maxPorts < 10 || maxPorts > 200) {
      return c.json({ error: "maxPorts must be between 10 and 200" }, 400);
    }

    const start = performance.now();
    const scanInput: PortScanInput = { targets, maxPorts };
    const result: AggregatedPortScanResult = await performDeepPortScan(scanInput);
    const duration_ms = Math.round(performance.now() - start);
    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ error: "Analysis temporarily unavailable", detail: msg }, status);
  }
});

// Spend cap middleware
app.use("*", spendCapMiddleware());

// Payment middleware with x402 and MPP support
app.use(
  paymentMiddleware(
    {
      "POST /scan": paidRouteWithDiscovery(
        PRICE_STR,
        "Deep scan with extensive multi-source port aggregation and vulnerability analysis",
        {
          bodyType: "json",
          input: { targets: ["8.8.8.8"], maxPorts: 100 },
          inputSchema: {
            properties: {
              targets: {
                type: "array",
                items: { type: "string", description: "IP or CIDR to scan" },
                description: "List of IPv4 or IPv6 addresses or CIDR ranges",
              },
              maxPorts: {
                type: "number",
                description: "Max number of top ports to scan per host (10 to 200)",
              },
            },
            required: ["targets"],
          },
        }
      ),
    },
    resourceServer
  )
);

// Not found handler
app.notFound((c) => c.json({ error: "Not found" }, 404));

// Error handling middleware (passes through HTTPExceptions such as 402)
app.onError((err, c) => {
  if (typeof err === "object" && err !== null && "getResponse" in err) {
    return (err as any).getResponse();
  }
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

export { app };

if (import.meta.main) {
  // eslint-disable-next-line no-console
  console.log(`${API_NAME} listening on port ${PORT}`);
}

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
