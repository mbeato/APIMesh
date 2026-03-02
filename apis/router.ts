import { Hono } from "hono";
import { registry } from "./registry";

const router = new Hono();
const PORT = 3001;

// Per-subdomain paid route mapping for .well-known/x402 discovery
const subdomainRoutes: Record<string, string[]> = {
  check:                        ["GET /check"],
  "http-status-checker":        ["GET /check"],
  "favicon-checker":            ["GET /check"],
  "microservice-health-check":  ["POST /check"],
  "status-code-checker":        ["GET /check"],
  "regex-builder":              ["POST /build", "POST /test"],
  "user-agent-analyzer":        ["GET /analyze"],
  "robots-txt-parser":          ["GET /analyze"],
  "mock-jwt-generator":         ["POST /generate"],
  "yaml-validator":             ["POST /validate"],
  "swagger-docs-creator":       ["POST /generate"],
  "core-web-vitals":            ["GET /check"],
  "security-headers":           ["GET /check"],
  "redirect-chain":             ["GET /check"],
  "email-security":             ["GET /check"],
  "seo-audit":                  ["GET /check"],
  "indexability":               ["GET /check"],
  "brand-assets":               ["GET /check"],
  "email-verify":               ["GET /check"],
  "tech-stack":                  ["GET /check"],
};

// Router health check (no subdomain needed)
router.get("/health", (c) => {
  const host = c.req.header("host") ?? "";
  const subdomain = extractSubdomain(host);
  // If a subdomain matches a registered API, delegate to it
  if (subdomain && registry[subdomain]) {
    return registry[subdomain].fetch(c.req.raw);
  }
  return c.json({ status: "ok" });
});

// Serve .well-known/x402 per subdomain so x402 scanners can discover paid routes
router.get("/.well-known/x402", (c) => {
  const host = c.req.header("host") ?? "";
  const subdomain = extractSubdomain(host);

  if (subdomain && subdomainRoutes[subdomain]) {
    return c.json({ version: 1, resources: subdomainRoutes[subdomain] });
  }

  // No subdomain or unknown — return empty discovery
  return c.json({ version: 1, resources: [] }, 404);
});

// Catch-all: route by subdomain
router.all("*", async (c) => {
  const host = c.req.header("host") ?? "";
  const subdomain = extractSubdomain(host);

  if (!subdomain) {
    return c.json({ error: "No subdomain specified" }, 404);
  }

  const subApp = registry[subdomain];
  if (!subApp) {
    return c.json({ error: `Unknown API: ${subdomain}` }, 404);
  }

  return subApp.fetch(c.req.raw);
});

function extractSubdomain(host: string): string | null {
  // Remove port if present
  const hostname = host.split(":")[0];
  // Match *.apimesh.xyz
  const match = hostname.match(/^([^.]+)\.apimesh\.xyz$/);
  if (match) return match[1];
  // Local testing only: allow <name>.localhost (disabled in production)
  if (process.env.NODE_ENV !== "production" && hostname.endsWith(".localhost")) return hostname.split(".")[0];
  return null;
}

console.log(`api-router listening on port ${PORT} — serving: ${Object.keys(registry).join(", ")}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: router.fetch,
};
