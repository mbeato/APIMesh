import { Hono } from "hono";
import { registry } from "./registry";
import { apiKeyAuth } from "../shared/api-key-auth";
import { buildPerApiManifest } from "../shared/mpp-manifest";

const router = new Hono();

function resolvePort(envVar: string, defaultPort: number): number {
  const raw = process.env[envVar];
  if (!raw) return defaultPort;
  const port = parseInt(raw, 10);
  if (isNaN(port) || port < 1024 || port > 65535) {
    console.error(`FATAL: ${envVar}=${raw} is not a valid port (1024-65535)`);
    process.exit(1);
  }
  return port;
}

const PORT = resolvePort("ROUTER_PORT", 3001);

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

// Serve .well-known/mpp per subdomain — vendor-proprietary JSON manifest for
// MPP/agent-ecosystem crawlers (apr 2026: observed 118 AWS IPs in coordinated
// probe, all 4-path sequence /.well-known/mpp → /openapi.json → /llms.txt → /).
router.get("/.well-known/mpp", (c) => {
  const host = c.req.header("host") ?? "";
  const subdomain = extractSubdomain(host);
  if (subdomain && registry[subdomain]) {
    return c.json(buildPerApiManifest(subdomain, host));
  }
  return c.json({ error: "unknown_api" }, 404);
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

  // API key auth: check for Bearer sk_live_... and handle credits
  // Returns Response for auth success/error, or null for x402 fallthrough
  const authResponse = await apiKeyAuth(c.req.raw, subdomain, subdomainRoutes[subdomain], subApp);
  if (authResponse) return authResponse;

  // No API key — fall through to existing x402 payment flow
  return subApp.fetch(c.req.raw);
});

function extractSubdomain(host: string): string | null {
  const hostname = host.split(":")[0];
  if (process.env.NODE_ENV === "production") {
    // Production: only accept *.apimesh.xyz
    const match = hostname.match(/^([^.]+)\.apimesh\.xyz$/);
    if (match) return match[1];
  } else if (process.env.NODE_ENV === "staging") {
    // Staging: only accept *.staging.apimesh.xyz
    const match = hostname.match(/^([^.]+)\.staging\.apimesh\.xyz$/);
    if (match) return match[1];
  } else {
    // Development: accept both patterns + localhost
    const match = hostname.match(/^([^.]+)\.(?:staging\.)?apimesh\.xyz$/);
    if (match) return match[1];
    if (hostname.endsWith(".localhost")) return hostname.split(".")[0];
  }
  return null;
}

console.log(`api-router listening on port ${PORT} — serving: ${Object.keys(registry).join(", ")}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: router.fetch,
};
