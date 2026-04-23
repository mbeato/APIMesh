import { registry } from "../apis/registry";

// Per-subdomain price map. Core 20 hand-priced; brain-built APIs default to $0.01.
// Keep in sync with apiLogger() calls in apis/*/index.ts.
const PRICE_USD: Record<string, number> = {
  "email-verify": 0.001,
  "email-security": 0.01,
  "robots-txt-parser": 0.002,
  "seo-audit": 0.003,
  "web-checker": 0.005,
  "brand-assets": 0.002,
  "swagger-docs-creator": 0.002,
  "core-web-vitals": 0.005,
  "redirect-chain": 0.001,
  "web-resource-validator": 0.005,
  "status-code-checker": 0.001,
  "yaml-validator": 0.002,
  "favicon-checker": 0.002,
  "website-security-header-info": 0.01,
  "security-headers": 0.005,
  "tech-stack": 0.003,
  "http-status-checker": 0.002,
  "indexability": 0.001,
  "microservice-health-check": 0.003,
  "mock-jwt-generator": 0.001,
  "regex-builder": 0.002,
  "user-agent-analyzer": 0.002,
  "check": 0.005,
};
const DEFAULT_PRICE_USD = 0.01;

// Canonical endpoint path per subdomain (keep in sync with subdomainRoutes in router.ts).
const ENDPOINT_PATH: Record<string, { method: string; path: string }> = {
  "check": { method: "GET", path: "/check" },
  "http-status-checker": { method: "GET", path: "/check" },
  "favicon-checker": { method: "GET", path: "/check" },
  "microservice-health-check": { method: "POST", path: "/check" },
  "status-code-checker": { method: "GET", path: "/check" },
  "regex-builder": { method: "POST", path: "/build" },
  "user-agent-analyzer": { method: "GET", path: "/analyze" },
  "robots-txt-parser": { method: "GET", path: "/analyze" },
  "mock-jwt-generator": { method: "POST", path: "/generate" },
  "yaml-validator": { method: "POST", path: "/validate" },
  "swagger-docs-creator": { method: "POST", path: "/generate" },
  "core-web-vitals": { method: "GET", path: "/check" },
  "security-headers": { method: "GET", path: "/check" },
  "redirect-chain": { method: "GET", path: "/check" },
  "email-security": { method: "GET", path: "/check" },
  "seo-audit": { method: "GET", path: "/check" },
  "indexability": { method: "GET", path: "/check" },
  "brand-assets": { method: "GET", path: "/check" },
  "email-verify": { method: "GET", path: "/check" },
  "tech-stack": { method: "GET", path: "/check" },
};
const DEFAULT_ENDPOINT = { method: "GET", path: "/check" };

function baseFor(subdomain: string, host: string): string {
  if (host.endsWith("apimesh.xyz")) return `https://${subdomain}.apimesh.xyz`;
  return `https://${subdomain}.${host.replace(/^[^.]+\./, "")}`;
}

function categoryFor(subdomain: string): string {
  if (subdomain.includes("ssl") || subdomain.includes("tls") || subdomain.includes("security") || subdomain.includes("vulnerability") || subdomain.includes("csp") || subdomain.includes("privacy") || subdomain.includes("risk")) return "security";
  if (subdomain.includes("seo") || subdomain.includes("indexability") || subdomain.includes("robots") || subdomain.includes("core-web-vitals")) return "seo";
  if (subdomain.includes("dns") || subdomain.includes("ip") || subdomain.includes("cdn") || subdomain.includes("port") || subdomain.includes("network") || subdomain.includes("route")) return "devops";
  if (subdomain.includes("http") || subdomain.includes("check") || subdomain.includes("status")) return "web-analysis";
  return "web-analysis";
}

function tagsFor(subdomain: string, category: string): string[] {
  return [category, ...subdomain.split("-").filter(s => s.length > 2)].slice(0, 6);
}

function describeFrom(subdomain: string): string {
  const words = subdomain.split("-").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
  return `${words} — pay-per-call API on apimesh.xyz`;
}

export interface ApiEntry {
  name: string;
  endpoint: string;
  method: string;
  price_usd: number;
  description: string;
  category: string;
  tags: string[];
}

export function buildApiEntry(subdomain: string, host: string): ApiEntry {
  const ep = ENDPOINT_PATH[subdomain] ?? DEFAULT_ENDPOINT;
  const price = PRICE_USD[subdomain] ?? DEFAULT_PRICE_USD;
  const category = categoryFor(subdomain);
  return {
    name: subdomain,
    endpoint: `${baseFor(subdomain, host)}${ep.path}`,
    method: ep.method,
    price_usd: price,
    description: describeFrom(subdomain),
    category,
    tags: tagsFor(subdomain, category),
  };
}

export interface PlatformManifest {
  $schema: string;
  name: string;
  description: string;
  provider: { name: string; url: string; contact: string };
  payment_methods: Array<Record<string, unknown>>;
  discovery: Record<string, string>;
  apis: ApiEntry[];
  categories: string[];
  api_count: number;
  generated_at: string;
}

export function buildPlatformManifest(host: string = "apimesh.xyz"): PlatformManifest {
  const root = host.endsWith("apimesh.xyz") ? "https://apimesh.xyz" : `https://${host}`;
  const apis = Object.keys(registry)
    .filter(s => s !== "check" && s !== "dashboard" && s !== "landing" && s !== "router")
    .sort()
    .map(s => buildApiEntry(s, host));
  const categories = Array.from(new Set(apis.map(a => a.category))).sort();

  return {
    $schema: `${root}/.well-known/mpp.schema.json`,
    name: "APIMesh",
    description: `Pay-per-call API marketplace. ${apis.length} web-analysis, SEO, security, and devops APIs for agents and developers.`,
    provider: {
      name: "APIMesh",
      url: root,
      contact: "c@vtxathlete.com",
    },
    payment_methods: [
      {
        protocol: "x402",
        version: "1",
        networks: ["base-mainnet"],
        asset: "USDC",
        discovery: "Per-endpoint via WWW-Authenticate: Payment on 402 responses",
      },
      {
        protocol: "mpp",
        version: "draft-ryan-httpauth-payment",
        discovery: "OpenAPI x-mpp annotations + WWW-Authenticate: Payment on 402",
      },
      {
        protocol: "api-key",
        purchase_url: `${root}/signup`,
        accepts: ["stripe"],
      },
    ],
    discovery: {
      openapi: `${root}/openapi.json`,
      agent_card: `${root}/.well-known/agent-card.json`,
      llms_txt: `${root}/llms.txt`,
      api_catalog: `${root}/.well-known/api-catalog`,
    },
    apis,
    categories,
    api_count: apis.length,
    generated_at: new Date().toISOString(),
  };
}

export function buildPerApiManifest(subdomain: string, host: string): Record<string, unknown> {
  const entry = buildApiEntry(subdomain, host);
  const root = host.endsWith("apimesh.xyz") ? "https://apimesh.xyz" : `https://${host.replace(/^[^.]+\./, "")}`;
  return {
    $schema: `${root}/.well-known/mpp.schema.json`,
    name: entry.name,
    description: entry.description,
    provider: {
      name: "APIMesh",
      url: root,
      contact: "c@vtxathlete.com",
    },
    payment_methods: [
      { protocol: "x402", version: "1", networks: ["base-mainnet"], asset: "USDC" },
      { protocol: "mpp", version: "draft-ryan-httpauth-payment" },
      { protocol: "api-key", purchase_url: `${root}/signup`, accepts: ["stripe"] },
    ],
    api: entry,
    discovery: {
      platform_manifest: `${root}/.well-known/mpp`,
      openapi: `${root}/openapi.json`,
      llms_txt: `${root}/llms.txt`,
    },
    generated_at: new Date().toISOString(),
  };
}
