import db, { getActiveApis } from "../../shared/db";
import { join } from "path";

const PUBLIC_DIR = join(import.meta.dir, "..", "..", "public");
const WELL_KNOWN_DIR = join(PUBLIC_DIR, ".well-known");
const APIS_DIR = join(import.meta.dir, "..", "..", "apis");

interface ApiDetail {
  name: string;
  subdomain: string;
  url: string;
  description: string;
  price: string;
  paidEndpoint: string;
  previewEndpoint: string | null;
}

// Manual descriptions for APIs that don't have good ones in source
const DESCRIPTIONS: Record<string, string> = {
  "web-checker": "Check brand/product name availability across 5 TLDs (.com, .io, .dev, .app, .xyz), GitHub, npm, PyPI, and Reddit in one call.",
  "core-web-vitals": "Google PageSpeed Insights analysis — Lighthouse performance, accessibility, SEO scores plus LCP, CLS, INP field data from Chrome UX Report.",
  "security-headers": "Audit 10 HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) with A+ to F grading and remediation suggestions.",
  "redirect-chain": "Trace the full HTTP redirect chain for any URL with per-hop status codes, latency, and loop detection.",
  "email-security": "Validate SPF, DKIM (probes 10 common selectors), and DMARC records for any domain. Detects email provider and grades overall email security.",
  "seo-audit": "Comprehensive on-page SEO analysis — title, meta, headings, images, links, OG tags, JSON-LD, and robots directives with a 0-100 score.",
  "indexability": "5-layer indexability analysis — robots.txt, HTTP status, meta robots, X-Robots-Tag, and canonical. Returns whether a URL is indexable.",
  "indexability-checker": "5-layer indexability analysis — robots.txt, HTTP status, meta robots, X-Robots-Tag, and canonical. Returns whether a URL is indexable.",
  "brand-assets": "Extract brand assets from any domain — logo URL, favicon, theme colors, OG image, and site name.",
  "email-verify": "Verify email addresses — syntax, MX record check, disposable domain detection, role-address detection, and deliverability assessment.",
  "tech-stack": "Detect website technology stack — CMS, frameworks, analytics, CDN, hosting, JS libraries, and CSS frameworks from headers and HTML.",
};

/** Extract endpoint details from an API's index.ts source code */
async function extractApiDetails(name: string, subdomain: string): Promise<ApiDetail> {
  const url = `https://${subdomain}.apimesh.xyz`;
  let description = `${name} API`;
  let price = "$0.005";
  let paidEndpoint = "";
  let previewEndpoint: string | null = null;

  // Priority: static overrides > backlog > source extraction
  if (DESCRIPTIONS[name]) {
    description = DESCRIPTIONS[name];
  } else {
    const backlog = db.query("SELECT description FROM backlog WHERE name = ?").get(name) as { description: string } | null;
    if (backlog?.description) {
      description = backlog.description;
    }
  }

  // Read the API's index.ts for endpoint and pricing info
  const indexPath = join(APIS_DIR, name, "index.ts");
  try {
    const src = await Bun.file(indexPath).text();

    // Extract price from paidRoute/paidRouteWithDiscovery calls
    const priceMatch = src.match(/paidRoute(?:WithDiscovery)?\(\s*["'](\$[\d.]+)["']/);
    if (priceMatch) price = priceMatch[1];

    // Extract price from apiLogger if no paidRoute match
    if (!priceMatch) {
      const loggerMatch = src.match(/apiLogger\(\s*\w+\s*,\s*([\d.]+)\s*\)/);
      if (loggerMatch) price = `$${loggerMatch[1]}`;
    }

    // Extract paid endpoint patterns
    const routeMatch = src.match(/["'](GET|POST)\s+(\/\w+)["']\s*.*?paidRoute/);
    if (routeMatch) paidEndpoint = `${routeMatch[1]} ${url}${routeMatch[2]}`;

    // Extract preview endpoint
    const previewMatch = src.match(/app\.get\(\s*["']\/preview["']/);
    if (previewMatch) previewEndpoint = `GET ${url}/preview`;

    // Extract description from source only if we don't have a good one already
    if (!DESCRIPTIONS[name] && description === `${name} API`) {
      // Look for description in the app.get("/", ...) info handler
      const infoBlock = src.match(/app\.get\(\s*["']\/["'][\s\S]{0,500}?description:\s*["']([^"']{15,300})["']/);
      if (infoBlock) {
        description = infoBlock[1];
      } else {
        // Fallback: look for a longer description string (skip short input field labels)
        const descMatch = src.match(/description:\s*["']([^"']{30,300})["']/);
        if (descMatch) description = descMatch[1];
      }
    }
  } catch {
    // API source not available locally
  }

  return { name, subdomain, url, description, price, paidEndpoint, previewEndpoint };
}

export async function list(): Promise<void> {
  const apis = getActiveApis();
  console.log(`[list] Found ${apis.length} active APIs`);

  await Bun.spawn(["mkdir", "-p", WELL_KNOWN_DIR]).exited;

  const details: ApiDetail[] = [];
  for (const api of apis) {
    details.push(await extractApiDetails(api.name, api.subdomain));
  }

  // 1. x402 discovery
  const discovery = {
    version: "1.0",
    provider: "APIMesh (apimesh.xyz)",
    description: `${details.length} pay-per-call web analysis APIs for AI agents. Supports x402, MPP, and API key payments.`,
    updated_at: new Date().toISOString(),
    network: "eip155:8453",
    apis: details.map((api) => ({
      name: api.name,
      url: api.url,
      description: api.description,
      price: api.price,
      protocol: "x402",
      health: `${api.url}/health`,
      preview: api.previewEndpoint ? `${api.url}/preview` : undefined,
    })),
  };
  await Bun.write(join(WELL_KNOWN_DIR, "x402.json"), JSON.stringify(discovery, null, 2));
  console.log(`[list] Wrote .well-known/x402.json`);

  // 2. llms.txt — detailed per-tool docs for AI agent discovery
  const toolDocs = details.map((api) => {
    let doc = `### ${api.name.replace(/-/g, "_")}\n`;
    if (api.paidEndpoint) {
      doc += `- **Endpoint:** ${api.paidEndpoint}\n`;
    } else {
      doc += `- **Endpoint:** GET ${api.url}/\n`;
    }
    doc += `- **Price:** ${api.price} per call\n`;
    doc += `- **What it does:** ${api.description}\n`;
    if (api.previewEndpoint) {
      doc += `- **Free preview:** ${api.previewEndpoint} — limited results, no payment required.\n`;
    }
    return doc;
  }).join("\n");

  const llmsTxt = `# apimesh.xyz

> APIMesh — ${details.length} pay-per-call web analysis APIs for AI agents and developers. Supports x402 (USDC on Base), Stripe MPP, and API key payments.

## Tools

${toolDocs}

## Payment Methods

1. **x402** — pay per call with USDC on Base. No signup needed. Send payment header with request.
2. **MPP** — Stripe Machine Payments Protocol. Cards + stablecoins.
3. **API key** — traditional auth. Sign up at https://apimesh.xyz/signup, buy credits via Stripe.

## Discovery

- MCP server (npm): \`npx @mbeato/apimesh-mcp-server\`
- x402 discovery: https://apimesh.xyz/.well-known/x402.json
- AI plugin manifest: https://apimesh.xyz/.well-known/ai-plugin.json
- OpenAPI spec: https://apimesh.xyz/.well-known/openapi.json
- GitHub: https://github.com/mbeato/conway

## How to Use

1. Try a free preview: \`GET https://check.apimesh.xyz/preview?name=myapp\`
2. GET any paid endpoint — receive 402 Payment Required with payment details
3. Include payment header and retry — receive the response
`;
  await Bun.write(join(PUBLIC_DIR, "llms.txt"), llmsTxt);
  await Bun.write(join(WELL_KNOWN_DIR, "llms.txt"), llmsTxt);
  console.log(`[list] Wrote llms.txt`);

  // 3. ai-plugin.json
  const aiPlugin = {
    schema_version: "v1",
    name_for_human: "APIMesh",
    name_for_model: "apimesh",
    description_for_human: `${details.length} pay-per-call web analysis APIs for AI agents`,
    description_for_model: `APIMesh provides ${details.length} pay-per-call web analysis APIs. ${details.map(a => `${a.name}: ${a.description} (${a.price})`).join(". ")}. Each API has /health and / info endpoints. Most have free /preview endpoints. Supports x402, MPP, and API key payments.`,
    auth: { type: "none" },
    api: {
      type: "openapi",
      url: "https://apimesh.xyz/.well-known/openapi.json",
    },
    logo_url: "https://apimesh.xyz/logo.png",
    contact_email: "max@apimesh.xyz",
    legal_info_url: "https://apimesh.xyz",
  };
  await Bun.write(join(WELL_KNOWN_DIR, "ai-plugin.json"), JSON.stringify(aiPlugin, null, 2));
  console.log(`[list] Wrote .well-known/ai-plugin.json`);

  // 4. OpenAPI spec
  const openapi = {
    openapi: "3.1.0",
    info: {
      title: "APIMesh",
      description: `${details.length} pay-per-call web analysis APIs for AI agents`,
      version: "2.0.0",
    },
    servers: details.map((api) => ({
      url: api.url,
      description: `${api.name}: ${api.description}`,
    })),
    paths: {
      "/": {
        get: {
          summary: "API info and available endpoints",
          responses: { "200": { description: "API metadata and pricing" } },
        },
      },
      "/health": {
        get: {
          summary: "Health check",
          responses: { "200": { description: "Service is healthy" } },
        },
      },
      "/preview": {
        get: {
          summary: "Free preview — limited results, no payment required",
          responses: { "200": { description: "Preview results" } },
        },
      },
    },
  };
  await Bun.write(join(WELL_KNOWN_DIR, "openapi.json"), JSON.stringify(openapi, null, 2));
  console.log(`[list] Wrote .well-known/openapi.json`);

  // 5. Smithery schemas
  for (const api of details) {
    const schemaPath = join(APIS_DIR, api.name, "smithery.json");
    const schema = {
      name: api.name,
      description: api.description,
      url: api.url,
      protocol: "x402",
      price: api.price,
      tools: [{
        name: api.name,
        description: api.description,
        inputSchema: { type: "object", properties: {} },
      }],
    };
    try {
      await Bun.write(schemaPath, JSON.stringify(schema, null, 2));
    } catch {}
  }
  console.log(`[list] Wrote smithery schemas`);

  console.log("[list] Done");
}

// Run directly
if (import.meta.main) {
  await list();
}
