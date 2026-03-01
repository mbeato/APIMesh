import db, { getActiveApis } from "../../shared/db";
import { join } from "path";

const PUBLIC_DIR = join(import.meta.dir, "..", "..", "public");
const WELL_KNOWN_DIR = join(PUBLIC_DIR, ".well-known");
const APIS_DIR = join(import.meta.dir, "..", "..", "apis");

interface ApiInfo {
  name: string;
  subdomain: string;
  url: string;
  description: string;
}

function getApiInfos(apis: { name: string; subdomain: string }[]): ApiInfo[] {
  return apis.map((api) => {
    const url = `https://${api.subdomain}.apimesh.xyz`;
    // Try to get description from backlog
    const backlog = db.query("SELECT description FROM backlog WHERE name = ?").get(api.name) as { description: string } | null;
    return {
      name: api.name,
      subdomain: api.subdomain,
      url,
      description: backlog?.description ?? `${api.name} API`,
    };
  });
}

export async function list(): Promise<void> {
  const apis = getActiveApis();
  console.log(`[list] Found ${apis.length} active APIs`);

  await Bun.spawn(["mkdir", "-p", WELL_KNOWN_DIR]).exited;

  const apiInfos = getApiInfos(apis);

  // 1. x402 discovery — /.well-known/x402.json
  const discovery = {
    version: "1.0",
    provider: "Conway (apimesh.xyz)",
    description: "Autonomous x402-payable API mesh. Pay per call with USDC on Base.",
    updated_at: new Date().toISOString(),
    network: "eip155:8453",
    apis: apiInfos.map((api) => ({
      name: api.name,
      url: api.url,
      description: api.description,
      protocol: "x402",
      health: `${api.url}/health`,
    })),
  };
  await Bun.write(join(WELL_KNOWN_DIR, "x402.json"), JSON.stringify(discovery, null, 2));
  console.log(`[list] Wrote .well-known/x402.json`);

  // 2. llms.txt — AI agent discovery
  const llmsTxt = `# apimesh.xyz

> Conway API Mesh — autonomous x402-payable APIs. Pay per call with USDC on Base network.

## APIs

${apiInfos.map((api) => `- [${api.name}](${api.url}): ${api.description}`).join("\n")}

## Payment

All endpoints use the x402 payment protocol. Send USDC on Base (chain ID 8453) to access paid routes.
Each API has a free /health endpoint and a free / info endpoint describing available routes and pricing.

## Discovery

- x402 discovery: https://apimesh.xyz/.well-known/x402.json
- AI plugin manifest: https://apimesh.xyz/.well-known/ai-plugin.json

## How to Use

1. GET \`https://<api-name>.apimesh.xyz/\` — see available endpoints and pricing
2. GET any paid endpoint — receive 402 Payment Required with payment details
3. Include x402 payment header and retry — receive the response
`;
  await Bun.write(join(PUBLIC_DIR, "llms.txt"), llmsTxt);
  // Also write to .well-known for immediate access (root /llms.txt needs Caddy config update)
  await Bun.write(join(WELL_KNOWN_DIR, "llms.txt"), llmsTxt);
  console.log(`[list] Wrote llms.txt`);

  // 3. ai-plugin.json — OpenAI-compatible plugin manifest
  const aiPlugin = {
    schema_version: "v1",
    name_for_human: "API Mesh",
    name_for_model: "apimesh",
    description_for_human: "Pay-per-call API marketplace powered by x402 micropayments",
    description_for_model: `API Mesh provides ${apiInfos.length} pay-per-call APIs accessible via x402 micropayments (USDC on Base). Available APIs: ${apiInfos.map(a => `${a.name} (${a.description})`).join("; ")}. Each API has a /health and / info endpoint. Paid endpoints return 402 with payment instructions.`,
    auth: { type: "none" },
    api: {
      type: "openapi",
      url: "https://apimesh.xyz/.well-known/openapi.json",
    },
    logo_url: "https://apimesh.xyz/logo.png",
    contact_email: "conway@apimesh.xyz",
    legal_info_url: "https://apimesh.xyz",
  };
  await Bun.write(join(WELL_KNOWN_DIR, "ai-plugin.json"), JSON.stringify(aiPlugin, null, 2));
  console.log(`[list] Wrote .well-known/ai-plugin.json`);

  // 4. OpenAPI spec — minimal discovery spec for the mesh
  const openapi = {
    openapi: "3.1.0",
    info: {
      title: "API Mesh",
      description: "Autonomous x402-payable API mesh",
      version: "1.0.0",
    },
    servers: apiInfos.map((api) => ({
      url: api.url,
      description: api.description,
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
    },
  };
  await Bun.write(join(WELL_KNOWN_DIR, "openapi.json"), JSON.stringify(openapi, null, 2));
  console.log(`[list] Wrote .well-known/openapi.json`);

  // 5. Smithery tool schemas per API
  for (const api of apiInfos) {
    const schemaPath = join(APIS_DIR, api.name, "smithery.json");
    const schema = {
      name: api.name,
      description: api.description,
      url: api.url,
      protocol: "x402",
      tools: [
        {
          name: api.name,
          description: api.description,
          inputSchema: { type: "object", properties: {} },
        },
      ],
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
