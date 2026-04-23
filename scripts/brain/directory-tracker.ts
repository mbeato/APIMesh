/**
 * Directory Tracker — tracks which directories/aggregators APIMesh is listed on.
 *
 * Maintains a state file of target directories with:
 * - Submission status (submitted, listed, pending, not-submitted)
 * - Submission URL/instructions
 * - Last checked date
 *
 * Outputs an action list for human follow-up.
 */

import { join } from "path";

// State lives under data/ (writable under systemd ProtectSystem=strict).
const STATE_FILE = join(import.meta.dir, "..", "..", "data", "directory-state.json");

interface DirectoryEntry {
  name: string;
  url: string;
  category: "api-marketplace" | "mcp-registry" | "ai-directory" | "dev-directory" | "awesome-list" | "product-launch" | "a2a-registry" | "llms-directory";
  status: "listed" | "submitted" | "pending" | "not-submitted" | "rejected" | "blocked";
  submissionUrl?: string;
  listingUrl?: string;
  notes?: string;
  lastChecked: string;
}

interface DirectoryState {
  directories: DirectoryEntry[];
  lastRun: string;
}

/** All target directories for APIMesh with known status. */
const TARGET_DIRECTORIES: Omit<DirectoryEntry, "lastChecked">[] = [
  // MCP Registries (already on most)
  { name: "Official MCP Registry", url: "https://registry.modelcontextprotocol.io", category: "mcp-registry", status: "not-submitted", submissionUrl: "https://github.com/modelcontextprotocol/registry", notes: "THE canonical registry (MCP + Linux Foundation, preview since late 2025). Submit via GitHub PR. TOP PRIORITY — we are missing from the official one." },
  { name: "Smithery", url: "https://smithery.ai", category: "mcp-registry", status: "listed", submissionUrl: "https://smithery.ai/submit", notes: "7,000+ servers" },
  { name: "mcp.so", url: "https://mcp.so", category: "mcp-registry", status: "listed" },
  { name: "Glama.ai", url: "https://glama.ai/mcp/servers", category: "mcp-registry", status: "listed", notes: "21,845+ servers (2026-04). Largest directory in ecosystem." },
  { name: "PulseMCP", url: "https://pulsemcp.com", category: "mcp-registry", status: "not-submitted", notes: "11,840+ servers, hand-reviewed daily by founder since MCP launch week. Missing from our list." },
  { name: "mcpserver.dev", url: "https://mcpserver.dev", category: "mcp-registry", status: "submitted", notes: "Pending review" },
  { name: "modelcontextprotocol/servers (examples)", url: "https://github.com/modelcontextprotocol/servers", category: "mcp-registry", status: "not-submitted", submissionUrl: "https://github.com/modelcontextprotocol/servers/issues", notes: "Examples repo, NOT the official registry. Lower priority than registry.modelcontextprotocol.io above." },
  { name: "Cline MCP Marketplace", url: "https://github.com/cline/cline", category: "mcp-registry", status: "submitted", notes: "Issue #1104 filed" },

  // API Marketplaces
  { name: "RapidAPI", url: "https://rapidapi.com", category: "api-marketplace", status: "not-submitted", submissionUrl: "https://rapidapi.com/provider", notes: "List individual APIs here" },
  { name: "API List", url: "https://apilist.fun", category: "api-marketplace", status: "not-submitted", submissionUrl: "https://apilist.fun/submit" },
  { name: "Public APIs (GitHub)", url: "https://github.com/public-apis/public-apis", category: "api-marketplace", status: "not-submitted", submissionUrl: "https://github.com/public-apis/public-apis/pulls", notes: "280K+ stars, PR to add" },
  { name: "APIs.guru", url: "https://apis.guru", category: "api-marketplace", status: "not-submitted", notes: "Auto-discovers from /.well-known/openapi.yaml" },
  { name: "Postman API Network", url: "https://www.postman.com/explore", category: "api-marketplace", status: "not-submitted", submissionUrl: "https://www.postman.com/api-network", notes: "Generate Postman collections from OpenAPI" },

  // x402 / MPP ecosystem
  { name: "x402.org/ecosystem", url: "https://www.x402.org/ecosystem", category: "api-marketplace", status: "not-submitted", notes: "Official Linux Foundation ecosystem page (2026-04). Founding members: Google, Visa, Stripe, AWS, Mastercard, Circle, Microsoft, Shopify, Amex. TOP PRIORITY." },
  { name: "x402scan.com", url: "https://x402scan.com", category: "api-marketplace", status: "not-submitted", notes: "Canonical x402 leaderboard. Real txn data. Submit after verifying our /.well-known/x402 lists all paid endpoints." },
  { name: "x402-list.com", url: "https://x402-list.com", category: "api-marketplace", status: "not-submitted", notes: "2026 directory of x402 API services. Agent-first JSON feed, live uptime." },
  { name: "x402.direct", url: "https://x402.direct", category: "api-marketplace", status: "not-submitted", notes: "Search engine for agent economy. 4,000+ x402 APIs, trust-scored by category/network/quality." },
  { name: "x402index.com", url: "https://www.x402index.com/docs", category: "api-marketplace", status: "not-submitted", notes: "Has programmatic submission API — preferred submission path for automation." },
  { name: "402index.io", url: "https://402index.io", category: "api-marketplace", status: "listed", notes: "Domain verified" },
  { name: "awesome-x402", url: "https://github.com/xpaysh/awesome-x402", category: "awesome-list", status: "listed", notes: "Merged" },
  { name: "awesome-mpp", url: "https://github.com/mbeato/awesome-mpp", category: "awesome-list", status: "listed", notes: "We own this" },
  { name: "coinbase/x402 ecosystem", url: "https://github.com/coinbase/x402", category: "awesome-list", status: "submitted", notes: "PR #1864 pending" },
  { name: "mpp.dev (provider directory)", url: "https://mpp.dev", category: "api-marketplace", status: "not-submitted", notes: "Canonical MPP (Tempo + Stripe). 100+ integrations at launch (Alchemy, Dune, Merit, Parallel). No public submission form yet — watch." },
  { name: "Cloudflare AI Marketplace", url: "https://developers.cloudflare.com/agents/x402/", category: "api-marketplace", status: "not-submitted", notes: "Bills on inference, supports x402 natively. Strong fit." },
  { name: "mpppay.fun", url: "https://mpppay.fun", category: "api-marketplace", status: "rejected", notes: "DEAD for payment discovery: site pivoted to 'Headless Compute for Agents' in 2026-04. Our listing is decaying asset — do not invest more effort here." },

  // A2A ecosystem (blocked until /.well-known/agent-card.json is served)
  { name: "A2A Registry", url: "https://a2aregistry.org", category: "a2a-registry", status: "blocked", submissionUrl: "https://a2aregistry.org/api/agents/register", notes: "Global A2A registry. Health-checks every 30 min. Submission = POST with our well-known URI. BLOCKED on us publishing /.well-known/agent-card.json first." },

  // llms.txt directories
  { name: "llmstxt.site", url: "https://llmstxt.site", category: "llms-directory", status: "not-submitted", submissionUrl: "https://llmstxt.site/submit", notes: "Central /llms.txt directory. We already serve /llms.txt — just need to fill the form." },
  { name: "directory.llmstxt.cloud", url: "https://directory.llmstxt.cloud", category: "llms-directory", status: "not-submitted", notes: "Alternate llms.txt directory" },

  // AI Tool Directories
  { name: "There's an AI for That", url: "https://theresanaiforthat.com", category: "ai-directory", status: "not-submitted", submissionUrl: "https://theresanaiforthat.com/submit" },
  { name: "FutureTools", url: "https://www.futuretools.io", category: "ai-directory", status: "not-submitted", submissionUrl: "https://www.futuretools.io/submit-a-tool" },
  { name: "ToolsForHumans.ai", url: "https://toolsforhumans.ai", category: "ai-directory", status: "not-submitted" },

  // Dev Directories
  { name: "AlternativeTo", url: "https://alternativeto.net", category: "dev-directory", status: "not-submitted", submissionUrl: "https://alternativeto.net/add-app/", notes: "List as alternative to RapidAPI" },
  { name: "DevHunt", url: "https://devhunt.org", category: "dev-directory", status: "not-submitted", submissionUrl: "https://devhunt.org/submit" },
  { name: "LibHunt", url: "https://www.libhunt.com", category: "dev-directory", status: "not-submitted" },

  // Product Launch (save for milestone)
  { name: "Product Hunt", url: "https://producthunt.com", category: "product-launch", status: "not-submitted", notes: "Save for 30+ APIs or major feature milestone" },
  { name: "Hacker News (Show HN)", url: "https://news.ycombinator.com", category: "product-launch", status: "not-submitted", notes: "Save for compelling story" },

  // Showcase Pages
  { name: "Bun Showcase", url: "https://bun.sh", category: "dev-directory", status: "not-submitted", notes: "Built with Bun — check if they have ecosystem page" },
  { name: "Hono Showcase", url: "https://hono.dev", category: "dev-directory", status: "not-submitted", notes: "Uses Hono — check middleware/ecosystem page" },

  // Apify Store
  { name: "Apify Store", url: "https://apify.com/store", category: "api-marketplace", status: "listed", notes: "5/7 Actors published" },
];

async function loadState(): Promise<DirectoryState> {
  try {
    const f = Bun.file(STATE_FILE);
    if (await f.exists()) return await f.json();
  } catch {}
  return { directories: [], lastRun: "" };
}

async function saveState(state: DirectoryState): Promise<void> {
  state.lastRun = new Date().toISOString();
  await Bun.write(STATE_FILE, JSON.stringify(state, null, 2));
}

export async function directoryTracker(): Promise<void> {
  console.log("[directory-tracker] Checking directory status...");

  const state = await loadState();
  const existingByName = new Map(state.directories.map(d => [d.name, d]));

  // Merge target directories with existing state
  const updated: DirectoryEntry[] = [];
  for (const target of TARGET_DIRECTORIES) {
    const existing = existingByName.get(target.name);
    if (existing) {
      // Keep existing status but update metadata
      updated.push({
        ...existing,
        url: target.url,
        category: target.category,
        submissionUrl: target.submissionUrl ?? existing.submissionUrl,
        notes: target.notes ?? existing.notes,
      });
    } else {
      updated.push({
        ...target,
        lastChecked: new Date().toISOString(),
      });
    }
  }

  state.directories = updated;

  // Report
  const byStatus = {
    listed: updated.filter(d => d.status === "listed"),
    submitted: updated.filter(d => d.status === "submitted" || d.status === "pending"),
    notSubmitted: updated.filter(d => d.status === "not-submitted"),
  };

  console.log(`[directory-tracker] ${updated.length} directories tracked:`);
  console.log(`[directory-tracker]   Listed: ${byStatus.listed.length}`);
  console.log(`[directory-tracker]   Submitted/Pending: ${byStatus.submitted.length}`);
  console.log(`[directory-tracker]   Not submitted: ${byStatus.notSubmitted.length}`);

  if (byStatus.notSubmitted.length > 0) {
    console.log(`\n[directory-tracker] === SUBMISSION OPPORTUNITIES ===`);
    for (const d of byStatus.notSubmitted) {
      const sub = d.submissionUrl ? ` → ${d.submissionUrl}` : "";
      const note = d.notes ? ` (${d.notes})` : "";
      console.log(`[directory-tracker]   ${d.name}${sub}${note}`);
    }
  }

  await saveState(state);
  console.log("[directory-tracker] Done");
}

if (import.meta.main) {
  await directoryTracker();
}
