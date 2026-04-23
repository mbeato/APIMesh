/**
 * MCP Client Monitor — scans for new MCP clients and checks if APIMesh is listed.
 *
 * Searches GitHub for MCP client/host repos, checks their docs/registry for
 * APIMesh mentions, and surfaces submission opportunities.
 */

import { join } from "path";

// State lives under data/ (writable under systemd ProtectSystem=strict).
const STATE_FILE = join(import.meta.dir, "..", "..", "data", "mcp-monitor-state.json");

interface MonitorState {
  /** Known MCP client repos we've already checked */
  knownClients: Record<string, {
    repo: string;
    listed: boolean;
    lastChecked: string;
    submissionUrl?: string;
  }>;
  lastRun: string;
}

async function loadState(): Promise<MonitorState> {
  try {
    const f = Bun.file(STATE_FILE);
    if (await f.exists()) return await f.json();
  } catch {}
  return { knownClients: {}, lastRun: "" };
}

async function saveState(state: MonitorState): Promise<void> {
  state.lastRun = new Date().toISOString();
  await Bun.write(STATE_FILE, JSON.stringify(state, null, 2));
}

/** Well-known MCP clients/hosts to always check. */
const KNOWN_MCP_CLIENTS = [
  { repo: "modelcontextprotocol/servers", label: "MCP Official Servers" },
  { repo: "anthropics/claude-code", label: "Claude Code" },
  { repo: "getcursor/cursor", label: "Cursor" },
  { repo: "codeium/windsurf", label: "Windsurf" },
  { repo: "saoudrizwan/claude-dev", label: "Cline" },
  { repo: "continuedev/continue", label: "Continue" },
  { repo: "nicepkg/gpt-runner", label: "GPT Runner" },
  { repo: "AbanteAI/mentat", label: "Mentat" },
];

/** Search GitHub for repos that look like MCP clients/hosts. */
async function discoverNewClients(state: MonitorState): Promise<{ repo: string; label: string }[]> {
  const queries = [
    '"mcp client" OR "mcp host" in:readme language:typescript',
    '"model context protocol" client in:readme',
    '"mcp server" marketplace OR registry OR directory in:readme',
  ];

  const discovered: { repo: string; label: string }[] = [];
  const seen = new Set(Object.keys(state.knownClients));

  // Always include well-known clients
  for (const client of KNOWN_MCP_CLIENTS) {
    if (!seen.has(client.repo.toLowerCase())) {
      discovered.push(client);
      seen.add(client.repo.toLowerCase());
    }
  }

  for (const q of queries) {
    try {
      const res = await fetch(
        `https://api.github.com/search/repositories?q=${encodeURIComponent(q)}&sort=stars&per_page=15`,
        {
          signal: AbortSignal.timeout(10_000),
          headers: {
            Accept: "application/vnd.github+json",
            "User-Agent": "apimesh-mcp-monitor/1.0",
          },
        }
      );
      if (!res.ok) continue;
      const data = await res.json();
      for (const repo of data.items ?? []) {
        const key = (repo.full_name as string).toLowerCase();
        if (seen.has(key)) continue;
        if (repo.stargazers_count < 50) continue; // skip tiny repos
        seen.add(key);
        discovered.push({ repo: repo.full_name, label: repo.name });
      }
    } catch {}
    await Bun.sleep(1_500);
  }

  return discovered;
}

/** Check if a repo's README or docs mention APIMesh. */
async function checkIfListed(repo: string): Promise<boolean> {
  try {
    const res = await fetch(
      `https://api.github.com/search/code?q=apimesh+repo:${repo}`,
      {
        signal: AbortSignal.timeout(10_000),
        headers: {
          Accept: "application/vnd.github+json",
          "User-Agent": "apimesh-mcp-monitor/1.0",
        },
      }
    );
    if (!res.ok) return false;
    const data = await res.json();
    return (data.total_count ?? 0) > 0;
  } catch {
    return false;
  }
}

export async function mcpClientMonitor(): Promise<void> {
  console.log("[mcp-monitor] Scanning for MCP clients...");

  const state = await loadState();
  const clients = await discoverNewClients(state);

  if (clients.length === 0) {
    console.log("[mcp-monitor] No new MCP clients discovered");
    await saveState(state);
    return;
  }

  console.log(`[mcp-monitor] Checking ${clients.length} MCP client(s) for APIMesh listing`);

  const needsSubmission: string[] = [];

  for (const client of clients) {
    const repoKey = client.repo.toLowerCase();
    const listed = await checkIfListed(client.repo);

    state.knownClients[repoKey] = {
      repo: client.repo,
      listed,
      lastChecked: new Date().toISOString(),
    };

    if (listed) {
      console.log(`[mcp-monitor] ${client.label} (${client.repo}) — APIMesh listed`);
    } else {
      console.log(`[mcp-monitor] ${client.label} (${client.repo}) — NOT listed, needs submission`);
      needsSubmission.push(`${client.label} (${client.repo})`);
    }

    await Bun.sleep(2_000); // GitHub code search rate limit
  }

  if (needsSubmission.length > 0) {
    console.log(`\n[mcp-monitor] === ACTION NEEDED ===`);
    console.log(`[mcp-monitor] APIMesh not listed in ${needsSubmission.length} MCP client(s):`);
    for (const s of needsSubmission) {
      console.log(`[mcp-monitor]   - ${s}`);
    }
  }

  await saveState(state);
  console.log("[mcp-monitor] Done");
}

if (import.meta.main) {
  await mcpClientMonitor();
}
