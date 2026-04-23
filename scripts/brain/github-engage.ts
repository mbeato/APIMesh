/**
 * GitHub Engage — stars relevant repos to increase APIMesh visibility.
 *
 * Stars 5 repos per run matching MCP/x402/agent-payment topics.
 * Tracks starred repos in state file to avoid duplicates.
 * Human-pace rate limiting to avoid GitHub anti-spam detection.
 */

import { join } from "path";

// State lives under data/ (writable under systemd ProtectSystem=strict).
// Previously scripts/brain/*.json caused EROFS crashes on prod (2026-04-22).
const STATE_FILE = join(import.meta.dir, "..", "..", "data", "github-engage-state.json");
const MAX_STARS_PER_RUN = 5;

interface EngageState {
  starredRepos: string[];
  lastRun: string;
}

async function loadState(): Promise<EngageState> {
  try {
    const f = Bun.file(STATE_FILE);
    if (await f.exists()) return await f.json();
  } catch {}
  return { starredRepos: [], lastRun: "" };
}

async function saveState(state: EngageState): Promise<void> {
  state.lastRun = new Date().toISOString();
  await Bun.write(STATE_FILE, JSON.stringify(state, null, 2));
}

/** Search GitHub for repos worth starring. */
async function findReposToStar(alreadyStarred: Set<string>): Promise<string[]> {
  const queries = [
    '"mcp server" stars:>20',
    '"x402" payment',
    '"machine payments protocol"',
    '"ai agent" tools api stars:>50',
    'mcp client typescript stars:>30',
  ];

  const candidates: string[] = [];

  for (const q of queries) {
    if (candidates.length >= MAX_STARS_PER_RUN * 3) break; // enough candidates
    try {
      const res = await fetch(
        `https://api.github.com/search/repositories?q=${encodeURIComponent(q)}&sort=updated&per_page=15`,
        {
          signal: AbortSignal.timeout(10_000),
          headers: {
            Accept: "application/vnd.github+json",
            "User-Agent": "apimesh-engage/1.0",
          },
        }
      );
      if (!res.ok) continue;
      const data = await res.json();
      for (const repo of data.items ?? []) {
        const name = (repo.full_name as string).toLowerCase();
        // Skip our own repos
        if (name.startsWith("mbeato/")) continue;
        // Skip already starred
        if (alreadyStarred.has(name)) continue;
        // Skip archived/forks
        if (repo.archived || repo.fork) continue;
        candidates.push(repo.full_name);
      }
    } catch {}
    await Bun.sleep(1_500);
  }

  return candidates;
}

/** Star a repo using GitHub API. Requires GITHUB_TOKEN. */
async function starRepo(repo: string): Promise<boolean> {
  const token = process.env.GITHUB_TOKEN;
  if (!token) return false;

  try {
    const res = await fetch(`https://api.github.com/user/starred/${repo}`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "apimesh-engage/1.0",
        "Content-Length": "0",
      },
      signal: AbortSignal.timeout(10_000),
    });
    return res.status === 204 || res.status === 304; // 204=starred, 304=already starred
  } catch {
    return false;
  }
}

export async function githubEngage(): Promise<void> {
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    console.log("[github-engage] GITHUB_TOKEN not set — skipping");
    return;
  }

  const state = await loadState();
  const alreadyStarred = new Set(state.starredRepos);

  const candidates = await findReposToStar(alreadyStarred);
  if (candidates.length === 0) {
    console.log("[github-engage] No new repos to star");
    await saveState(state);
    return;
  }

  console.log(`[github-engage] Found ${candidates.length} candidates, starring up to ${MAX_STARS_PER_RUN}`);

  let starred = 0;
  for (const repo of candidates.slice(0, MAX_STARS_PER_RUN)) {
    const ok = await starRepo(repo);
    if (ok) {
      console.log(`[github-engage] Starred ${repo}`);
      state.starredRepos.push(repo.toLowerCase());
      starred++;
    } else {
      console.warn(`[github-engage] Failed to star ${repo}`);
    }
    // Human-pace delay (8-15 seconds between stars)
    await Bun.sleep(8_000 + Math.random() * 7_000);
  }

  await saveState(state);
  console.log(`[github-engage] Starred ${starred} repo(s)`);
}

if (import.meta.main) {
  await githubEngage();
}
