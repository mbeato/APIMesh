/**
 * MPP Ecosystem Scanner — keeps awesome-mpp directory current.
 *
 * 1. Scrapes mpppay.fun for live providers
 * 2. Searches GitHub + npm for MPP repos/packages
 * 3. Diffs against awesome-mpp README.md
 * 4. Adds new providers to the correct section
 * 5. Opens notification issues on new projects' repos
 * 6. Reviews and auto-merges valid PRs on awesome-mpp
 *
 * State persisted in scanner-state.json to avoid re-processing
 * known projects and retrying failed issue repos every run.
 */

import { join } from "path";

// In data/ (covered by systemd ReadWritePaths) rather than alongside source.
const STATE_FILE = join(import.meta.dir, "..", "..", "data", "scanner-state.json");

interface ScannerState {
  /** Project IDs we've already processed (found + diffed) */
  knownProjectIds: string[];
  /** Repos where issue creation failed permanently (disabled, no permission) */
  failedIssueRepos: string[];
  /** Repos where we successfully opened an issue */
  notifiedRepos: string[];
  /** Last run ISO timestamp */
  lastRun: string;
}

async function loadState(): Promise<ScannerState> {
  try {
    const f = Bun.file(STATE_FILE);
    if (await f.exists()) return await f.json();
  } catch {}
  return { knownProjectIds: [], failedIssueRepos: [], notifiedRepos: [], lastRun: "" };
}

async function saveState(state: ScannerState): Promise<void> {
  state.lastRun = new Date().toISOString();
  await Bun.write(STATE_FILE, JSON.stringify(state, null, 2));
}

interface MppProvider {
  id: string;
  name: string;
  category: string;
  description: string;
  websiteUrl: string;
}

/** Scrape live providers from mpppay.fun ecosystem page. */
async function scrapeMppProviders(): Promise<MppProvider[]> {
  const pageRes = await fetch("https://www.mpppay.fun/ecosystem", {
    signal: AbortSignal.timeout(10_000),
  });
  if (!pageRes.ok) throw new Error(`mpppay.fun returned ${pageRes.status}`);

  const html = await pageRes.text();
  const jsMatch = html.match(/src="(\/assets\/index-[^"]+\.js)"/);
  if (!jsMatch) throw new Error("Could not find JS bundle URL in mpppay.fun");

  const jsRes = await fetch(`https://www.mpppay.fun${jsMatch[1]}`, {
    signal: AbortSignal.timeout(15_000),
  });
  if (!jsRes.ok) throw new Error(`JS bundle fetch failed: ${jsRes.status}`);

  const js = await jsRes.text();
  // Step 1: Extract core provider data (require live:!0)
  const corePattern = /id:`([^`]+)`,name:`([^`]+)`,category:`([^`]+)`,live:!0,description:`([^`]*)`/g;
  const providers: MppProvider[] = [];
  const seen = new Set<string>();

  let match;
  while ((match = corePattern.exec(js)) !== null) {
    const id = match[1];
    if (seen.has(id)) continue;
    seen.add(id);

    // Try to find websiteUrl near this match
    const after = js.slice(match.index, match.index + 500);
    const urlMatch = after.match(/websiteUrl:`([^`]+)`/);

    providers.push({
      id,
      name: match[2],
      category: match[3],
      description: match[4].slice(0, 200),
      websiteUrl: urlMatch?.[1] || "",
    });
  }

  return providers;
}

/**
 * Relevance filter for GitHub/npm results.
 *
 * "mpp" alone is too broad — it matches "Multi-Party Payment", "Mobile Payment
 * Platform", "mpp-webrtc", etc. We require STRONG signals that confirm the
 * project is part of the Tempo Machine Payments Protocol ecosystem.
 */

/**
 * Strict relevance filter for GitHub/npm results.
 *
 * The description (not just name) must contain clear MPP ecosystem signals.
 * "mpp" in a repo name alone is NOT enough — it matches webrtc, tiktok, etc.
 */
function isMppRelated(_name: string, description: string): boolean {
  const text = `${_name} ${description}`.toLowerCase();

  // No description = can't verify relevance
  if (description.length < 10) return false;

  // Tier 1: Unambiguous — instant accept
  if (text.includes("machine payments protocol")) return true;
  if (text.includes("machine payment protocol")) return true;
  if (text.includes("mpppay")) return true;
  if (text.includes("mpp.tempo")) return true;
  if (text.includes("tempo.xyz")) return true;

  // Tier 2: x402 + payment context
  if (text.includes("x402") && (text.includes("payment") || text.includes("402 "))) return true;

  // REJECT everything else — bare "mpp" is too ambiguous
  // (matches Multi-Party Payment, Mobile Payment Platform, WebRTC MPP, etc.)
  return false;
}

/** Search GitHub for MPP-related repos. */
async function searchGitHub(): Promise<MppProvider[]> {
  const queries = [
    '"machine payments protocol"',
    "mpppay",
    '"mpp" "tempo.xyz"',
    '"x402" "mpp" payment',
  ];
  const providers: MppProvider[] = [];
  const seen = new Set<string>();

  for (const q of queries) {
    try {
      const res = await fetch(
        `https://api.github.com/search/repositories?q=${encodeURIComponent(q)}&sort=updated&per_page=30`,
        {
          signal: AbortSignal.timeout(10_000),
          headers: {
            "Accept": "application/vnd.github+json",
            "User-Agent": "awesome-mpp-scanner/1.0",
          },
        }
      );
      if (!res.ok) { await res.text().catch(() => {}); continue; }
      const data = await res.json();
      for (const repo of data.items || []) {
        const key = (repo.full_name as string).toLowerCase();
        if (seen.has(key)) continue;
        if (repo.fork || repo.archived) continue;
        seen.add(key);
        const desc = (repo.description || "").slice(0, 200);
        // Must pass relevance check
        if (!isMppRelated(repo.name, desc)) continue;
        providers.push({
          id: `gh-${key}`,
          name: repo.name,
          category: "GitHub",
          description: desc,
          websiteUrl: repo.html_url,
        });
      }
    } catch {
      console.warn(`[scanner] GitHub search "${q}" failed — skipping`);
    }
    await Bun.sleep(1_500);
  }

  console.log(`[scanner] GitHub: found ${providers.length} MPP repos`);
  return providers;
}

/** Search npm for MPP-related packages. */
async function searchNpm(): Promise<MppProvider[]> {
  const queries = ["machine-payments-protocol", "mpppay", "mpp tempo.xyz", "x402 mpp payment"];
  const providers: MppProvider[] = [];
  const seen = new Set<string>();

  for (const q of queries) {
    try {
      const res = await fetch(
        `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(q)}&size=20`,
        { signal: AbortSignal.timeout(10_000) }
      );
      if (!res.ok) { await res.text().catch(() => {}); continue; }
      const data = await res.json();
      for (const item of data.objects || []) {
        const pkg = item.package;
        if (!pkg?.name || seen.has(pkg.name)) continue;
        const desc = (pkg.description || "").slice(0, 200);
        // Must pass relevance check
        if (!isMppRelated(pkg.name, desc)) continue;
        seen.add(pkg.name);
        const url = pkg.links?.repository || pkg.links?.homepage || `https://www.npmjs.com/package/${pkg.name}`;
        providers.push({
          id: `npm-${pkg.name}`,
          name: pkg.name,
          category: "npm",
          description: desc,
          websiteUrl: url,
        });
      }
    } catch {
      console.warn(`[scanner] npm search "${q}" failed — skipping`);
    }
  }

  console.log(`[scanner] npm: found ${providers.length} MPP packages`);
  return providers;
}

// Smithery removed — API endpoint has been returning 404 since at least April 2026

/** Parse existing project names AND URLs from awesome-mpp README. */
function parseExisting(readme: string): { names: Set<string>; urls: Set<string> } {
  const names = new Set<string>();
  const urls = new Set<string>();
  const pattern = /- \[([^\]]+)\]\(([^)]+)\)/g;
  let match;
  while ((match = pattern.exec(readme)) !== null) {
    names.add(match[1].toLowerCase().trim());
    urls.add(match[2].toLowerCase().trim());
  }
  return { names, urls };
}

/** Map source category → awesome-mpp section header. */
function mapCategoryToSection(category: string): string {
  switch (category) {
    // mpppay.fun categories
    case "AI":         return "### Applications";
    case "Blockchain": return "### Other Chains";
    case "Compute":    return "## Infrastructure and Proxies";
    case "Data":       return "### Applications";
    case "Search":     return "## Agent Tools and CLIs";
    case "Social":     return "### Applications";
    case "Storage":    return "## Infrastructure and Proxies";
    case "Web":        return "### Applications";
    // External source categories
    case "GitHub":     return "## Community Projects";
    case "npm":        return "## Middleware and Extensions";
    case "Smithery":   return "## Agent Tools and CLIs";
    default:           return "### Applications";
  }
}

/** Clean a URL for awesome-lint compliance. */
function cleanUrl(url: string): string {
  return url.replace(/^git\+/, "").replace(/\.git$/, "");
}

/** Ensure description starts uppercase and ends with a period. */
function cleanDescription(desc: string): string {
  let d = desc.trim();
  if (!d) return "MPP ecosystem project.";
  // Capitalize first letter
  d = d.charAt(0).toUpperCase() + d.slice(1);
  // End with period
  if (!d.endsWith(".")) d += ".";
  // Fix common spell check issues
  d = d.replace(/\bblockchain\b/g, "Blockchain");
  return d;
}

/** Insert a line at the end of a section (before the next heading). */
function insertInSection(readme: string, sectionHeader: string, line: string): string {
  const headerIdx = readme.indexOf(sectionHeader);
  if (headerIdx === -1) {
    const contribIdx = readme.indexOf("## Contributing");
    if (contribIdx === -1) return readme + "\n" + line + "\n";
    return readme.slice(0, contribIdx) + line + "\n\n" + readme.slice(contribIdx);
  }

  const afterHeader = headerIdx + sectionHeader.length;
  const rest = readme.slice(afterHeader);
  const headerLevel = sectionHeader.startsWith("### ") ? 3 : 2;
  const nextHeadingPattern = headerLevel === 3
    ? /\n(?=## [^#]|### )/
    : /\n(?=## [^#])/;

  const nextMatch = rest.match(nextHeadingPattern);
  if (nextMatch && nextMatch.index !== undefined) {
    const insertPos = afterHeader + nextMatch.index;
    return readme.slice(0, insertPos) + "\n" + line + readme.slice(insertPos);
  }
  return readme.trimEnd() + "\n" + line + "\n";
}

/** Run a shell command and return stdout. Returns null on failure. */
async function run(cmd: string[], timeoutMs = 30_000): Promise<string | null> {
  try {
    const isGit = cmd[0] === "git";
    const proc = Bun.spawn(cmd, {
      stdout: "pipe",
      stderr: "pipe",
      ...(isGit ? { env: { ...process.env, GIT_TERMINAL_PROMPT: "0" } } : {}),
    });
    const timer = setTimeout(() => proc.kill(), timeoutMs);
    const exit = await proc.exited;
    clearTimeout(timer);
    if (exit !== 0) {
      const stderr = await new Response(proc.stderr).text();
      console.warn(`[scanner] ${cmd.slice(0, 3).join(" ")} failed — ${stderr.trim()}`);
      return null;
    }
    return new Response(proc.stdout).text();
  } catch (err) {
    console.warn(`[scanner] ${cmd.slice(0, 3).join(" ")} error — ${err}`);
    return null;
  }
}

/** Check if `gh` CLI is available. */
async function hasGhCli(): Promise<boolean> {
  try {
    const proc = Bun.spawn(["which", "gh"], { stdout: "pipe", stderr: "pipe" });
    return (await proc.exited) === 0;
  } catch {
    return false;
  }
}

// ─── Step 3: Diff and push via GitHub API (no git clone needed) ─────────────

/** Update README via GitHub Contents API — avoids git clone hanging in Bun. */
async function updateAwesomeMpp(newProviders: MppProvider[], currentReadme: string, existingParsed: { names: Set<string>; urls: Set<string> }): Promise<void> {
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    console.warn("[scanner] GITHUB_TOKEN not set — cannot push updates");
    return;
  }

  let readme = currentReadme;
  const names: string[] = [];
  for (const p of newProviders) {
    const url = cleanUrl(p.websiteUrl);
    if (!url || url === "https://www.mpppay.fun/ecosystem" || existingParsed.urls.has(url.toLowerCase())) {
      console.log(`[scanner] skipping ${p.name} — no unique URL or duplicate link`);
      continue;
    }
    const section = mapCategoryToSection(p.category);
    const desc = cleanDescription(p.description);
    const entry = `- [${p.name}](${url}) - ${desc}`;
    readme = insertInSection(readme, section, entry);
    existingParsed.urls.add(url.toLowerCase());
    names.push(p.name);
  }

  if (names.length === 0) {
    console.log("[scanner] no entries with unique URLs to add");
    return;
  }

  // Get current file SHA (required for update)
  const metaRes = await fetch("https://api.github.com/repos/mbeato/awesome-mpp/contents/README.md", {
    headers: { Authorization: `Bearer ${token}`, "User-Agent": "awesome-mpp-scanner/1.0" },
    signal: AbortSignal.timeout(10_000),
  });
  if (!metaRes.ok) { console.warn(`[scanner] GitHub API meta failed: ${metaRes.status}`); return; }
  const meta = await metaRes.json() as { sha: string };

  const commitMsg = `scanner: add ${names.length} new MPP project${names.length > 1 ? "s" : ""} (${names.join(", ")})`;
  const updateRes = await fetch("https://api.github.com/repos/mbeato/awesome-mpp/contents/README.md", {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "User-Agent": "awesome-mpp-scanner/1.0",
    },
    body: JSON.stringify({
      message: commitMsg,
      content: Buffer.from(readme).toString("base64"),
      sha: meta.sha,
    }),
    signal: AbortSignal.timeout(15_000),
  });

  if (updateRes.ok) {
    console.log(`[scanner] pushed ${names.length} new project(s): ${names.join(", ")}`);
  } else {
    const err = await updateRes.text();
    console.warn(`[scanner] GitHub API update failed: ${updateRes.status} — ${err.slice(0, 200)}`);
  }
}


// ─── Step 4: Open notification issues on new projects' GitHub repos ─────────

/**
 * Try to find a GitHub repo for a provider by checking their website URL.
 * Returns "owner/repo" if found, null otherwise.
 */
async function findGitHubRepo(provider: MppProvider): Promise<string | null> {
  // Direct GitHub URL
  if (provider.websiteUrl.includes("github.com")) {
    const m = provider.websiteUrl.match(/github\.com\/([^/]+\/[^/]+)/);
    if (m) return m[1].replace(/\.git$/, "");
  }

  // Check website for GitHub links
  if (!provider.websiteUrl) return null;
  try {
    const res = await fetch(provider.websiteUrl, {
      signal: AbortSignal.timeout(8_000),
      headers: { "User-Agent": "awesome-mpp-scanner/1.0" },
      redirect: "follow",
    });
    if (!res.ok) return null;
    const html = await res.text();
    const ghMatch = html.match(/https?:\/\/github\.com\/([a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+)/);
    if (ghMatch) return ghMatch[1].replace(/\.git$/, "");
  } catch {
    // Website unreachable or timeout — skip
  }
  return null;
}

const ISSUE_TITLE = "Listed on Awesome MPP 🎉";

function issueBody(providerName: string): string {
  return `hi ${providerName.toLowerCase()} team

your project has been added to [awesome-mpp](https://github.com/mbeato/awesome-mpp), the community directory for the Machine Payments Protocol ecosystem.

you can find your listing in the README. if you'd like to update the description or add more details, feel free to open a PR.

thanks for building in the MPP ecosystem

max`;
}

async function openIssuesOnNewRepos(newProviders: MppProvider[], state: ScannerState): Promise<void> {
  const failedSet = new Set(state.failedIssueRepos.map(r => r.toLowerCase()));
  const notifiedSet = new Set(state.notifiedRepos.map(r => r.toLowerCase()));
  let opened = 0;

  for (const p of newProviders) {
    const repo = await findGitHubRepo(p);
    if (!repo) {
      console.log(`[scanner] no GitHub repo found for ${p.name} — skipping issue`);
      continue;
    }

    const repoLower = repo.toLowerCase();

    // Skip our own repos
    if (repoLower.startsWith("mbeato/")) continue;

    // Skip repos we already notified or that permanently failed
    if (notifiedSet.has(repoLower)) {
      console.log(`[scanner] already notified ${repo} — skipping`);
      continue;
    }
    if (failedSet.has(repoLower)) {
      console.log(`[scanner] ${repo} previously failed — skipping`);
      continue;
    }

    // Open the issue
    const result = await run(["gh", "issue", "create", "-R", repo, "--title", ISSUE_TITLE, "--body", issueBody(p.name)]);
    if (result !== null) {
      console.log(`[scanner] opened issue on ${repo}`);
      state.notifiedRepos.push(repoLower);
      notifiedSet.add(repoLower);
      opened++;
    } else {
      // Permanent failure — don't retry (issues disabled, no permission, etc.)
      state.failedIssueRepos.push(repoLower);
      failedSet.add(repoLower);
    }

    // Rate limit
    await Bun.sleep(2_000);
  }
  if (opened > 0) console.log(`[scanner] opened ${opened} notification issue(s)`);
}

// ─── Step 5: Review and auto-merge valid PRs ────────────────────────────────

interface PullRequest {
  number: number;
  title: string;
  user: string;
  body: string;
  additions: number;
  deletions: number;
  changedFiles: number;
  mergeable: boolean;
}

async function handlePullRequests(): Promise<void> {
  // List open PRs
  const prsJson = await run([
    "gh", "api", "repos/mbeato/awesome-mpp/pulls",
    "--jq", ".",
  ]);
  if (!prsJson) return;

  let prs: any[];
  try {
    prs = JSON.parse(prsJson);
  } catch {
    console.warn("[scanner] failed to parse PR list");
    return;
  }

  if (prs.length === 0) {
    console.log("[scanner] no open PRs on awesome-mpp");
    return;
  }

  console.log(`[scanner] found ${prs.length} open PR(s) on awesome-mpp`);

  for (const pr of prs) {
    const num = pr.number;
    const title = pr.title || "";
    const body = pr.body || "";
    const user = pr.user?.login || "unknown";

    // Get diff to check what's being changed
    const diff = await run(["gh", "api", `repos/mbeato/awesome-mpp/pulls/${num}`, "--jq", "{additions, deletions, changed_files, mergeable}"]);
    if (!diff) continue;

    let details: { additions: number; deletions: number; changed_files: number; mergeable: boolean };
    try {
      details = JSON.parse(diff);
    } catch {
      continue;
    }

    // Get the actual files changed
    const filesJson = await run(["gh", "api", `repos/mbeato/awesome-mpp/pulls/${num}/files`, "--jq", "[.[].filename]"]);
    if (!filesJson) continue;
    const files: string[] = JSON.parse(filesJson);

    // Validation criteria for auto-merge:
    // 1. Only README.md changed
    // 2. Small diff (additions ≤ 5, deletions ≤ 2)
    // 3. Title follows "Add X to Y" pattern
    // 4. Not from our own account
    const onlyReadme = files.length === 1 && files[0] === "README.md";
    const smallDiff = details.additions <= 5 && details.deletions <= 2;
    const validTitle = /^add\s+/i.test(title);

    if (onlyReadme && smallDiff && validTitle) {
      // Get the actual diff content to verify it's a valid listing entry
      const patchJson = await run(["gh", "api", `repos/mbeato/awesome-mpp/pulls/${num}/files`, "--jq", ".[0].patch"]);
      const patch = patchJson?.trim() || "";

      // Check if the added line follows the format: - [Name](url) - Description.
      const hasValidEntry = /^\+- \[[^\]]+\]\([^)]+\) - .+/m.test(patch);
      // Check for suspicious content
      const hasSuspicious = /\b(hack|spam|casino|porn|xxx|phish|scam)\b/i.test(patch);

      if (hasValidEntry && !hasSuspicious) {
        console.log(`[scanner] auto-merging PR #${num}: "${title}" by ${user}`);
        const mergeResult = await run(["gh", "pr", "merge", String(num), "-R", "mbeato/awesome-mpp", "--merge", "--body", "auto-merged by awesome-mpp scanner"]);
        if (mergeResult !== null) {
          console.log(`[scanner] merged PR #${num}`);
        }
      } else {
        console.log(`[scanner] PR #${num} by ${user} needs manual review — content didn't pass validation`);
      }
    } else {
      const reasons: string[] = [];
      if (!onlyReadme) reasons.push(`changes ${files.length} file(s): ${files.join(", ")}`);
      if (!smallDiff) reasons.push(`large diff (+${details.additions}/-${details.deletions})`);
      if (!validTitle) reasons.push(`title doesn't match "Add X" pattern`);
      console.log(`[scanner] PR #${num} by ${user} needs manual review — ${reasons.join(", ")}`);
    }
  }
}

// ─── Main ───────────────────────────────────────────────────────────────────

export async function scanner(): Promise<void> {
  console.log("[scanner] Scanning MPP ecosystem across multiple sources...");

  const state = await loadState();
  const knownIds = new Set(state.knownProjectIds);

  // Step 1: Gather from all sources
  const allProviders: MppProvider[] = [];
  const dedup = new Set<string>();

  // 1a. mpppay.fun (primary)
  try {
    const mpp = await scrapeMppProviders();
    console.log(`[scanner] mpppay.fun: ${mpp.length} live providers`);
    for (const p of mpp) {
      const key = p.name.toLowerCase().trim();
      if (!dedup.has(key)) { dedup.add(key); allProviders.push(p); }
    }
  } catch (err) {
    console.warn(`[scanner] mpppay.fun scrape failed — ${err}`);
  }

  // 1b. GitHub repos
  try {
    const gh = await searchGitHub();
    for (const p of gh) {
      const key = p.name.toLowerCase().trim();
      if (!dedup.has(key)) { dedup.add(key); allProviders.push(p); }
    }
  } catch (err) {
    console.warn(`[scanner] GitHub search failed — ${err}`);
  }

  // 1c. npm packages
  try {
    const npm = await searchNpm();
    for (const p of npm) {
      const key = p.name.toLowerCase().trim();
      if (!dedup.has(key)) { dedup.add(key); allProviders.push(p); }
    }
  } catch (err) {
    console.warn(`[scanner] npm search failed — ${err}`);
  }

  console.log(`[scanner] Total unique projects across all sources: ${allProviders.length}`);

  // Filter out projects we already know about from previous runs
  const unseenProviders = allProviders.filter(p => !knownIds.has(p.id));
  console.log(`[scanner] ${unseenProviders.length} unseen (${allProviders.length - unseenProviders.length} already known from previous runs)`);

  // Mark all current projects as known for next run
  for (const p of allProviders) knownIds.add(p.id);
  state.knownProjectIds = [...knownIds];

  if (unseenProviders.length === 0) {
    console.log("[scanner] No new projects since last run — skipping README diff");
    // Still check PRs
    if (await hasGhCli()) await handlePullRequests();
    await saveState(state);
    return;
  }

  // Step 2: Fetch awesome-mpp README via GitHub API
  console.log("[scanner] Fetching awesome-mpp README...");
  let readme: string;
  try {
    const res = await fetch("https://raw.githubusercontent.com/mbeato/awesome-mpp/main/README.md", {
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) throw new Error(`GitHub raw returned ${res.status}`);
    readme = await res.text();
  } catch (err) {
    console.warn(`[scanner] failed to fetch README — ${err}`);
    await saveState(state);
    return;
  }

  const existing = parseExisting(readme);

  // Step 3: Diff unseen projects against README
  const newProviders = unseenProviders.filter(
    (p) => !existing.names.has(p.name.toLowerCase().trim())
  );

  if (newProviders.length > 0) {
    console.log(`[scanner] Found ${newProviders.length} new project(s): ${newProviders.map((p) => p.name).join(", ")}`);
    await updateAwesomeMpp(newProviders, readme, existing);

    // Step 4: Open notification issues (requires gh CLI)
    if (await hasGhCli()) {
      await openIssuesOnNewRepos(newProviders, state);
    } else {
      console.log("[scanner] gh CLI not available — skipping issue notifications");
    }
  } else {
    console.log("[scanner] awesome-mpp is up to date — no new projects");
  }

  // Step 5: Handle PRs (requires gh CLI)
  if (await hasGhCli()) {
    await handlePullRequests();
  } else {
    console.log("[scanner] gh CLI not available — skipping PR handling");
  }

  await saveState(state);
}

// Allow standalone execution: bun run scripts/brain/scanner.ts
if (import.meta.main) {
  scanner().catch((e) => {
    console.error("[scanner] Fatal:", e);
    process.exit(1);
  });
}
