import db, { getActiveApis } from "../../shared/db";
import { list } from "./list";

interface Promotion {
  id: number;
  api_name: string;
  channel: string;
  status: string;
  url: string | null;
  created_at: string;
}

const CHANNELS = ["npm", "mcp-registry", "discovery-files", "awesome-mpp", "x402-discovery"] as const;
type Channel = (typeof CHANNELS)[number];

/** Get APIs registered in the last 7 days that haven't been promoted to a given channel yet. */
function getUnpromotedApis(channel: Channel): { name: string; subdomain: string }[] {
  const rows = db.query(`
    SELECT ar.name, ar.subdomain
    FROM api_registry ar
    WHERE ar.status = 'active'
      AND ar.created_at > datetime('now', '-7 days')
      AND NOT EXISTS (
        SELECT 1 FROM promotions p
        WHERE p.api_name = ar.name AND p.channel = ?
      )
  `).all(channel) as { name: string; subdomain: string }[];
  return rows;
}

/** Log a promotion action to the DB. Idempotent via UNIQUE(api_name, channel). */
function logPromotion(apiName: string, channel: Channel, status: string, url?: string) {
  db.run(
    `INSERT INTO promotions (api_name, channel, status, url)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(api_name, channel) DO UPDATE SET
       status = excluded.status,
       url = COALESCE(excluded.url, promotions.url),
       created_at = datetime('now')`,
    [apiName, channel, status, url ?? null]
  );
}

/** Step 1: Check for new APIs and flag them for npm update. */
function checkNpmPackage(newApis: { name: string }[]): string[] {
  const actions: string[] = [];
  if (newApis.length === 0) return actions;

  const names = newApis.map((a) => a.name).join(", ");
  console.log(`[promote] npm: ${newApis.length} new API(s) detected: ${names}`);
  console.log(`[promote] npm: ACTION NEEDED — update MCP server tool list and run 'npm publish'`);

  for (const api of newApis) {
    logPromotion(api.name, "npm", "manual-needed");
    actions.push(`npm: ${api.name} needs MCP server tool update + publish`);
  }
  return actions;
}

/** Step 2: Republish to MCP Registry if new tools were added. */
async function republishMcpRegistry(newApis: { name: string }[]): Promise<string[]> {
  const actions: string[] = [];
  if (newApis.length === 0) return actions;

  console.log(`[promote] mcp-registry: attempting republish for ${newApis.length} new API(s)`);
  try {
    const BUN = Bun.argv[0];
    const proc = Bun.spawn([BUN, "x", "@anthropic-ai/mcp-publisher", "publish"], {
      stdout: "pipe",
      stderr: "pipe",
      timeout: 60_000,
    });
    const exitCode = await proc.exited;
    const stdout = await new Response(proc.stdout).text();
    const stderr = await new Response(proc.stderr).text();

    if (exitCode === 0) {
      console.log(`[promote] mcp-registry: publish succeeded`);
      if (stdout.trim()) console.log(`[promote] mcp-registry stdout: ${stdout.trim()}`);
      for (const api of newApis) {
        logPromotion(api.name, "mcp-registry", "success");
        actions.push(`mcp-registry: ${api.name} published`);
      }
    } else {
      console.warn(`[promote] mcp-registry: publish failed (exit ${exitCode})`);
      if (stderr.trim()) console.warn(`[promote] mcp-registry stderr: ${stderr.trim()}`);
      for (const api of newApis) {
        logPromotion(api.name, "mcp-registry", "failed");
        actions.push(`mcp-registry: ${api.name} FAILED`);
      }
    }
  } catch (err) {
    console.error(`[promote] mcp-registry: error —`, err);
    for (const api of newApis) {
      logPromotion(api.name, "mcp-registry", "failed");
      actions.push(`mcp-registry: ${api.name} FAILED (${err})`);
    }
  }
  return actions;
}

/** Step 3: Regenerate discovery files (llms.txt, OpenAPI, x402.json, ai-plugin.json). */
async function updateDiscoveryFiles(newApis: { name: string }[]): Promise<string[]> {
  const actions: string[] = [];
  if (newApis.length === 0) return actions;

  console.log(`[promote] discovery-files: regenerating for ${newApis.length} new API(s)`);
  try {
    await list();
    console.log(`[promote] discovery-files: regenerated successfully`);
    for (const api of newApis) {
      logPromotion(api.name, "discovery-files", "success");
      actions.push(`discovery-files: ${api.name} listed`);
    }
  } catch (err) {
    console.error(`[promote] discovery-files: error —`, err);
    for (const api of newApis) {
      logPromotion(api.name, "discovery-files", "failed");
      actions.push(`discovery-files: ${api.name} FAILED (${err})`);
    }
  }
  return actions;
}

/** Step 4: Update awesome-mpp README with current API count (we own this repo). */
async function updateAwesomeMpp(newApis: { name: string }[]): Promise<string[]> {
  const actions: string[] = [];
  if (newApis.length === 0) return actions;

  const activeApis = getActiveApis();
  const count = activeApis.length;

  console.log(`[promote] awesome-mpp: updating APIMesh listing to ${count} APIs`);

  try {
    // Clone/fetch the repo, update the listing line, push
    const tmpDir = "/tmp/awesome-mpp-promote";
    const BUN = Bun.argv[0];

    // Clean up any previous run
    await Bun.spawn(["rm", "-rf", tmpDir]).exited;

    const clone = Bun.spawn(
      ["git", "clone", "--depth", "1", "https://github.com/mbeato/awesome-mpp.git", tmpDir],
      { stdout: "pipe", stderr: "pipe", timeout: 30_000 }
    );
    const cloneExit = await clone.exited;
    if (cloneExit !== 0) {
      const stderr = await new Response(clone.stderr).text();
      console.warn(`[promote] awesome-mpp: clone failed — ${stderr.trim()}`);
      for (const api of newApis) {
        logPromotion(api.name, "awesome-mpp", "failed");
        actions.push(`awesome-mpp: ${api.name} FAILED (clone error)`);
      }
      return actions;
    }

    // Read current README
    const readmePath = `${tmpDir}/README.md`;
    const readme = await Bun.file(readmePath).text();

    // Build the API name list for the description
    const apiNames = activeApis.map(a => a.name).slice(0, 6).join(", ");
    const suffix = count > 6 ? `, +${count - 6} more` : "";

    // Update the APIMesh line — match the existing format
    const oldPattern = /- \[APIMesh\]\(https:\/\/github\.com\/mbeato\/conway\)[^\n]*/;
    const newLine = `- [APIMesh](https://github.com/mbeato/conway) - ${count} pay-per-call APIs for AI agents (${apiNames}${suffix}). Supports x402 + MPP.`;

    if (!oldPattern.test(readme)) {
      console.warn(`[promote] awesome-mpp: could not find APIMesh listing to update`);
      for (const api of newApis) {
        logPromotion(api.name, "awesome-mpp", "failed");
        actions.push(`awesome-mpp: ${api.name} FAILED (pattern not found)`);
      }
      await Bun.spawn(["rm", "-rf", tmpDir]).exited;
      return actions;
    }

    const updated = readme.replace(oldPattern, newLine);
    if (updated === readme) {
      console.log(`[promote] awesome-mpp: listing already up to date`);
      for (const api of newApis) {
        logPromotion(api.name, "awesome-mpp", "already-current");
        actions.push(`awesome-mpp: ${api.name} already current`);
      }
      await Bun.spawn(["rm", "-rf", tmpDir]).exited;
      return actions;
    }

    await Bun.write(readmePath, updated);

    // Commit and push
    const newApiNames = newApis.map(a => a.name).join(", ");
    const commitMsg = `update APIMesh: ${count} APIs (added ${newApiNames})`;

    const gitCmds = [
      ["git", "-C", tmpDir, "add", "README.md"],
      ["git", "-C", tmpDir, "commit", "-m", commitMsg],
      ["git", "-C", tmpDir, "push", "origin", "main"],
    ];

    for (const cmd of gitCmds) {
      const proc = Bun.spawn(cmd, { stdout: "pipe", stderr: "pipe", timeout: 30_000 });
      const exit = await proc.exited;
      if (exit !== 0) {
        const stderr = await new Response(proc.stderr).text();
        console.warn(`[promote] awesome-mpp: ${cmd.slice(2).join(" ")} failed — ${stderr.trim()}`);
        for (const api of newApis) {
          logPromotion(api.name, "awesome-mpp", "failed");
          actions.push(`awesome-mpp: ${api.name} FAILED (git ${cmd[3]} error)`);
        }
        await Bun.spawn(["rm", "-rf", tmpDir]).exited;
        return actions;
      }
    }

    console.log(`[promote] awesome-mpp: pushed update — ${count} APIs`);
    for (const api of newApis) {
      logPromotion(api.name, "awesome-mpp", "success", "https://github.com/mbeato/awesome-mpp");
      actions.push(`awesome-mpp: ${api.name} listed`);
    }

    await Bun.spawn(["rm", "-rf", tmpDir]).exited;
  } catch (err) {
    console.error(`[promote] awesome-mpp: error —`, err);
    for (const api of newApis) {
      logPromotion(api.name, "awesome-mpp", "failed");
      actions.push(`awesome-mpp: ${api.name} FAILED (${err})`);
    }
  }
  return actions;
}

/** Step 5: Update x402 discovery — refresh .well-known/x402.json with all current APIs. */
async function updateX402Discovery(newApis: { name: string; subdomain: string }[]): Promise<string[]> {
  const actions: string[] = [];
  if (newApis.length === 0) return actions;

  console.log(`[promote] x402-discovery: registering ${newApis.length} new API(s)`);

  // The .well-known/x402.json is already updated by the list step.
  // Here we ping 402index.io to re-index our discovery endpoint.
  try {
    const res = await fetch("https://402index.io/api/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://apimesh.xyz/.well-known/x402.json" }),
      signal: AbortSignal.timeout(15_000),
    });

    if (res.ok || res.status === 409) {
      // 409 = already indexed, which is fine
      console.log(`[promote] x402-discovery: 402index.io submission ${res.ok ? "succeeded" : "already indexed"}`);
      for (const api of newApis) {
        logPromotion(api.name, "x402-discovery", "success", "https://402index.io");
        actions.push(`x402-discovery: ${api.name} submitted to 402index`);
      }
    } else {
      const body = await res.text().catch(() => "");
      console.warn(`[promote] x402-discovery: 402index returned ${res.status} — ${body.slice(0, 200)}`);
      for (const api of newApis) {
        logPromotion(api.name, "x402-discovery", "manual-needed");
        actions.push(`x402-discovery: ${api.name} needs manual 402index submission`);
      }
    }
  } catch (err) {
    // 402index may not have a submission API — log for manual action
    console.warn(`[promote] x402-discovery: 402index submission failed —`, err);
    for (const api of newApis) {
      logPromotion(api.name, "x402-discovery", "manual-needed");
      actions.push(`x402-discovery: ${api.name} needs manual 402index submission`);
    }
  }

  // Also update per-subdomain x402 discovery on each new API
  for (const api of newApis) {
    try {
      const healthRes = await fetch(`https://${api.subdomain}.apimesh.xyz/.well-known/x402`, {
        signal: AbortSignal.timeout(10_000),
      });
      if (healthRes.ok) {
        console.log(`[promote] x402-discovery: ${api.name} x402 endpoint confirmed`);
      } else {
        console.warn(`[promote] x402-discovery: ${api.name} x402 endpoint returned ${healthRes.status}`);
      }
    } catch {
      console.warn(`[promote] x402-discovery: ${api.name} x402 endpoint unreachable`);
    }
  }

  return actions;
}

export async function promote(): Promise<void> {
  console.log("[promote] Starting promotion check");

  // Gather unpromoted APIs per channel
  const unpromotedNpm = getUnpromotedApis("npm");
  const unpromotedMcp = getUnpromotedApis("mcp-registry");
  const unpromotedDiscovery = getUnpromotedApis("discovery-files");
  const unpromotedMpp = getUnpromotedApis("awesome-mpp");
  const unpromotedX402 = getUnpromotedApis("x402-discovery");

  // Deduplicate for summary
  const allNewNames = new Set([
    ...unpromotedNpm.map((a) => a.name),
    ...unpromotedMcp.map((a) => a.name),
    ...unpromotedDiscovery.map((a) => a.name),
    ...unpromotedMpp.map((a) => a.name),
    ...unpromotedX402.map((a) => a.name),
  ]);

  if (allNewNames.size === 0) {
    console.log("[promote] No new APIs need promotion — all up to date");
    return;
  }

  console.log(`[promote] Found ${allNewNames.size} API(s) needing promotion: ${Array.from(allNewNames).join(", ")}`);

  const allActions: string[] = [];

  // Run promotion steps
  allActions.push(...checkNpmPackage(unpromotedNpm));
  allActions.push(...(await republishMcpRegistry(unpromotedMcp)));
  allActions.push(...(await updateDiscoveryFiles(unpromotedDiscovery)));
  allActions.push(...(await updateAwesomeMpp(unpromotedMpp)));
  allActions.push(...(await updateX402Discovery(unpromotedX402)));

  // Summary
  console.log(`\n[promote] === Summary ===`);
  if (allActions.length === 0) {
    console.log("[promote] No actions taken");
  } else {
    for (const action of allActions) {
      console.log(`[promote]   ${action}`);
    }
  }

  const manualCount = allActions.filter((a) => a.includes("needs") || a.includes("FAILED")).length;
  if (manualCount > 0) {
    console.log(`[promote] ${manualCount} item(s) need manual attention`);
  }

  console.log("[promote] Done");
}

// Run directly
if (import.meta.main) {
  await promote();
}
