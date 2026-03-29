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

const CHANNELS = ["npm", "mcp-registry", "discovery-files"] as const;
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

export async function promote(): Promise<void> {
  console.log("[promote] Starting promotion check");

  // Gather unpromoted APIs per channel
  const unpromotedNpm = getUnpromotedApis("npm");
  const unpromotedMcp = getUnpromotedApis("mcp-registry");
  const unpromotedDiscovery = getUnpromotedApis("discovery-files");

  // Deduplicate for summary
  const allNewNames = new Set([
    ...unpromotedNpm.map((a) => a.name),
    ...unpromotedMcp.map((a) => a.name),
    ...unpromotedDiscovery.map((a) => a.name),
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
