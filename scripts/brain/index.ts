import { monitor } from "./monitor";
import { scanner } from "./scanner";
import { scout } from "./scout";
import { build } from "./build";
import { list } from "./list";
import { market } from "./market";
import { prune } from "./prune";
import { promote } from "./promote";
import { devtoPublish } from "./devto-publish";
import { socialPublish } from "./social-publish";
import { changelog } from "./changelog";
import { mcpClientMonitor } from "./mcp-client-monitor";
import { digest } from "./digest";
import { githubEngage } from "./github-engage";
import { directoryTracker } from "./directory-tracker";
import { reapUnverifiedUsers } from "../reap-unverified";
import { reconcileRegistryWithFile } from "../../shared/db";
import { join } from "path";

async function main() {
  const timestamp = new Date().toISOString();
  console.log(`\n${"=".repeat(60)}`);
  console.log(`[brain] Conway Brain starting at ${timestamp}`);
  console.log(`${"=".repeat(60)}\n`);

  // Step 0: Reconcile DB ↔ registry.ts before any downstream step reads
  // getActiveApis(). Without this, deactivated/renamed APIs accumulate as
  // stale "active" rows and inflate every count produced downstream.
  try {
    const result = reconcileRegistryWithFile(
      join(import.meta.dir, "..", "..", "apis", "registry.ts"),
    );
    if (result.marked_inactive.length || result.inserted.length) {
      console.log(
        `[brain] Reconciled DB with registry.ts: ${result.marked_inactive.length} marked inactive, ${result.inserted.length} inserted, ${result.active_count} now active`,
      );
    } else {
      console.log(`[brain] DB ↔ registry.ts in sync: ${result.active_count} active APIs`);
    }
  } catch (err) {
    console.error(
      `[brain] Reconcile failed (non-fatal):`,
      err instanceof Error ? err.message : err,
    );
  }

  const hasLlmKey = !!process.env.OPENAI_API_KEY;
  if (!hasLlmKey) {
    console.warn("[brain] OPENAI_API_KEY not set — scout and build will be skipped");
  }

  // Shared: day-of-week for weekly steps
  const dayOfWeek = new Date().getDay();

  // Step 1: Monitor — always runs
  console.log("[brain] Step 1: Monitor");
  const health = await monitor();

  // Step 1.2: Reap unverified signups (bot spam)
  try {
    const reaped = reapUnverifiedUsers(24);
    if (reaped > 0) console.log(`[brain] Reaped ${reaped} unverified user(s)`);
  } catch (e) {
    console.error(`[brain] Reap failed:`, e instanceof Error ? e.message : e);
  }

  // Step 1.5: Scanner — scan MPP ecosystem for new projects (weekly)
  if (dayOfWeek === 0) {
    console.log("\n[brain] Step 1.5: Scanner (Sunday)");
    await scanner();
  } else {
    console.log("\n[brain] Step 1.5: Scanner SKIPPED — runs weekly on Sundays");
  }

  // Step 2: Scout — needs LLM key
  if (hasLlmKey) {
    console.log("\n[brain] Step 2: Scout");
    await scout();
  } else {
    console.log("\n[brain] Step 2: Scout SKIPPED — no LLM API key");
  }

  // Step 3: Build — needs LLM key, up to 3 APIs per run
  const MAX_BUILDS_PER_RUN = 3;
  if (hasLlmKey) {
    let totalBuilt = 0;
    for (let i = 1; i <= MAX_BUILDS_PER_RUN; i++) {
      console.log(`\n[brain] Step 3: Build (${i}/${MAX_BUILDS_PER_RUN})`);
      const built = await build();
      if (built) {
        totalBuilt++;
      } else {
        console.log(`[brain] No more backlog items to build — stopping after ${totalBuilt} builds`);
        break;
      }
    }
    if (totalBuilt > 0) {
      console.log(`\n[brain] Step 4: List (${totalBuilt} new APIs built)`);
      await list();
    } else {
      console.log("\n[brain] Step 4: List SKIPPED — no new APIs built");
    }
  } else {
    console.log("\n[brain] Step 3: Build SKIPPED — no LLM API key");
    console.log("[brain] Step 4: List SKIPPED — no build");
  }

  // Step 5: Market — generate social drafts, tool pages, sitemap, README updates
  if (hasLlmKey) {
    console.log("\n[brain] Step 5: Market");
    await market();
  } else {
    console.log("\n[brain] Step 5: Market SKIPPED — no LLM API key");
  }

  // Step 5.5: Changelog — always runs (no LLM needed)
  console.log("\n[brain] Step 5.5: Changelog");
  await changelog();

  // Step 6: Publish — post to Dev.to and X (daily, rate-limited)
  console.log("\n[brain] Step 6: Publish");
  await devtoPublish();
  await socialPublish();

  // Step 7: Promote — push to registries
  console.log("\n[brain] Step 7: Promote");
  await promote();

  // Step 8: Outreach — engagement and monitoring (daily)
  console.log("\n[brain] Step 8: Outreach");
  await digest();
  await githubEngage();

  // Step 9: Weekly deep scans (Sundays)
  if (dayOfWeek === 0) {
    console.log("\n[brain] Step 9: Weekly scans (Sunday)");
    await mcpClientMonitor();
    await directoryTracker();
    await prune();
  } else {
    console.log("\n[brain] Step 9: Weekly scans SKIPPED — not Sunday");
  }

  console.log(`\n${"=".repeat(60)}`);
  console.log(`[brain] Conway Brain finished at ${new Date().toISOString()}`);
  console.log(`${"=".repeat(60)}\n`);
}

main().catch((e) => {
  console.error("[brain] Fatal error:", e);
  process.exit(1);
});
