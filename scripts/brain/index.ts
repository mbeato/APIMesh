import { monitor } from "./monitor";
import { scout } from "./scout";
import { build } from "./build";
import { list } from "./list";
import { market } from "./market";
import { prune } from "./prune";
import { promote } from "./promote";

async function main() {
  const timestamp = new Date().toISOString();
  console.log(`\n${"=".repeat(60)}`);
  console.log(`[brain] Conway Brain starting at ${timestamp}`);
  console.log(`${"=".repeat(60)}\n`);

  const hasLlmKey = !!process.env.OPENAI_API_KEY;
  if (!hasLlmKey) {
    console.warn("[brain] OPENAI_API_KEY not set — scout and build will be skipped");
  }

  // Step 1: Monitor — always runs
  console.log("[brain] Step 1: Monitor");
  const health = await monitor();

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

  // Step 5: Market — generate social drafts, tool pages, README updates
  if (hasLlmKey) {
    console.log("\n[brain] Step 5: Market");
    await market();
  } else {
    console.log("\n[brain] Step 5: Market SKIPPED — no LLM API key");
  }

  // Step 6: Prune — on Sundays
  const dayOfWeek = new Date().getDay();
  if (dayOfWeek === 0) {
    console.log("\n[brain] Step 6: Prune (Sunday)");
    await prune();
  } else {
    console.log("\n[brain] Step 6: Prune SKIPPED — not Sunday");
  }

  // Step 7: Promote — always runs
  console.log("\n[brain] Step 7: Promote");
  await promote();

  console.log(`\n${"=".repeat(60)}`);
  console.log(`[brain] Conway Brain finished at ${new Date().toISOString()}`);
  console.log(`${"=".repeat(60)}\n`);
}

main().catch((e) => {
  console.error("[brain] Fatal error:", e);
  process.exit(1);
});
