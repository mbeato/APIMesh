import { monitor } from "./monitor";
import { scout } from "./scout";
import { build } from "./build";
import { list } from "./list";
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

  // Step 3: Build — needs LLM key
  if (hasLlmKey) {
    console.log("\n[brain] Step 3: Build");
    const built = await build();
    if (built) {
      console.log("\n[brain] Step 4: List");
      await list();
    } else {
      console.log("\n[brain] Step 4: List SKIPPED — no new API built");
    }
  } else {
    console.log("\n[brain] Step 3: Build SKIPPED — no LLM API key");
    console.log("[brain] Step 4: List SKIPPED — no build");
  }

  // Step 5: Prune — on Sundays
  const dayOfWeek = new Date().getDay();
  if (dayOfWeek === 0) {
    console.log("\n[brain] Step 5: Prune (Sunday)");
    await prune();
  } else {
    console.log("\n[brain] Step 5: Prune SKIPPED — not Sunday");
  }

  // Step 6: Promote — always runs
  console.log("\n[brain] Step 6: Promote");
  await promote();

  console.log(`\n${"=".repeat(60)}`);
  console.log(`[brain] Conway Brain finished at ${new Date().toISOString()}`);
  console.log(`${"=".repeat(60)}\n`);
}

main().catch((e) => {
  console.error("[brain] Fatal error:", e);
  process.exit(1);
});
