import {
  getActiveApis,
  getApiRevenue,
  getErrorRate,
  getRequestCount,
  deactivateApi,
} from "../../shared/db";
import { join } from "path";

const PROTECTED_APIS = new Set(["web-checker"]);
const ZERO_REVENUE_DAYS = 14;
const MIN_AGE_DAYS = 21; // Don't prune APIs younger than this
const ERROR_RATE_THRESHOLD = 0.20;
const MIN_REQUESTS_FOR_ERROR_CHECK = 50;

const REGISTRY_PATH = join(import.meta.dir, "..", "..", "apis", "registry.ts");

async function removeFromRegistry(name: string) {
  const content = await Bun.file(REGISTRY_PATH).text();

  // Remove import line
  const importRegex = new RegExp(`import \\{ app as \\w+ \\} from "\\.\\/${name}\\/index";\\n?`);
  let updated = content.replace(importRegex, "");

  // Remove registry entry (and match quoted keys too)
  const entryRegex = new RegExp(`\\s*"?${name}"?: \\w+,\\n?`);
  updated = updated.replace(entryRegex, "");

  await Bun.write(REGISTRY_PATH, updated);
}

export async function prune(): Promise<string[]> {
  const apis = getActiveApis();
  const pruned: string[] = [];

  console.log(`[prune] Evaluating ${apis.length} active APIs...`);

  for (const api of apis) {
    if (PROTECTED_APIS.has(api.name)) {
      console.log(`[prune] ${api.name}: PROTECTED — skipping`);
      continue;
    }

    // Grace period: don't prune APIs that are too new
    const createdAt = new Date(api.created_at).getTime();
    const ageDays = (Date.now() - createdAt) / (1000 * 60 * 60 * 24);
    if (ageDays < MIN_AGE_DAYS) {
      console.log(`[prune] ${api.name}: ${ageDays.toFixed(0)}d old (< ${MIN_AGE_DAYS}d) — skipping`);
      continue;
    }

    const revenue14d = getApiRevenue(api.name, ZERO_REVENUE_DAYS);
    const errorInfo = getErrorRate(api.name, 7);
    const requests7d = getRequestCount(api.name, 7).count;

    // Only prune on sustained high error rates — keep everything else running.
    // Zero-revenue APIs still have value: traffic stats, portfolio, discoverability.
    if (errorInfo.total >= MIN_REQUESTS_FOR_ERROR_CHECK && errorInfo.rate > ERROR_RATE_THRESHOLD) {
      console.log(`[prune] ${api.name}: ${(errorInfo.rate * 100).toFixed(1)}% error rate (${errorInfo.errors}/${errorInfo.total}) — PRUNING`);
      await pruneApi(api.name);
      pruned.push(api.name);
      continue;
    }

    console.log(`[prune] ${api.name}: OK — $${revenue14d.toFixed(4)} rev, ${requests7d} reqs, ${(errorInfo.rate * 100).toFixed(1)}% errors`);
  }

  if (pruned.length > 0) {
    console.log(`[prune] Pruned ${pruned.length} APIs: ${pruned.join(", ")}`);
    // Restart router to pick up registry changes
    try {
      Bun.spawnSync(["sudo", "/usr/local/bin/conway-deploy-restart"]);
      console.log("[prune] Services restarted via deploy wrapper");
    } catch {
      console.log("[prune] Router restart skipped (not on server or no sudo)");
    }
  } else {
    console.log("[prune] No APIs pruned");
  }

  return pruned;
}

async function pruneApi(name: string) {
  deactivateApi(name);
  await removeFromRegistry(name);
  console.log(`[prune] Deactivated ${name} in DB and removed from registry`);
}

// Run directly
if (import.meta.main) {
  const result = await prune();
  console.log("Pruned:", result);
}
