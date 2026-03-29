import {
  getActiveApis,
  getApiRevenue,
  getErrorRate,
  getTotalRevenue,
  getRequestCount,
} from "../../shared/db";

export interface HealthReport {
  balanceUsd: number;
  creditsUsd: number;
  weeklyCostUsd: number;
  runwayWeeks: number;
  totalRevenue7d: number;
  apiReports: {
    name: string;
    revenue7d: number;
    requests7d: number;
    errorRate: number;
  }[];
}

// Estimated weekly cost: server only (~$2.50/week for Hetzner VPS)
// LLM API costs tracked separately when brain Phase 2 lands
const ESTIMATED_WEEKLY_COST_USD = 2.50;

export async function monitor(): Promise<HealthReport> {
  console.log("[monitor] Checking health...");

  // Revenue metrics from local DB (no external dependency)
  const totalRev = getTotalRevenue(7);
  const totalRev30 = getTotalRevenue(30);

  // Per-API metrics
  const apis = getActiveApis();
  const apiReports = apis.map((api) => ({
    name: api.name,
    revenue7d: getApiRevenue(api.name, 7),
    requests7d: getRequestCount(api.name, 7).count,
    errorRate: getErrorRate(api.name, 7).rate,
  }));

  // Runway based on 30-day revenue trend vs costs
  // If revenue > costs, runway is infinite (self-sustaining)
  // Otherwise, estimate how long current trajectory lasts
  const weeklyRevenue = totalRev30.total_usd / 4.3;
  const netWeekly = weeklyRevenue - ESTIMATED_WEEKLY_COST_USD;
  const runwayWeeks = netWeekly >= 0 ? Infinity : Math.abs(weeklyRevenue / ESTIMATED_WEEKLY_COST_USD) * 52;

  const report: HealthReport = {
    balanceUsd: 0, // No longer tracking external wallet balance
    creditsUsd: 0, // Conway Terminal credits deprecated
    weeklyCostUsd: ESTIMATED_WEEKLY_COST_USD,
    runwayWeeks: Math.min(runwayWeeks, 52), // Cap at 1 year for display
    totalRevenue7d: totalRev.total_usd,
    apiReports,
  };

  // Log summary
  console.log("[monitor] --- Health Report ---");
  console.log(`  Weekly Revenue: $${weeklyRevenue.toFixed(4)}`);
  console.log(`  Weekly Cost: $${ESTIMATED_WEEKLY_COST_USD.toFixed(2)}`);
  console.log(`  Runway: ${report.runwayWeeks.toFixed(1)} weeks`);
  console.log(`  Revenue (7d): $${totalRev.total_usd.toFixed(4)}`);
  for (const api of apiReports) {
    console.log(`  ${api.name}: $${api.revenue7d.toFixed(4)} rev, ${api.requests7d} reqs, ${(api.errorRate * 100).toFixed(1)}% errors`);
  }
  console.log("[monitor] --- End Report ---");

  return report;
}

// Run directly
if (import.meta.main) {
  const report = await monitor();
  console.log(JSON.stringify(report, null, 2));
}
