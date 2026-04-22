import {
  safeFetch,
  validateExternalUrl
} from "../../shared/ssrf";

// Types

export interface ResolverStatus {
  resolver: string;
  response: string | null;
  lastSeen: string; // ISO timestamp
  success: boolean;
  latencyMs: number | null;
}

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface PropagationScores {
  completenessPct: number; // how many resolvers returned expected record
  consistencyPct: number; // how consistent are returned values
  averageLatencyMs: number; // average resolver latency in ms
  grade: string; // letter grade A-F
  recommendations: Recommendation[];
}

export interface DNSPropagationResult {
  domain: string;
  recordType: string;
  queryTimeUTC: string;
  propagationScores: PropagationScores;
  resolverStatuses: ResolverStatus[];
  details: string;
}

export interface DNSPropagationPreviewResult {
  domain: string;
  recordType: string;
  snapshots: {
    resolver: string;
    value: string | null;
    timestampUTC: string;
    success: boolean;
  }[];
  note: string;
}

// Global free DNS resolvers with public JSON DNS over HTTPS endpoints
// For performance, we only query A, AAAA, CNAME, TXT, MX, NS
const DNS_RESOLVERS = [
  {
    name: "Google DNS",
    doHUrl: "https://dns.google/resolve",
    ips: ["8.8.8.8", "8.8.4.4"]
  },
  {
    name: "Cloudflare DNS",
    doHUrl: "https://cloudflare-dns.com/dns-query",
    ips: ["1.1.1.1", "1.0.0.1"]
  },
  {
    name: "Quad9 DNS",
    doHUrl: "https://dns.quad9.net/dns-query",
    ips: ["9.9.9.9", "149.112.112.112"]
  },
  {
    name: "OpenDNS",
    doHUrl: "https://dns.opendns.com/dns-query",
    ips: ["208.67.222.222", "208.67.220.220"]
  },
  {
    name: "CleanBrowsing",
    doHUrl: "https://doh.cleanbrowsing.org/doh/security-filter/",
    ips: []
  }
];

// Supported record types minimized for demonstration
const ALLOWED_RECORD_TYPES = new Set(["A", "AAAA", "CNAME", "TXT", "MX", "NS"]);

// Helpers

async function queryResolver(
  resolver: { name: string; doHUrl: string; ips: string[] },
  domain: string,
  recordType: string
): Promise<ResolverStatus> {
  const url = new URL(resolver.doHUrl);
  url.searchParams.set("name", domain);
  url.searchParams.set("type", recordType.toUpperCase());

  const headers: Record<string, string> = {};
  // Cloudflare requires application/dns-json accept for GET
  if (url.host.includes("cloudflare-dns.com")) {
    headers["accept"] = "application/dns-json";
  }

  try {
    const start = performance.now();
    const res = await safeFetch(url.toString(), {
      method: "GET",
      headers,
      signal: AbortSignal.timeout(10_000),
    });
    const latency = Math.round(performance.now() - start);

    if (!res.ok) {
      return {
        resolver: resolver.name,
        response: null,
        lastSeen: new Date().toISOString(),
        success: false,
        latencyMs: latency
      };
    }

    const json = await res.json();

    if (!json || json.Status !== 0 || !json.Answer) {
      return {
        resolver: resolver.name,
        response: null,
        lastSeen: new Date().toISOString(),
        success: false,
        latencyMs: latency
      };
    }

    // Extract values from Answer for requested record type
    // For simplicity, return concatenated string values
    const values = [];
    for (const ans of json.Answer) {
      // type 1=A, 5=CNAME, 15=MX, 16=TXT, 2=NS, 28=AAAA
      // Map recordType to code
      const typeMap: Record<string, number> = {
        A: 1,
        AAAA: 28,
        CNAME: 5,
        MX: 15,
        TXT: 16,
        NS: 2,
      };
      if (ans.type === typeMap[recordType.toUpperCase()]) {
        values.push(ans.data);
      }
    }

    const responseVal = values.length > 0 ? values.join(", ") : null;

    return {
      resolver: resolver.name,
      response: responseVal,
      lastSeen: new Date().toISOString(),
      success: true,
      latencyMs: latency
    };
  } catch (e: any) {
    // Match error handling pattern
    const msg = e instanceof Error ? e.message : String(e);
    if (/timeout|timed out|abort/i.test(msg)) {
      throw new Error(`Timeout from resolver ${resolver.name}: ${msg}`);
    }
    throw new Error(`Network error from resolver ${resolver.name}: ${msg}`);
  }
}

function gradeFromScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 50) return "D";
  return "F";
}

// Calculates consistency: fraction of resolvers agreeing on the majority record value
function calculateConsistency(responses: (string | null)[]): number {
  const counts = new Map<string, number>();
  let validCount = 0;
  for (const val of responses) {
    if (val === null) continue;
    validCount++;
    counts.set(val, (counts.get(val) || 0) + 1);
  }

  if (validCount === 0) return 0;

  let maxCount = 0;
  for (const count of counts.values()) {
    if (count > maxCount) maxCount = count;
  }

  return (maxCount / validCount) * 100;
}

// Calculates completeness: fraction of resolvers that responded successfully
function calculateCompleteness(statuses: ResolverStatus[]): number {
  const total = statuses.length;
  if (total === 0) return 0;
  const successCount = statuses.filter((s) => s.success).length;
  return (successCount / total) * 100;
}

// Average latency from successful resolvers
function averageLatency(statuses: ResolverStatus[]): number {
  const latencies = statuses
    .map((s) => s.latencyMs)
    .filter((l): l is number => l !== null && l >= 0);
  if (latencies.length === 0) return 0;
  const sum = latencies.reduce((a, b) => a + b, 0);
  return Math.round(sum / latencies.length);
}

// Generate actionable recommendations from propagation results
function generateRecommendations(
  completenessPct: number,
  consistencyPct: number,
  statuses: ResolverStatus[],
  domain: string,
  recordType: string
): Recommendation[] {
  const recs: Recommendation[] = [];

  if (completenessPct < 90) {
    recs.push({
      issue: "Incomplete DNS resolver responses",
      severity: 80,
      suggestion: `Verify NS delegation and DNS server health for domain ${domain}`
    });
  }

  if (consistencyPct < 90) {
    recs.push({
      issue: "Inconsistent DNS record values across resolvers",
      severity: 75,
      suggestion: `Check for DNS record misconfiguration or cache poisoning for ${recordType} record`
    });
  }

  // Detect regional latency issues
  const slowResolvers = statuses.filter((s) => s.latencyMs !== null && s.latencyMs > 4000 && s.success);
  if (slowResolvers.length > 0) {
    recs.push({
      issue: "High latency detected from some DNS resolvers",
      severity: 60,
      suggestion: "Consider adjusting TTL or reviewing DNS server network topology and redundancy"
    });
  }

  // Detect any resolver that failed
  const failedResolvers = statuses.filter((s) => !s.success);
  if (failedResolvers.length > 0) {
    recs.push({
      issue: "Some DNS resolvers failed to respond",
      severity: 50,
      suggestion: "Monitor and possibly avoid unreliable DNS resolvers listed in resolution reports"
    });
  }

  if (recs.length === 0) {
    recs.push({
      issue: "Healthy DNS propagation",
      severity: 10,
      suggestion: "No remediations needed. Continue monitoring regularly."
    });
  }

  return recs;
}

// Public API: comprehensive propagation audit with multiple resolvers and scoring
export async function runFullPropagationAudit(
  domain: string,
  recordType: string
): Promise<DNSPropagationResult> {
  if (!domain || typeof domain !== "string" || domain.length > 255) {
    throw new Error("Invalid domain");
  }
  if (!ALLOWED_RECORD_TYPES.has(recordType.toUpperCase())) {
    throw new Error(`Unsupported record type ${recordType}`);
  }

  let resolverStatuses: ResolverStatus[] = [];

  try {
    // Run all resolver queries in parallel
    const queries: Promise<ResolverStatus>[] = DNS_RESOLVERS.map((resolver) =>
      queryResolver(resolver, domain, recordType.toUpperCase())
    );

    // Await all
    resolverStatuses = await Promise.all(queries);
  } catch (e) {
    // Pass known error pattern
    throw e;
  }

  // Calculate scores
  const completenessPct = Math.round(calculateCompleteness(resolverStatuses));
  const consistencyPct = Math.round(calculateConsistency(resolverStatuses.map((s) => s.response)));
  const avgLatencyMs = averageLatency(resolverStatuses);

  // Compute grade as weighted average
  // Give bigger weight to completeness and consistency vs latency
  const weightedScore = completenessPct * 0.45 + consistencyPct * 0.45 + Math.max(0, 100 - avgLatencyMs / 10) * 0.1;
  const grade = gradeFromScore(weightedScore);

  const recommendations = generateRecommendations(
    completenessPct,
    consistencyPct,
    resolverStatuses,
    domain,
    recordType
  );

  const details = `DNS ${recordType.toUpperCase()} record propagation for domain ${domain} shows ${completenessPct}% completeness and ${consistencyPct}% consistency with average latency ${avgLatencyMs} ms.`;

  return {
    domain,
    recordType: recordType.toUpperCase(),
    queryTimeUTC: new Date().toISOString(),
    propagationScores: {
      completenessPct,
      consistencyPct,
      averageLatencyMs: avgLatencyMs,
      grade,
      recommendations,
    },
    resolverStatuses,
    details,
  };
}

// Public API: preview endpoint - queries a reduced subset of resolvers, returns snapshot only
const PREVIEW_RESOLVERS = DNS_RESOLVERS.slice(0, 3); // top 3 for preview

export async function runPreviewPropagationCheck(
  domain: string,
  recordType: string
): Promise<DNSPropagationPreviewResult> {
  if (!domain || typeof domain !== "string" || domain.length > 255) {
    throw new Error("Invalid domain");
  }
  if (!ALLOWED_RECORD_TYPES.has(recordType.toUpperCase())) {
    throw new Error(`Unsupported record type ${recordType}`);
  }

  const snapshots: {
    resolver: string;
    value: string | null;
    timestampUTC: string;
    success: boolean;
  }[] = [];

  try {
    const queries = PREVIEW_RESOLVERS.map(async (resolver) => {
      try {
        const res = await queryResolver(resolver, domain, recordType.toUpperCase());
        return {
          resolver: resolver.name,
          value: res.response,
          timestampUTC: res.lastSeen,
          success: res.success,
        };
      } catch {
        return {
          resolver: resolver.name,
          value: null,
          timestampUTC: new Date().toISOString(),
          success: false,
        };
      }
    });

    const resolved = await Promise.all(queries);
    snapshots.push(...resolved);
  } catch (e) {
    throw e;
  }

  return {
    domain,
    recordType: recordType.toUpperCase(),
    snapshots,
    note: "Preview endpoint does basic DNS checks from 3 resolvers with no scoring. Full analytics require paid access.",
  };
}
