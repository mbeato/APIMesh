import { safeFetch } from "../../shared/ssrf";

// --- Types ---

export interface DNSChangeForecastRequest {
  domain: string;
}

export interface DNSChangeSummary {
  recentDnsAdds: number;
  recentDnsDeletes: number;
  recentCtCerts: number;
}

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface DNSRawRecordChange {
  type: string;
  recordName: string;
  oldValue?: string;
  newValue?: string;
  timestamp: string;
}

export interface CTCertChange {
  loggedAt: string;
  issuerName: string;
  commonName: string;
  serialNumber: string;
  fingerprintSha256: string;
}

export interface DNSChangeForecastResult {
  domain: string;
  lastScanAt: string;
  dnsChangesScore: number; // 0-100, stability
  ctCertChangesScore: number; // 0-100
  combinedGrade: string; // e.g. A- to F
  changeSummary: DNSChangeSummary;
  recommendations: Recommendation[];
  explanation: string;
  details: {
    dns: {
      recentChanges: DNSRawRecordChange[];
      propagatedRecords: string[];
    };
    ctLogs: {
      recentCerts: CTCertChange[];
    };
    forecast: {
      upcomingDnsChangeRisk: number;
      propagationDelayExpectedMs: number;
      recommendedAction: string | null;
    };
  };
}

export interface DNSChangeForecastPreview {
  domain: string;
  recentARecordChanges: number;
  previewScore: number; // 0-100
  explanation: string;
  recommendations: Recommendation[];
}

const ABORT_TIMEOUT_MS = 10000;
const PREVIEW_ABORT_TIMEOUT_MS = 20000;

// --- Helpers: fetch DNS records from Google's DNS-over-HTTPS API ---

async function fetchDnsRecords(domain: string, type: string) {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`;
  const res = await safeFetch(url, { timeoutMs: ABORT_TIMEOUT_MS });
  if (!res.ok) {
    throw new Error(`DNS fetch failed with status ${res.status}`);
  }
  const data = await res.json();
  return data;
}

// --- Helpers: fetch domain's certificate transparency logs from crt.sh ---
async function fetchCTLogs(domain: string) {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  const res = await safeFetch(url, { timeoutMs: ABORT_TIMEOUT_MS });
  if (!res.ok) {
    throw new Error(`CT logs fetch failed with status ${res.status}`);
  }
  const text = await res.text();
  if (!text || text === "[]") {
    return [];
  }
  const data = JSON.parse(text);
  return data;
}

// --- Utility to grade numeric scores to letter grades ---
function gradeScore(score: number): string {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B";
  if (score >= 55) return "C";
  if (score >= 40) return "D";
  return "F";
}

// --- Analyze DNS record changes ---
function analyzeDnsChanges(dnsAnswers: any[]): {
  recentChanges: DNSRawRecordChange[];
  adds: number;
  deletes: number;
  changed: number;
  stableRecords: string[];
} {
  // This function simulates detection of changes by looking at record TTLs and timestamps
  // Since we do not have state here, just simulate recent additions by filtering recent TTL < 3600

  // Filter only A, AAAA, CNAME, TXT
  const filtered = (dnsAnswers || []).filter(
    (a) => [1, 28, 5, 16].includes(a.type) // A=1, AAAA=28, CNAME=5, TXT=16
  );

  const recentChanges: DNSRawRecordChange[] = [];
  let adds = 0;
  let deletes = 0;
  let changed = 0;

  const stableRecords: string[] = [];

  for (const answer of filtered) {
    // We consider TTL < 3600 as hint for recent add/change
    if (answer.TTL !== undefined && typeof answer.TTL === "number") {
      if (answer.TTL < 3600) {
        recentChanges.push({
          type: dnsTypeName(answer.type),
          recordName: answer.name,
          newValue: answer.data || answer.rdata || null,
          timestamp: new Date().toISOString(),
        });
        adds++;
      } else {
        stableRecords.push(answer.name);
      }
    } else {
      stableRecords.push(answer.name);
    }
  }

  // We don't detect deletes/changed without history so omit

  return { recentChanges, adds, deletes, changed, stableRecords };
}

function dnsTypeName(type: number): string {
  switch (type) {
    case 1:
      return "A";
    case 28:
      return "AAAA";
    case 5:
      return "CNAME";
    case 16:
      return "TXT";
    default:
      return "UNKNOWN";
  }
}

// --- Analyze CT cert entries ---
function analyzeCtChanges(ctEntries: any[]): { recentCerts: CTCertChange[]; recentCount: number } {
  if (!Array.isArray(ctEntries)) {
    return { recentCerts: [], recentCount: 0 };
  }

  // Filter by not_before within past 90 days (approx 3 months)
  const now = Date.now();
  const cutoff = now - 90 * 24 * 3600 * 1000;
  const recentCerts: CTCertChange[] = [];
  for (const entry of ctEntries) {
    const loggedAt = entry.logged_at || entry.not_before || entry.entry_timestamp || entry.not_before;
    if (!loggedAt) continue;
    const logTime = new Date(loggedAt).getTime();
    if (isNaN(logTime) || logTime < cutoff) continue;

    recentCerts.push({
      loggedAt: new Date(loggedAt).toISOString(),
      issuerName: entry.issuer_name || "unknown",
      commonName: entry.common_name || entry.name_value || "unknown",
      serialNumber: String(entry.serial_number || ""),
      fingerprintSha256: entry.cert_sha256 || "",
    });
  }

  return { recentCerts, recentCount: recentCerts.length };
}

// --- Generate recommendations based on findings ---
function generateRecommendations(
  dnsAdds: number,
  dnsDeletes: number,
  ctCertsCount: number,
  dnsStabilityScore: number,
  ctScore: number
): Recommendation[] {
  const recommendations: Recommendation[] = [];

  if (dnsAdds > 5) {
    recommendations.push({
      issue: "High frequency of DNS record additions",
      severity: 80,
      suggestion: "Investigate potential unauthorized DNS updates or dynamic DNS usage to prevent DNS hijacking."
    });
  } else if (dnsAdds > 0) {
    recommendations.push({
      issue: "Moderate number of DNS record additions",
      severity: 40,
      suggestion: "Ensure DNS changes are planned and TTLs are configured to reduce propagation issues."
    });
  }

  if (dnsDeletes > 2) {
    recommendations.push({
      issue: "Frequent DNS record deletions",
      severity: 60,
      suggestion: "Verify that DNS deletions are intentional and do not disrupt services."
    });
  }

  if (ctCertsCount > 10) {
    recommendations.push({
      issue: "Many recent certificate transparency log entries",
      severity: 50,
      suggestion: "Check all issued certificates for the domain for legitimacy and revoke unused certificates."
    });
  } else if (ctCertsCount > 0) {
    recommendations.push({
      issue: "Active certificate issuance",
      severity: 20,
      suggestion: "Regularly monitor CT logs to detect suspicious certificates."
    });
  }

  if (dnsStabilityScore < 50) {
    recommendations.push({
      issue: "Unstable DNS record set",
      severity: 70,
      suggestion: "Strongly consider locking DNS records, improving monitoring, and enhancing security practices."
    });
  }

  if (ctScore < 50) {
    recommendations.push({
      issue: "Potential risky certificate activity",
      severity: 70,
      suggestion: "Investigate certificate issuance patterns and apply stricter certificate management policies."
    });
  }

  if (recommendations.length === 0) {
    recommendations.push({
      issue: "No significant issues detected",
      severity: 10,
      suggestion: "Maintain regular monitoring and best security practices."
    });
  }

  return recommendations;
}

// --- Scoring heuristics (0-100 range) ---
function scoreDnsStability(adds: number, deletes: number): number {
  // Simple heuristic: more adds/deletes => lower score
  let score = 100 - (adds * 10 + deletes * 12);
  if(score < 0) score = 0;
  if(score > 100) score = 100;
  return score;
}

function scoreCtActivity(count: number): number {
  // More CT certs recent => lower score
  let score = 100 - count * 8;
  if(score < 0) score = 0;
  if(score > 100) score = 100;
  return score;
}

// --- Domain validation helper (basic) ---
function isValidDomain(domain: string): boolean {
  // RFC 1035 basic domain name check
  if (!domain || domain.length > 253) return false;
  const labelRegex = /^[a-z0-9-]{1,63}$/i;
  const labels = domain.split(".");
  if (labels.some((l) => !labelRegex.test(l))) return false;
  return true;
}

// --- Public API Functions ---

export async function forecastDnsChangesPreview(
  domain: string
): Promise<DNSChangeForecastPreview> {
  if (!isValidDomain(domain)) {
    throw new Error("Invalid domain format");
  }

  // Fetch A record DNS answers (for preview we keep it lightweight)
  let dnsData;
  try {
    dnsData = await safeFetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`, {
      timeoutMs: PREVIEW_ABORT_TIMEOUT_MS,
    }).then(async (r) => {
      if (!r.ok) throw new Error(`DNS fetch failed ${r.status}`);
      return r.json();
    });
  } catch (e) {
    throw new Error(`Failed to fetch DNS A records: ${(e instanceof Error ? e.message : String(e))}`);
  }

  const answers = dnsData?.Answer || [];

  // For preview, count records with TTL below threshold as "changes"
  let recentChangesCount = 0;
  for (const ans of answers) {
    if (typeof ans.TTL === "number" && ans.TTL < 3600) {
      recentChangesCount++;
    }
  }

  // Simple heuristic for score
  let previewScore = 100 - recentChangesCount * 20;
  if (previewScore < 0) previewScore = 0;

  const recommendations: Recommendation[] = [];
  if (recentChangesCount > 3) {
    recommendations.push({
      issue: "Frequent A record changes",
      severity: 50,
      suggestion: "Consider monitoring DNS changes closely to avoid propagation issues."
    });
  } else {
    recommendations.push({
      issue: "Stable A record set",
      severity: 10,
      suggestion: "Keep up good DNS management practices."
    });
  }

  return {
    domain,
    recentARecordChanges: recentChangesCount,
    previewScore: previewScore,
    explanation: "Preview includes basic recent DNS A record observation to provide quick insight about DNS stability.",
    recommendations
  };
}

export async function forecastDnsChanges(
  domain: string
): Promise<DNSChangeForecastResult> {
  if (!isValidDomain(domain)) {
    throw new Error("Invalid domain format");
  }

  // AbortSignal with timeout
  const abortSignal = AbortSignal.timeout(ABORT_TIMEOUT_MS);

  // Fetch DNS records in parallel (A, AAAA, CNAME, TXT)
  const dnsRecordTypes = [1, 28, 5, 16];

  type DnsFetchResult = { type: number; data: any | null; error?: string };

  const dnsFetches = dnsRecordTypes.map(async (type) => {
    try {
      const res = await safeFetch(
        `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`,
        { signal: abortSignal, timeoutMs: ABORT_TIMEOUT_MS }
      );

      if (!res.ok) {
        throw new Error(`DNS type ${type} fetch status ${res.status}`);
      }
      const jsonData = await res.json();
      return { type, data: jsonData } as DnsFetchResult;
    } catch (e: unknown) {
      return { type, data: null, error: e instanceof Error ? e.message : String(e) } as DnsFetchResult;
    }
  });

  // Fetch CT logs
  const ctFetch = (async () => {
    try {
      return await fetchCTLogs(domain);
    } catch (e) {
      return null; // gracefully degrade
    }
  })();

  // Await all
  const dnsResults = await Promise.all(dnsFetches);
  const ctEntries = await ctFetch;

  // Extract valid DNS answers from results
  const combinedDNSAnswers = dnsResults
    .filter((r) => r.data && Array.isArray(r.data.Answer))
    .map((r) => r.data.Answer)
    .flat();

  // Analyze DNS changes
  const dnsChangesAnalysis = analyzeDnsChanges(combinedDNSAnswers);

  const dnsAdds = dnsChangesAnalysis.adds;
  const dnsDeletes = dnsChangesAnalysis.deletes;
  const dnsChanges = dnsChangesAnalysis.recentChanges;
  const stableRecords = dnsChangesAnalysis.stableRecords;

  const dnsScore = scoreDnsStability(dnsAdds, dnsDeletes);

  // Analyze CT logs
  const ctAnalysis = analyzeCtChanges(ctEntries || []);

  const ctCount = ctAnalysis.recentCount;
  const ctScore = scoreCtActivity(ctCount);

  // Combine scores weighted
  const combinedRawScore = dnsScore * 0.6 + ctScore * 0.4;
  const combinedGrade = gradeScore(combinedRawScore);

  // Compose change summary
  const changeSummary = {
    recentDnsAdds: dnsAdds,
    recentDnsDeletes: dnsDeletes,
    recentCtCerts: ctCount,
  };

  // Explanation text
  const explanation = `Domain ${domain} has DNS stability score of ${dnsScore} and certificate transparency score of ${ctScore}. Combined grade is ${combinedGrade}. DNS changes are ${dnsAdds} adds and ${dnsDeletes} deletes. Recent certificate transparency entries count is ${ctCount}.`;

  // Forecast
  const forecast = {
    upcomingDnsChangeRisk: 100 - dnsScore, // Higher risk if score low
    propagationDelayExpectedMs: 30000, // static estimation 30s for demonstration
    recommendedAction:
      dnsScore < 50
        ? "Implement DNS record locking and improve monitoring."
        : null,
  };

  // Recommendations
  const recommendations = generateRecommendations(dnsAdds, dnsDeletes, ctCount, dnsScore, ctScore);

  return {
    domain,
    lastScanAt: new Date().toISOString(),
    dnsChangesScore: dnsScore,
    ctCertChangesScore: ctScore,
    combinedGrade,
    changeSummary,
    recommendations,
    explanation,
    details: {
      dns: {
        recentChanges: dnsChanges,
        propagatedRecords: stableRecords,
      },
      ctLogs: {
        recentCerts: ctAnalysis.recentCerts,
      },
      forecast,
    },
  };
}
