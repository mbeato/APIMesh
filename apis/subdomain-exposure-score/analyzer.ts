import { safeFetch } from "../../shared/ssrf";

// -----------------------------
// Types
// -----------------------------

export interface ExposureIssue {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface SubdomainInfo {
  subdomain: string;
  sources: string[]; // e.g. ["dns", "ctLog", "publicApi"]
  sensitive: boolean; // likely sensitive based on patterns
  unused: boolean;    // likely unused if TTL or IP status
}

export interface SubdomainExposureScoreResult {
  domain: string;
  subdomains: string[];
  sources: Record<string, number>; // counts by source
  exposureScore: number; // 0-100
  grade: "A" | "B" | "C" | "D" | "F";
  explanation: string;
  recommendations: ExposureIssue[];
}

export interface SubdomainExposureScorePreview {
  domain: string;
  subdomainCount: number;
  exposureScore: number; // 0-100
  grade: "A" | "B" | "C" | "D" | "F";
  details: string;
  recommendations: ExposureIssue[];
}

// -----------------------------
// Constants and Helpers
// -----------------------------

const FREECTLOGS_API = "https://api.certdb.com/v1/domains";
const DNS_ENUM_API = "https://sonar.omnisint.io/subdomains"; // public API for subdomains
const MAX_SUBDOMAIN_ENTRIES = 200;

// Patterns considered sensitive or dangerous
const SENSITIVE_SUBDOMAIN_PATTERNS: RegExp[] = [
  /admin/i,
  /test/i,
  /dev/i,
  /stage/i,
  /mail/i,
  /login/i,
  /^ftp$/i,
  /vpn/i,
  /^webmail$/i,
  /^secure$/i,
  /portal/i,
  /api/i,
  /internal/i,
  /db/i,
  /backup/i,
  /backup1/i,
  /old/i,
  /beta/i,
];

// Simulate unused subdomains via common prefixes that might be stale
const COMMON_UNUSED_PREFIXES = ["old", "test", "dev", "stage", "beta"];

// Timeout constants
const FETCH_TIMEOUT_MS = 10000;

// -----------------------------
// Utilities
// -----------------------------
function scoreToGrade(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 85) return "A";
  if (score >= 70) return "B";
  if (score >= 55) return "C";
  if (score >= 40) return "D";
  return "F";
}

function isSensitiveSubdomain(sub: string): boolean {
  return SENSITIVE_SUBDOMAIN_PATTERNS.some((re) => re.test(sub));
}

function isUnusedSubdomain(sub: string): boolean {
  return COMMON_UNUSED_PREFIXES.some((prefix) => sub.startsWith(prefix));
}

// -----------------------------
// Fetch Subdomains From DNS API
// -----------------------------
async function fetchDnsSubdomains(domain: string): Promise<string[]> {
  try {
    const url = `${DNS_ENUM_API}/${encodeURIComponent(domain)}`;
    const res = await safeFetch(url, { timeoutMs: FETCH_TIMEOUT_MS });
    if (!res.ok) throw new Error(`HTTP ${res.status} from DNS API`);
    const data = await res.json();
    if (!Array.isArray(data)) throw new Error("Invalid data format from DNS API");
    return data.slice(0, MAX_SUBDOMAIN_ENTRIES);
  } catch (e) {
    throw new Error(`DNS API fetch failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// -----------------------------
// Fetch Subdomains From Certificate Transparency Logs
// -----------------------------
async function fetchCtLogSubdomains(domain: string): Promise<string[]> {
  // Use crt.sh JSON API
  try {
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    const res = await safeFetch(url, { timeoutMs: FETCH_TIMEOUT_MS });
    if (!res.ok) throw new Error(`HTTP ${res.status} from CT log API`);
    const text = await res.text();
    if (!text || text.length === 0) return [];
    const entries = JSON.parse(text);
    if (!Array.isArray(entries)) return [];
    // Extract subdomains from Common Name and SAN
    const subdomainsSet = new Set<string>();
    for (const entry of entries) {
      if (typeof entry.name_value === "string") {
        // name_value can contain multiple names newline separated
        const names = entry.name_value.split(/\s+/);
        for (const n of names) {
          if (n.endsWith(domain)) {
            // Remove wildcard prefixes
            const sub = n.replace(/^\*\./, "");
            if (sub.length > 0 && sub !== domain) {
              subdomainsSet.add(sub.toLowerCase());
            }
          }
        }
      }
      if (subdomainsSet.size >= MAX_SUBDOMAIN_ENTRIES) break;
    }
    return Array.from(subdomainsSet).slice(0, MAX_SUBDOMAIN_ENTRIES);
  } catch (e) {
    throw new Error(`CT log API fetch failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// -----------------------------
// Fetch Subdomains From Public API (Placeholder)
// -----------------------------
async function fetchPublicApiSubdomains(domain: string): Promise<string[]> {
  // As no API keys allowed, emulate limited subdomain enumeration
  // Use https://securitytrails.com API open endpoints is restricted; fallback to empty
  // For demo, fetch DNS TXT records via google DNS
  try {
    const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`;
    const res = await safeFetch(url, { timeoutMs: FETCH_TIMEOUT_MS });
    if (!res.ok) throw new Error(`HTTP ${res.status} from public DNS API`);
    const data = await res.json();
    // Attempt: parse txt records for subdomains may not be reliable
    // Return empty list to indicate no data
    return [];
  } catch (e) {
    // Return empty list on failure
    return [];
  }
}

// -----------------------------
// Aggregate and Score
// -----------------------------
function aggregateSubdomains(sourcesData: Record<string, string[]>): string[] {
  const mergedSet = new Set<string>();
  for (const arr of Object.values(sourcesData)) {
    arr.forEach((sd) => mergedSet.add(sd));
  }
  return Array.from(mergedSet).slice(0, MAX_SUBDOMAIN_ENTRIES);
}

function calculateExposureScore(subdomains: string[]): number {
  // Calculate score 0-100 based on count, sensitive subset, and unused subdomains
  const total = subdomains.length;
  if (total === 0) return 0;

  let sensitiveCount = 0;
  let unusedCount = 0;
  for (const sd of subdomains) {
    if (isSensitiveSubdomain(sd)) sensitiveCount++;
    if (isUnusedSubdomain(sd)) unusedCount++;
  }

  const sensitiveRatio = sensitiveCount / total;
  const unusedRatio = unusedCount / total;

  // Score: fewer sensitive and unused subdomains is better
  // Weight sensitive higher
  let score = 100;
  score -= sensitiveRatio * 60; // up to 60 points penalty
  score -= unusedRatio * 30;    // up to 30 points penalty
  score -= Math.min(total, 100) * 0.1; // small penalty for large number of subdomains

  if (score < 0) score = 0;
  return Math.round(score);
}

function generateRecommendations(
  subdomains: string[],
  score: number
): ExposureIssue[] {
  const issues: ExposureIssue[] = [];

  if (subdomains.length === 0) {
    issues.push({
      issue: "No subdomains discovered",
      severity: 0,
      suggestion: "No exposure detected. Maintain monitoring.",
    });
    return issues;
  }

  // Check for sensitive subdomains
  const sensitiveSubdomains = subdomains.filter(isSensitiveSubdomain);
  if (sensitiveSubdomains.length > 0) {
    issues.push({
      issue: `Detected ${sensitiveSubdomains.length} sensitive subdomains: ${sensitiveSubdomains
        .slice(0, 5)
        .join(", ")}${sensitiveSubdomains.length > 5 ? ", ..." : ""}`,
      severity: Math.min(100, 50 + sensitiveSubdomains.length * 10),
      suggestion: "Review and secure sensitive subdomains, restrict access and remove unused ones.",
    });
  }

  // Check for unused subdomains
  const unusedSubdomains = subdomains.filter(isUnusedSubdomain);
  if (unusedSubdomains.length > 0) {
    issues.push({
      issue: `Detected ${unusedSubdomains.length} potentially unused subdomains: ${unusedSubdomains
        .slice(0, 5)
        .join(", ")}${unusedSubdomains.length > 5 ? ", ..." : ""}`,
      severity: Math.min(80, 30 + unusedSubdomains.length * 5),
      suggestion: "Disable or remove unused subdomains to reduce attack surface.",
    });
  }

  if (score < 50 && issues.length === 0) {
    issues.push({
      issue: "Subdomain exposure score is low without clear issues",
      severity: 50,
      suggestion: "Perform manual review of subdomains for hidden risks.",
    });
  }

  if (issues.length === 0) {
    issues.push({
      issue: "Subdomain exposure looks good",
      severity: 0,
      suggestion: "Maintain current security posture and monitor regularly.",
    });
  }

  return issues;
}

// -----------------------------
// Public API: previewExposureScan
// Limited data sources, free, no CT queries, no public API,
// just DNS enumeration + simple scoring
// -----------------------------
export async function previewExposureScan(domain: string): Promise<SubdomainExposureScorePreview> {
  // Fetch DNS subdomains only
  let dnsSubs: string[] = [];
  try {
    dnsSubs = await fetchDnsSubdomains(domain);
  } catch (e) {
    // partial failure: empty list
    dnsSubs = [];
  }

  const subdomainCount = dnsSubs.length;
  const exposureScore = calculateExposureScore(dnsSubs);
  const grade = scoreToGrade(exposureScore);

  const recommendations = generateRecommendations(dnsSubs, exposureScore);

  return {
    domain,
    subdomainCount,
    exposureScore,
    grade,
    details: "Preview scan with limited data sources; for full audit pay via x402 or MPP.",
    recommendations,
  };
}

// -----------------------------
// Public API: comprehensiveExposureScan
// Uses multiple data sources with parallel fetches, detailed analysis,
// scoring, grading, and recommendations
// -----------------------------
export async function comprehensiveExposureScan(domain: string): Promise<SubdomainExposureScoreResult> {
  // Query multiple data sources in parallel
  const sources: {
    dns?: string[];
    ctLogs?: string[];
    publicApis?: string[];
  } = {};

  try {
    const [dnsRes, ctRes, pubRes] = await Promise.all([
      fetchDnsSubdomains(domain).catch((e) => {
        throw new Error(`DNS subdomains error: ${e.message}`);
      }),
      fetchCtLogSubdomains(domain).catch((e) => {
        console.warn(`[comprehensiveExposureScan] CT log fetch failed, continuing: ${e.message}`);
        return [];
      }),
      fetchPublicApiSubdomains(domain).catch((e) => {
        console.warn(`[comprehensiveExposureScan] Public API fetch failed, continuing: ${e.message}`);
        return [];
      }),
    ]);

    sources.dns = dnsRes;
    sources.ctLogs = ctRes;
    sources.publicApis = pubRes || [];
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`Data source fetch failure: ${msg}`);
  }

  // Aggregate all unique subdomains 
  const allSubdomains = aggregateSubdomains(sources);

  const exposureScore = calculateExposureScore(allSubdomains);
  const grade = scoreToGrade(exposureScore);

  const recommendations = generateRecommendations(allSubdomains, exposureScore);

  return {
    domain,
    subdomains: allSubdomains,
    sources: {
      dns: sources.dns ? sources.dns.length : 0,
      ctLogs: sources.ctLogs ? sources.ctLogs.length : 0,
      publicApis: sources.publicApis ? sources.publicApis.length : 0,
    },
    exposureScore,
    grade,
    explanation: `Analyzed subdomains from multiple data sources. Detected ${allSubdomains.length} unique subdomains with exposure score ${exposureScore}.`,
    recommendations,
  };
}
