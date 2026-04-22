import { safeFetch } from "../../shared/ssrf";

export type SeverityLevel = "low" | "medium" | "high";

export interface Recommendation {
  issue: string;
  severity: SeverityLevel;
  suggestion: string;
}

export interface SubdomainRisk {
  name: string;
  ipAddresses: string[];
  riskScore: number; // 0-100
  riskGrade: string; // A-F
  issuesCount: number;
  recommendations: Recommendation[];
  details: string; // human readable summary
}

export interface RiskRankingResult {
  domain: string;
  subdomains: SubdomainRisk[];
  totalSubdomains: number;
  scannedAt: string;
}

export interface PreviewSubdomain {
  name: string;
  ipAddresses: string[];
}

export interface PreviewRiskRankingResult {
  domain: string;
  subdomains: PreviewSubdomain[];
  totalSubdomains: number;
  scannedAt: string;
}

interface AnalyzeOptions {
  previewOnly?: boolean;
}

// Helper: Letter grade by score
function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  if (score >= 40) return "E";
  return "F";
}

// Helper: Timeout helper for fetch
const FETCH_TIMEOUT_MS = 10000;

// Regex for subdomain validation
const SUBDOMAIN_LABEL = /^[a-z0-9-]{1,63}$/;

// Validate domain name format (simple, not full IDN support)
function validateDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  const labels = domain.toLowerCase().split(".");
  if (labels.some((l) => !SUBDOMAIN_LABEL.test(l) || l.startsWith("-") || l.endsWith("-"))) return false;
  return true;
}

async function fetchDnsSubdomains(domain: string): Promise<string[]> {
  try {
    // Using DNS-over-HTTPS public API to get subdomains from known CNAME/DNS logs
    // Note: No direct public free API for exhaustive subdomains, so simulate via crt.sh DNS names
    // Use crt.sh to get names with wildcard query and parse CN names
    const url = `https://crt.sh/?q=%25.${domain}&output=json`;
    const res = await safeFetch(url, {
      timeoutMs: FETCH_TIMEOUT_MS,
      headers: { "User-Agent": "subdomain-risk-ranking/1.0 apimesh.xyz" },
    });
    if (!res.ok) return [];
    const text = await res.text();
    if (!text) return [];
    try {
      const data = JSON.parse(text);
      if (!Array.isArray(data)) return [];
      const namesSet = new Set<string>();
      for (const cert of data) {
        if (typeof cert.name_value === "string") {
          // name_value can be multiple names separated by \n
          const parts = cert.name_value.toLowerCase().split(/\n/);
          for (const part of parts) {
            const cleaned = part.trim();
            if (cleaned.endsWith(domain) && cleaned !== domain && validateDomain(cleaned)) {
              namesSet.add(cleaned);
            }
          }
        }
      }
      return Array.from(namesSet);
    } catch {
      return [];
    }
  } catch {
    return [];
  }
}

async function fetchCertTransparencySubdomains(domain: string): Promise<string[]> {
  // crt.sh call is combined above. To keep extensible,
  // we treat it combined with DNS. In future, connect to other CT log aggregators.
  return fetchDnsSubdomains(domain);
}

async function resolveIpAddresses(subdomain: string): Promise<string[]> {
  try {
    // Query DNS resolution via DNS-over-HTTPS
    const url = `https://dns.google/resolve?name=${encodeURIComponent(subdomain)}&type=A`;
    const res = await safeFetch(url, {
      timeoutMs: FETCH_TIMEOUT_MS,
      headers: { "User-Agent": "subdomain-risk-ranking/1.0 apimesh.xyz" },
    });
    if (!res.ok) return [];
    const data = await res.json();
    if (!data.Answer) return [];
    const ips: string[] = [];
    for (const a of data.Answer) {
      if (typeof a.data === "string" && /^\d{1,3}(\.\d{1,3}){3}$/.test(a.data)) {
        ips.push(a.data);
      }
    }
    return ips;
  } catch {
    return [];
  }
}

// Risk check helpers
async function checkSslCertificate(subdomain: string): Promise<Recommendation | null> {
  // Query crt.sh for this exact subdomain entry
  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(subdomain)}&output=json`;
    const res = await safeFetch(url, {
      timeoutMs: FETCH_TIMEOUT_MS,
      headers: { "User-Agent": "subdomain-risk-ranking/1.0 apimesh.xyz" },
    });
    if (!res.ok) return null;
    const body = await res.text();
    if (!body || body === "[]") return null; // no certs found
    const certs = JSON.parse(body);
    if (!Array.isArray(certs)) return null;
    // Find if any cert expired
    for (const cert of certs) {
      try {
        const notAfter = new Date(cert.not_after);
        if (isNaN(notAfter.getTime())) continue;
        if (Date.now() > notAfter.getTime()) {
          return {
            issue: "Expired SSL certificate",
            severity: "high",
            suggestion: "Renew SSL certificate promptly",
          };
        }
      } catch {
        continue;
      }
    }
    return null;
  } catch {
    return null;
  }
}

async function checkHttpOpen(subdomain: string): Promise<Recommendation | null> {
  // Check if HTTP port 80 responds (not redirected to HTTPS or open)
  try {
    const url = `http://${subdomain}`;
    const res = await safeFetch(url, {
      method: "GET",
      timeoutMs: 8000,
      headers: { "User-Agent": "subdomain-risk-ranking/1.0 apimesh.xyz" },
      redirect: "manual",
      signal: AbortSignal.timeout(8000),
    });
    if (res.status === 200) {
      return {
        issue: "Open HTTP endpoint",
        severity: "medium",
        suggestion: "Redirect HTTP to HTTPS or close port 80",
      };
    }
    // 301/302 redirect to HTTPS allowed
    if (res.status === 301 || res.status === 302) {
      const loc = res.headers.get("location") || "";
      if (!loc.toLowerCase().startsWith("https://")) {
        return {
          issue: "HTTP endpoint redirects to non-HTTPS location",
          severity: "medium",
          suggestion: "Redirect HTTP to HTTPS",
        };
      }
    }
    return null;
  } catch {
    // Timeout or other errors treated as not open
    return null;
  }
}

async function checkServerSoftware(subdomain: string): Promise<Recommendation | null> {
  try {
    const url = `https://${subdomain}`;
    const res = await safeFetch(url, {
      method: "HEAD",
      timeoutMs: 8000,
      headers: { "User-Agent": "subdomain-risk-ranking/1.0 apimesh.xyz" },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const server = res.headers.get("server") || "";
    if (!server) return null;

    // Very simple outdated software detection based on server string
    // In real world, integrate CVE database or software version checks

    const lowVersionPattern = /apache\/(1\.|2\.2|2\.0)/i; // old Apache versions
    const nginxOldPattern = /nginx\/(0\.|1\.[0-9]\.)/i; // old nginx
    if (lowVersionPattern.test(server) || nginxOldPattern.test(server)) {
      return {
        issue: `Outdated server software (${server})`,
        severity: "medium",
        suggestion: "Update to latest stable server software version",
      };
    }
    return null;
  } catch {
    return null;
  }
}

async function analyzeSubdomain(subdomain: string): Promise<SubdomainRisk> {
  const ipAddresses = await resolveIpAddresses(subdomain);

  const issues: string[] = [];
  const recommendations: Recommendation[] = [];

  // Riskiest checks
  const [sslCheck, httpCheck, serverCheck] = await Promise.all([
    checkSslCertificate(subdomain),
    checkHttpOpen(subdomain),
    checkServerSoftware(subdomain),
  ]);

  if (sslCheck) {
    recommendations.push(sslCheck);
    issues.push(sslCheck.issue);
  }
  if (httpCheck) {
    recommendations.push(httpCheck);
    issues.push(httpCheck.issue);
  }
  if (serverCheck) {
    recommendations.push(serverCheck);
    issues.push(serverCheck.issue);
  }

  // Additional checks could be here for open ports, DNS misconfigs, exposed services...

  // Score calculation (simplified, weighted by presence of issues)
  let baseScore = 100;
  for (const rec of recommendations) {
    if (rec.severity === "high") baseScore -= 40;
    else if (rec.severity === "medium") baseScore -= 20;
    else if (rec.severity === "low") baseScore -= 10;
  }
  if (baseScore < 0) baseScore = 0;

  // Compose detail summary
  const details = issues.length > 0
    ? `Found issues: ${issues.join(", ")}. See recommendations for details.`
    : "No significant risks detected.";

  return {
    name: subdomain,
    ipAddresses,
    riskScore: baseScore,
    riskGrade: scoreToGrade(baseScore),
    issuesCount: recommendations.length,
    recommendations,
    details,
  };
}

// Core function to perform comprehensive risk ranking
export async function performComprehensiveRiskRanking(
  domain: string,
  opts: AnalyzeOptions = {}
): Promise<RiskRankingResult | PreviewRiskRankingResult> {
  if (!validateDomain(domain)) {
    throw new Error("Invalid domain format");
  }

  // Step 1: Enumerate subdomains from DNS and certificate transparency logs in parallel
  let subdomainLists: string[][] = [];
  try {
    subdomainLists = await Promise.all([
      fetchDnsSubdomains(domain),
      fetchCertTransparencySubdomains(domain),
    ]);
  } catch {
    // Ignore failures in enumeration sources (include partial results)
    subdomainLists = [[], []];
  }

  // Combine subdomains unique
  const combinedSubsSet = new Set<string>();
  for (const list of subdomainLists) {
    for (const entry of list) {
      if (entry.endsWith(domain)) {
        combinedSubsSet.add(entry.toLowerCase());
      }
    }
  }
  const subdomainsArray = Array.from(combinedSubsSet);

  // Include root domain? The spec only mentions subdomains, but adding root domain for completeness
  // Although many checks apply to root domain separately

  if (opts.previewOnly) {
    // Preview: return only names and attached IPs, no scoring
    // Resolve IPs in parallel, but capped to 30 subdomains for performance
    const capped = subdomainsArray.slice(0, 30);
    const ipPromises = capped.map(async (sd) => {
      const ips = await resolveIpAddresses(sd);
      return { name: sd, ipAddresses: ips };
    });
    const resultSubdomains = await Promise.all(ipPromises);

    return {
      domain,
      subdomains: resultSubdomains,
      totalSubdomains: combinedSubsSet.size,
      scannedAt: new Date().toISOString(),
    };
  }

  // Comprehensive full risk check: limit to 50 subdomains max to avoid excessive CPU/IO
  const cappedSubdomains = subdomainsArray.slice(0, 50);
  const analysisPromises = cappedSubdomains.map((sd) => analyzeSubdomain(sd));
  const analyzedSubs = await Promise.all(analysisPromises);

  return {
    domain,
    subdomains: analyzedSubs,
    totalSubdomains: combinedSubsSet.size,
    scannedAt: new Date().toISOString(),
  };
}
