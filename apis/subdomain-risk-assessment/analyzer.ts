import { safeFetch } from "../../shared/ssrf";

// -- Types --

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface SubdomainDetail {
  subdomain: string;
  ip: string | null;
  misconfigurations: string[];
  outdatedService: string | null;
  exposedEndpoints: string[];
  sensitiveExposure: boolean;
}

export interface SubdomainRiskAssessmentResult {
  domain: string;
  subdomainsCount: number;
  detailedSubdomains?: SubdomainDetail[]; // only in full
  summary: {
    misconfigurations: number;
    outdatedServices: number;
    exposedEndpoints: number;
    sensitiveExposure: number;
  };
  score: number; // 0-100
  grade: string; // A-F
  recommendations: Recommendation[];
  details: string;
  checkedAt: string;
}

// Constants
const CT_LOG_URL = "https://crt.sh";
const DNS_RESOLVE_TIMEOUT = 10000;
const CERT_FETCH_TIMEOUT = 10000;

// Helper: grade from score
function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  if (score >= 30) return "E";
  return "F";
}

// Basic validation: domain format
function validateDomain(domain: string): boolean {
  // Simple regex for domain labels separated by dots
  // Allow punycode
  return /^[a-z0-9\-\.]+$/i.test(domain) && !domain.includes("..") && !domain.startsWith(".") && !domain.endsWith(".");
}

// Secure Fetch with timeout
async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  return safeFetch(url, { timeoutMs, headers: { "User-Agent": "subdomain-risk-assessment/1.0 apimesh.xyz" } });
}

// Enumerate subdomains from certificate transparency logs
async function enumerateSubdomainsCertTransparency(domain: string): Promise<Set<string>> {
  const subdomains = new Set<string>();
  try {
    const url = `${CT_LOG_URL}/?q=%25.${encodeURIComponent(domain)}&output=json`;
    const res = await fetchWithTimeout(url, CERT_FETCH_TIMEOUT);
    if (!res.ok) throw new Error(`crt.sh responded ${res.status}`);
    const text = await res.text();
    if (!text || text === "[]") return subdomains;
    const data = JSON.parse(text);
    if (!Array.isArray(data)) return subdomains;
    for (const entry of data) {
      if (typeof entry?.name_value === "string") {
        const names = entry.name_value.split(/\s+/).filter(Boolean);
        for (const name of names) {
          if (name.endsWith(domain)) {
            subdomains.add(name.toLowerCase());
          }
        }
      }
    }
  } catch (e) {
    // Fail silently for CT enumeration to avoid blocking
  }
  return subdomains;
}

// Enumerate subdomains from DNS (A/AAAA/NSEC scanning not feasible here)
// Fallback: Use a static common prefixes list
const COMMON_SUBDOMAINS = [
  "www",
  "mail",
  "ftp",
  "smtp",
  "webmail",
  "admin",
  "beta",
  "test",
  "dev",
  "staging",
  "api",
  "shop",
  "blog",
];

async function enumerateSubdomainsDNS(domain: string): Promise<Set<string>> {
  // Try to resolve common prefixes
  const results = new Set<string>();

  const fetches = COMMON_SUBDOMAINS.map(async (prefix) => {
    const fqdn = `${prefix}.${domain}`;
    try {
      // Use public DNS resolver over HTTPS to check A record
      const url = `https://dns.google/resolve?name=${encodeURIComponent(fqdn)}&type=A`;
      const res = await fetchWithTimeout(url, DNS_RESOLVE_TIMEOUT);
      if (!res.ok) return;
      const data = await res.json();
      if (data?.Answer && Array.isArray(data.Answer) && data.Answer.length > 0) {
        results.add(fqdn.toLowerCase());
      }
    } catch {
      // Ignore errors in dns query
    }
  });

  await Promise.all(fetches);
  return results;
}

// Analyze a subdomain for common misconfigurations and risks
async function analyzeSubdomain(subdomain: string): Promise<SubdomainDetail> {
  const misconfigurations: string[] = [];
  let outdatedService: string | null = null;
  const exposedEndpoints: string[] = [];
  let sensitiveExposure = false;

  let ip: string | null = null;

  try {
    // Resolve IP via DNS over HTTPS
    const url = `https://dns.google/resolve?name=${encodeURIComponent(subdomain)}&type=A`;
    const res = await fetch(url, { signal: AbortSignal.timeout(DNS_RESOLVE_TIMEOUT) });
    if (res.ok) {
      const data = await res.json();
      if (data?.Answer && Array.isArray(data.Answer)) {
        const answer = data.Answer.find((a: any) => typeof a.data === "string");
        if (answer) ip = answer.data;
      }
    }
  } catch {
    ip = null;
  }

  // If IP resolves, try HTTP probe for header checks
  if (ip) {
    try {
      const scheme = "https"; // Prefer HTTPS
      const urlStr = `${scheme}://${subdomain}`;
      const res = await safeFetch(urlStr, {
        method: "GET",
        signal: AbortSignal.timeout(10_000),
        redirect: "manual",
        headers: { "User-Agent": "subdomain-risk-assessment/1.0 apimesh.xyz" },
      });
      // Detect outdated server headers
      const serverHeader = res.headers.get("server");
      if (serverHeader) {
        const serverLower = serverHeader.toLowerCase();
        if (/apache\s?2\.2/.test(serverLower)) {
          outdatedService = "Apache 2.2";
          misconfigurations.push("Outdated Apache 2.2 server detected");
        } else if (/nginx\/[0-1]\./.test(serverLower)) {
          outdatedService = "Old Nginx (v1.x)";
          misconfigurations.push("Old Nginx version detected");
        }
      }

      // Check for exposed common debug endpoints
      for (const ep of ["/debug", "/status", "/admin", "/config"] ) {
        try {
          const epUrl = `${urlStr}${ep}`;
          const epRes = await safeFetch(epUrl, {
            method: "HEAD",
            signal: AbortSignal.timeout(8000),
            redirect: "manual",
            headers: { "User-Agent": "subdomain-risk-assessment/1.0 apimesh.xyz" },
          });
          if (epRes.status === 200) {
            exposedEndpoints.push(ep);
            misconfigurations.push(`Exposed endpoint at ${ep}`);
          }
        } catch {
          // ignore endpoint fetch failures
        }
      }

      // Check for sensitive exposure - very basic heuristic
      const contentType = res.headers.get("content-type") || "";
      if (contentType.includes("text/plain") || contentType.includes("application/json")) {
        // Do a small body peek
        const bodyText = await res.text();
        if (/password|token|secret|credentials/i.test(bodyText)) {
          sensitiveExposure = true;
          misconfigurations.push("Possible sensitive info exposure in response body");
        }
      }

    } catch {
      // Ignore fetch failures
    }
  }

  return {
    subdomain,
    ip,
    misconfigurations,
    outdatedService,
    exposedEndpoints,
    sensitiveExposure,
  };
}

// Aggregate scores and generate recommendations
function aggregateScore(details: SubdomainDetail[]): { score: number; recommendations: Recommendation[] } {
  let score = 100;
  const recommendations: Recommendation[] = [];

  for (const d of details) {
    for (const issue of d.misconfigurations) {
      // Severity heuristic
      const severity = issue.toLowerCase().includes("exposed")
        ? 80
        : issue.toLowerCase().includes("outdated")
        ? 65
        : 50;
      score -= severity / details.length;
      recommendations.push({
        issue: issue,
        severity,
        suggestion: issue.toLowerCase().includes("exposed")
          ? "Limit access to sensitive endpoints; enforce authentication and IP restrictions"
          : issue.toLowerCase().includes("outdated")
          ? "Update the affected service to the latest secure version"
          : "Investigate and fix the misconfiguration",
      });
    }
    if (d.sensitiveExposure) {
      score -= 30 / details.length;
      recommendations.push({
        issue: `Sensitive data exposure detected on ${d.subdomain}`,
        severity: 90,
        suggestion:
          "Review and sanitize exposed data; restrict access and add authentication",
      });
    }
  }

  // Clamp
  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, recommendations };
}

// Preview assessment - limited enumeration and analysis
export async function previewAssessment(domain: string): Promise<{ status: string; data: SubdomainRiskAssessmentResult; meta: { timestamp: string; duration_ms: number; api_version: string } } | { status: string; error: string }> {
  const start = performance.now();
  if (!validateDomain(domain)) {
    return { status: "error", error: "Invalid domain format" };
  }

  const subdomains = new Set<string>();
  try {
    // Use DNS enumerated common subdomains
    const dnsSubs = await enumerateSubdomainsDNS(domain);
    dnsSubs.forEach(s => subdomains.add(s));

    // Use CT enumeration
    const ctSubs = await enumerateSubdomainsCertTransparency(domain);
    ctSubs.forEach(s => subdomains.add(s));

  } catch (e) {
    // ignore
  }

  // Limit preview to max 25 subdomains
  const limitedSubs = Array.from(subdomains).slice(0, 25);

  // Analyze subdomains - limited to 10 for preview
  const toAnalyze = limitedSubs.slice(0, 10);

  const details: SubdomainDetail[] = await Promise.all(toAnalyze.map(s => analyzeSubdomain(s)));

  // Summaries
  const misconfigurations = details.reduce((a, d) => a + d.misconfigurations.length, 0);
  const outdatedServices = details.reduce((a, d) => a + (d.outdatedService ? 1 : 0), 0);
  const exposedEndpoints = details.reduce((a, d) => a + d.exposedEndpoints.length, 0);
  const sensitiveExposure = details.reduce((a, d) => a + (d.sensitiveExposure ? 1 : 0), 0);

  const { score, recommendations } = aggregateScore(details);
  const grade = scoreToGrade(score);

  const result: SubdomainRiskAssessmentResult = {
    domain,
    subdomainsCount: subdomains.size,
    summary: {
      misconfigurations,
      outdatedServices,
      exposedEndpoints,
      sensitiveExposure,
    },
    score,
    grade,
    recommendations,
    details: "Preview limited to passive enumeration and basic checks.",
    checkedAt: new Date().toISOString(),
  };
  const duration_ms = Math.round(performance.now() - start);
  return {
    status: "ok",
    data: result,
    meta: { timestamp: result.checkedAt, duration_ms, api_version: "1.0.0" },
  };
}

// Full comprehensive assessment
export async function fullAssessment(domain: string): Promise<{ status: string; data: SubdomainRiskAssessmentResult; meta: { timestamp: string; duration_ms: number; api_version: string } } | { status: string; error: string }> {
  const start = performance.now();
  if (!validateDomain(domain)) {
    return { status: "error", error: "Invalid domain format" };
  }

  let subdomains = new Set<string>();

  try {
    // Parallel enumeration
    const [dnsSubs, ctSubs] = await Promise.all([
      enumerateSubdomainsDNS(domain),
      enumerateSubdomainsCertTransparency(domain),
    ]);
    dnsSubs.forEach(s => subdomains.add(s));
    ctSubs.forEach(s => subdomains.add(s));
  } catch (e) {
    // ignore
  }

  // Limit to max 100 subdomains for performance and billing
  const limitedSubs = Array.from(subdomains).slice(0, 100);

  // Analyze all subdomains in parallel with concurrency control (max 10 concurrent)
  const concurrency = 10;
  const detailResults: SubdomainDetail[] = [];

  for (let i = 0; i < limitedSubs.length; i += concurrency) {
    const batch = limitedSubs.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map(s => analyzeSubdomain(s)));
    detailResults.push(...batchResults);
  }

  // Summaries
  const misconfigurations = detailResults.reduce((a, d) => a + d.misconfigurations.length, 0);
  const outdatedServices = detailResults.reduce((a, d) => a + (d.outdatedService ? 1 : 0), 0);
  const exposedEndpoints = detailResults.reduce((a, d) => a + d.exposedEndpoints.length, 0);
  const sensitiveExposure = detailResults.reduce((a, d) => a + (d.sensitiveExposure ? 1 : 0), 0);

  const { score, recommendations } = aggregateScore(detailResults);
  const grade = scoreToGrade(score);

  const result: SubdomainRiskAssessmentResult = {
    domain,
    subdomainsCount: subdomains.size,
    detailedSubdomains: detailResults,
    summary: {
      misconfigurations,
      outdatedServices,
      exposedEndpoints,
      sensitiveExposure,
    },
    score,
    grade,
    recommendations,
    details: "Includes passive and active enumeration, multi-source correlation, and heuristic-based risk scoring.",
    checkedAt: new Date().toISOString(),
  };
  const duration_ms = Math.round(performance.now() - start);
  return {
    status: "ok",
    data: result,
    meta: { timestamp: result.checkedAt, duration_ms, api_version: "1.0.0" },
  };
}
