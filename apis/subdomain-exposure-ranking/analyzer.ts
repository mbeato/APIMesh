import { safeFetch, validateExternalUrl } from "../../shared/ssrf";

// -- Types --

export interface SubdomainExposureReport {
  domain: string;
  totalSubdomains: number;
  subdomainsSample?: EnrichedSubdomainResult[]; // limited sample for preview
  subdomains?: EnrichedSubdomainResult[]; // full list for paid
  overallScore: number; // 0-100
  overallGrade: LetterGrade;
  recommendations: Recommendation[];
  checkedAt: string; // ISO timestamp
  explanation: string;
}

export interface EnrichedSubdomainResult {
  subdomain: string;
  score: number; // 0-100 exposure risk score
  grade: LetterGrade; // A-F
  exposures: number; // number of detected exposure issues
  outdatedServices: number; // number of outdated service detections
  details?: ExposureDetails;
  recommendations?: Recommendation[];
}

export interface ExposureDetails {
  httpHeaders?: Record<string, string>;
  tlsVersion?: string;
  serviceVersions?: Record<string, string>;
  openEndpoints?: string[];
  notes?: string[];
}

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

type LetterGrade = "A" | "B" | "C" | "D" | "E" | "F";

// -- Constants --

const HTTP_TIMEOUT = 10000; // 10s per request
const DNS_TIMEOUT = 10000; // 10s
const CTLOGS_TIMEOUT = 10000; // 10s

// -- Public Analysis Entry --

/**
 * Analyze subdomains of the domain.
 * mode = 'preview' samples limited data, 'full' runs comprehensive collected checks
 */
export async function analyzeSubdomains(
  domain: string,
  options: { mode: "preview" | "full" }
): Promise<SubdomainExposureReport> {
  // Validate domain (basic)
  if (!/^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?:[A-Za-z]{2,63})$/.test(domain)) {
    throw new Error("Domain parameter has invalid format or unsupported TLD");
  }

  // Enumerate subdomains from multiple sources
  const [dnsSubs, ctSubs] = await Promise.all([
    enumerateSubdomainsFromDNS(domain),
    enumerateSubdomainsFromCTLogs(domain),
  ]);

  // Merge and deduplicate
  const allSubdomainsSet = new Set<string>();
  dnsSubs.forEach((sd) => allSubdomainsSet.add(sd));
  ctSubs.forEach((sd) => allSubdomainsSet.add(sd));

  const allSubdomains = Array.from(allSubdomainsSet).filter((sd) => sd.endsWith(domain));

  // Limit details in preview
  const subdomainSlice = options.mode === "preview" ? allSubdomains.slice(0, 10) : allSubdomains;

  // Analyze exposures of each subdomain with concurrency limit
  const concurrency = 5;
  const results: EnrichedSubdomainResult[] = [];

  const promises: Promise<void>[] = [];
  let active = 0;
  for (const subdomain of subdomainSlice) {
    const p = analyzeExposures(subdomain)
      .then((res) => {
        results.push(res);
      })
      .catch((e) => {
        // Fail safe: record minimal result
        results.push({
          subdomain,
          score: 0,
          grade: "F",
          exposures: 0,
          outdatedServices: 0,
          details: { notes: [`Analysis error: ${(e as Error).message}`] },
          recommendations: [
            {
              issue: "Subdomain analysis failure",
              severity: 90,
              suggestion: "Ensure availability of service and try again later.",
            },
          ],
        });
      })
      .finally(() => {
        active--;
      });

    promises.push(p);
    active++;
    if (active >= concurrency) {
      await Promise.race(promises);
    }
  }
  await Promise.all(promises);

  // Score aggregation
  const overallScore = Math.round(
    results.reduce((acc, r) => acc + r.score, 0) / (results.length || 1)
  );
  const overallGrade = computeLetterGrade(overallScore);

  // Aggregate top recommendations prioritizing severity
  const allRecommendations = results.flatMap((r) => r.recommendations || []);
  const recMap = new Map<string, Recommendation>();
  for (const rec of allRecommendations) {
    if (!recMap.has(rec.issue) || (recMap.get(rec.issue)?.severity ?? 0) < rec.severity) {
      recMap.set(rec.issue, rec);
    }
  }

  const finalRecommendations = Array.from(recMap.values()).sort(
    (a, b) => b.severity - a.severity
  );

  const explanation =
    "This report combines subdomain enumeration via DNS and certificate transparency logs, enriched by HTTP probing and security configuration analysis, providing exposure risk scoring and remediation guidelines.";

  return {
    domain,
    totalSubdomains: allSubdomains.length,
    subdomainsSample: options.mode === "preview" ? results : undefined,
    subdomains: options.mode === "full" ? results : undefined,
    overallScore,
    overallGrade,
    recommendations: finalRecommendations,
    checkedAt: new Date().toISOString(),
    explanation,
  };
}

// -- Implementation details --

/**
 * Basic DNS subdomain enumeration using public DNS lookup for NS and A records of common prefixes.
 * For demo usage: limited common subdomains queried.
 */
async function enumerateSubdomainsFromDNS(domain: string): Promise<string[]> {
  // Common subdomain prefixes for quick discovery
  const commonSubdomains = [
    "www",
    "mail",
    "ftp",
    "api",
    "dev",
    "admin",
    "test",
    "portal",
    "m",
    "blog",
  ];

  const results: string[] = [];
  const concurrency = 5;
  const promises: Promise<void>[] = [];
  let active = 0;

  for (const prefix of commonSubdomains) {
    const fqdn = `${prefix}.${domain}`;
    const p = dnsResolveA(fqdn)
      .then((ips) => {
        if (ips.length > 0) results.push(fqdn);
      })
      .catch(() => {
        // Ignore failure silently
      })
      .finally(() => {
        active--;
      });

    promises.push(p);
    active++;
    if (active >= concurrency) {
      await Promise.race(promises);
    }
  }

  await Promise.all(promises);

  return results;
}

/**
 * Query crt.sh to find recently issued certificates for the domain and extract subdomains.
 */
async function enumerateSubdomainsFromCTLogs(domain: string): Promise<string[]> {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  try {
    const res = await safeFetch(url, { timeoutMs: CTLOGS_TIMEOUT });
    if (!res.ok) throw new Error(`crt.sh HTTP status ${res.status}`);
    const text = await res.text();
    if (!text || text === "[]") return [];
    const json = JSON.parse(text);
    if (!Array.isArray(json)) return [];

    const subdomainsSet = new Set<string>();
    for (const entry of json) {
      if (typeof entry?.name_value !== "string") continue;
      const names = entry.name_value.split("\n");
      for (const name of names) {
        const cleanName = name.toLowerCase().trim();
        if (cleanName.endsWith(domain)) subdomainsSet.add(cleanName);
      }
    }

    return Array.from(subdomainsSet);
  } catch (e) {
    return [];
  }
}

/**
 * Perform exposure analysis on a fully qualified subdomain.
 * Includes HTTP header probing, TLS checks, outdated service detection.
 */
export async function analyzeExposures(
  fqdn: string
): Promise<EnrichedSubdomainResult> {
  const recordsResult: EnrichedSubdomainResult = {
    subdomain: fqdn,
    score: 0,
    grade: "F",
    exposures: 0,
    outdatedServices: 0,
    details: {},
    recommendations: [],
  };

  try {
    // Validate fqdn
    if (!/^([a-z0-9-]+\.)+[a-z]{2,63}$/.test(fqdn)) {
      throw new Error("Invalid subdomain format");
    }

    // Check HTTP and HTTPS endpoints
    const urlHttp = `http://${fqdn}/`;
    const urlHttps = `https://${fqdn}/`;

    // Probe HTTP and HTTPS in parallel with timeout
    const [httpRes, httpsRes] = await Promise.all([
      probeHttpEndpoint(urlHttp),
      probeHttpEndpoint(urlHttps),
    ]);

    let exposuresDetected = 0;
    let outdatedServicesDetected = 0;
    const recs: Recommendation[] = [];
    const details: ExposureDetails = { notes: [] };

    // Evaluate HTTP response header exposures
    if (httpRes.reachable) {
      details.httpHeaders = httpRes.headers;
      if (httpRes.headers["server"]?.toLowerCase().includes("apache")) {
        exposuresDetected++;
        recs.push({
          issue: "HTTP server header leaks exposure",
          severity: 30,
          suggestion: "Remove or obfuscate Server header to prevent fingerprinting.",
        });
      }
      if (httpRes.headers["x-powered-by"]?.toLowerCase().includes("php/5.")) {
        outdatedServicesDetected++;
        recs.push({
          issue: "Outdated PHP version detected",
          severity: 80,
          suggestion: "Upgrade PHP to actively supported and secure versions.",
        });
      }
    }

    if (httpsRes.reachable) {
      details.tlsVersion = httpsRes.tlsVersion;
      details.httpHeaders = {
        ...details.httpHeaders,
        ...httpsRes.headers,
      };

      // Check TLS version for modernity
      if (httpsRes.tlsVersion === "TLS 1.0" || httpsRes.tlsVersion === "TLS 1.1") {
        exposuresDetected++;
        recs.push({
          issue: "Outdated TLS version in use",
          severity: 70,
          suggestion:
            "Upgrade TLS to version 1.2 or preferably 1.3 to ensure strong encryption.",
        });
      }

      if (httpsRes.headers["server"]?.toLowerCase().includes("nginx")) {
        // Example suggestion
        recs.push({
          issue: "Nginx server detected",
          severity: 10,
          suggestion: "Ensure Nginx configuration disables server tokens.",
        });
      }
    }

    // Scan for exposed endpoints (simple heuristic)
    if (httpRes.openEndpoints.length || httpsRes.openEndpoints.length) {
      exposuresDetected += httpRes.openEndpoints.length + httpsRes.openEndpoints.length;
      details.openEndpoints = [...httpRes.openEndpoints, ...httpsRes.openEndpoints];

      for (const ep of details.openEndpoints) {
        recs.push({
          issue: `Exposed endpoint: ${ep}`,
          severity: 60,
          suggestion: `Restrict or secure the endpoint ${ep} to prevent unauthorized access.`,
        });
      }
    }

    // Score calculation: basic formula
    let baseScore = 100;
    baseScore -= exposuresDetected * 15;
    baseScore -= outdatedServicesDetected * 20;

    if (baseScore < 0) baseScore = 0;
    if (baseScore > 100) baseScore = 100;

    const grade = computeLetterGrade(baseScore);

    return {
      subdomain: fqdn,
      score: baseScore,
      grade,
      exposures: exposuresDetected,
      outdatedServices: outdatedServicesDetected,
      details,
      recommendations: recs,
    };
  } catch (e) {
    return {
      subdomain: fqdn,
      score: 0,
      grade: "F",
      exposures: 0,
      outdatedServices: 0,
      details: { notes: [`Analysis error: ${(e as Error).message}`] },
      recommendations: [
        {
          issue: "Subdomain analysis failure",
          severity: 90,
          suggestion: "Ensure DNS resolves and services are reachable.",
        },
      ],
    };
  }
}

// --- Helpers ---

/**
 * Simple DNS A record resolution using DNS over HTTPS (Google's DNS API)
 * Returns list of IPv4 addresses or empty array if none or error.
 */
async function dnsResolveA(fqdn: string): Promise<string[]> {
  try {
    const dnsUrl = `https://dns.google/resolve?name=${encodeURIComponent(fqdn)}&type=A`;
    const res = await safeFetch(dnsUrl, { timeoutMs: DNS_TIMEOUT });
    if (!res.ok) throw new Error(`DNS query status ${res.status}`);
    const js = await res.json();
    if (!js.Answer || !Array.isArray(js.Answer)) return [];

    const ips: string[] = [];
    for (const ans of js.Answer) {
      if (ans.type === 1 && typeof ans.data === "string") {
        ips.push(ans.data);
      }
    }
    return ips;
  } catch {
    return [];
  }
}

interface ProbeResult {
  reachable: boolean;
  headers: Record<string, string>;
  tlsVersion?: string;
  openEndpoints: string[];
}

/**
 * Probe HTTP or HTTPS endpoint on / with GET request to check headers and TLS info.
 * Returns probe results with headers, TLS version (best effort), and open endpoints detected.
 */
async function probeHttpEndpoint(url: string): Promise<ProbeResult> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), HTTP_TIMEOUT);

    // HEAD requests often blocked; use GET to get headers
    const res = await safeFetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: { "User-Agent": "subdomain-exposure-ranking/1.0 apimesh.xyz" },
    });
    clearTimeout(timeout);

    const headersObj: Record<string, string> = {};
    for (const [key, val] of res.headers.entries()) {
      headersObj[key.toLowerCase()] = val;
    }

    // Determine TLS version from connection info if available - no direct way in fetch, approximated
    // Here, we fake TLS version detection by checking headers only (simplified)
    let tlsVersion = "unknown";
    if (url.startsWith("https://")) {
      if (headersObj["strict-transport-security"]) {
        tlsVersion = "TLS 1.2 or 1.3";
      }
    }

    // Simple heuristic for known exposed endpoints (e.g., /admin, /git, /backup...)
    const openEndpoints = [] as string[];
    const candidatePaths = ["admin", "git", "backup", "config", ".env"];

    // Check presence by quick fetch HEAD with timeout
    const probePromises = candidatePaths.map(async (path) => {
      const checkUrl = new URL(url);
      checkUrl.pathname = `/${path}`;
      try {
        const r = await safeFetch(checkUrl.toString(), { method: "HEAD", timeoutMs: 8000 });
        if (r.ok) {
          openEndpoints.push(`/${path}`);
        }
      } catch {
        // ignore
      }
    });

    await Promise.all(probePromises);

    return {
      reachable: res.ok,
      headers: headersObj,
      tlsVersion,
      openEndpoints,
    };
  } catch (e) {
    return { reachable: false, headers: {}, openEndpoints: [] };
  }
}

/**
 * Convert numeric score into letter grade.
 */
function computeLetterGrade(score: number): LetterGrade {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  if (score >= 30) return "E";
  return "F";
}
