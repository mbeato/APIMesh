import { safeFetch } from "../../shared/ssrf";

// Types
export type Grade = "A" | "B" | "C" | "D" | "F";

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface SubdomainReport {
  name: string;
  score: number; // 0-100
  grade: Grade;
  issues: string[];
  recommendations: Recommendation[];
  lastScanned?: string; // ISO8601 timestamp
}

export interface SubdomainExposureRankingsPreviewResult {
  status: "ok";
  data: {
    domain: string;
    subdomains_found: number;
    subdomains: SubdomainReport[];
    summary_score: number; // 0-100
    summary_grade: Grade;
    explanation: string;
  };
  meta: {
    timestamp: string;
    duration_ms: number;
    api_version: string;
  };
}

export interface SubdomainExposureRankingsFullResult {
  domain: string;
  total_subdomains: number;
  analyzed_subdomains: number;
  subdomains: SubdomainReport[];
  overall_score: number;
  overall_grade: Grade;
  explanation: string;
  scannedAt: string;
  error?: string;
  // Meta omitted for payload, handled by route
}

// Grade mapping function
function gradeFromScore(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

// Utility to produce recommendations given issues
function generateRecommendations(issues: string[]): Recommendation[] {
  const recs: Recommendation[] = [];

  for (const issue of issues) {
    // Assign severity heuristic based on issue keywords
    let severity = 50;
    let suggestion = "Investigate and resolve this issue.";

    if (/expos(?:ed|ure)/i.test(issue)) {
      severity = 90;
      suggestion = "Restrict access and audit this exposed service or path.";
    } else if (/outdated|deprecated/i.test(issue)) {
      severity = 70;
      suggestion = "Update software or dependencies to the latest secure versions.";
    } else if (/misconfigur/i.test(issue)) {
      severity = 65;
      suggestion = "Review configuration to close security gaps.";
    } else if (/ssl|tls/i.test(issue)) {
      severity = 80;
      suggestion = "Upgrade SSL/TLS configurations to industry best practices.";
    } else if (/open port/i.test(issue)) {
      severity = 85;
      suggestion = "Close unnecessary open ports or restrict access by firewall rules.";
    }

    recs.push({ issue, severity, suggestion });
  }

  return recs;
}

// Simulated subdomain enumeration using data sources
async function enumerateSubdomains(domain: string, signal: AbortSignal): Promise<string[]> {
  // Use crt.sh API for certificate transparency logs
  // Use DNS over HTTPS for DNS enumeration

  // crt.sh fetch
  const crtShUrl = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  // dns.google resolve
  const googleDnsUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=NS`;

  try {
    const [crtResp, dnsResp] = await Promise.all([
      safeFetch(crtShUrl, { timeoutMs: 10000, signal }),
      safeFetch(googleDnsUrl, { timeoutMs: 10000, signal }),
    ]);

    let crtData: any[] = [];
    let crtSubdomains: Set<string> = new Set();

    if (crtResp.ok) {
      try {
        crtData = await crtResp.json();
        if (Array.isArray(crtData)) {
          for (const entry of crtData) {
            if (typeof entry.name_value === "string") {
              const names = entry.name_value.split(/\n|\r\n/).map(s => s.trim().toLowerCase());
              for (const sub of names) {
                // Filter subdomains ending with domain
                if (sub.endsWith(domain.toLowerCase())) crtSubdomains.add(sub);
              }
            }
          }
        }
      } catch {
        // ignore JSON parse failure
      }
    }

    // Also get NS records to add NS subdomains
    let dnsSubdomains: Set<string> = new Set();
    if (dnsResp.ok) {
      try {
        const dnsData = await dnsResp.json();
        if (dnsData?.Authority && Array.isArray(dnsData.Authority)) {
          for (const a of dnsData.Authority) {
            if (typeof a.data === "string") {
              dnsSubdomains.add(a.data.trim());
            }
          }
        }
        if (dnsData?.Answer && Array.isArray(dnsData.Answer)) {
          for (const ans of dnsData.Answer) {
            if (typeof ans.name === "string") {
              dnsSubdomains.add(ans.name.trim());
            }
          }
        }
      } catch {
        // ignore parse failure
      }
    }

    // Combine and normalize
    const combined = new Set<string>([...crtSubdomains, ...dnsSubdomains]);
    // Always include domain itself
    combined.add(domain);

    // Only subdomains ending with domain
    const filteredSubs = Array.from(combined).filter(s => s.endsWith(domain.toLowerCase()));

    // Limit results to max 100 to avoid overload
    return filteredSubs.slice(0, 100);
  } catch (e) {
    return [domain]; // fallback just root domain if failure
  }
}

// Simulate analysis check of subdomain
async function analyzeSubdomain(subdomain: string, signal: AbortSignal): Promise<SubdomainReport> {
  // We'll perform multiple checks:
  // 1. HTTP(S) fetch GET for exposed endpoints, timeouts
  // 2. Check for SSL/TLS issues
  // 3. Check subdomain for outdated services by common fingerprints (simulated)
  // 4. Check for exposed common paths (like /.git, /admin)

  // Basic setup
  const issues: string[] = [];
  const recommendations: Recommendation[] = [];

  let score = 100;

  // Check connectivity and fetch
  const httpsUrl = `https://${subdomain}/`;
  let fetchOk = false;
  let fetchStatus = 0;

  try {
    const res = await safeFetch(httpsUrl, {
      method: "GET",
      timeoutMs: 10000,
      signal,
      headers: { "User-Agent": "subdomain-exposure-rankings/1.0 apimesh.xyz" },
    });
    fetchOk = res.ok;
    fetchStatus = res.status;

    // Check headers for outdated server or tech using Server header
    const serverHeader = res.headers.get("server") || "";
    if (/apache|nginx|iis/i.test(serverHeader)) {
      // Simulate version extraction
      if (/2\./.test(serverHeader) || /1\.\d/.test(serverHeader)) {
        issues.push("Outdated server software detected");
        score -= 20;
      }
    }

    // Check for exposed endpoints
    const pathsToCheck = ["/.git/", "/admin", "/config", "/.env"];
    for (const path of pathsToCheck) {
      try {
        const resCheck = await safeFetch(`https://${subdomain}${path}`, {
          method: "HEAD",
          timeoutMs: 8000,
          signal,
          redirect: "manual",
        });
        if (resCheck.status >= 200 && resCheck.status < 400) {
          issues.push(`Exposed endpoint detected: ${path}`);
          score -= 25;
        }
      } catch {
        // ignore
      }
    }
  } catch {
    issues.push("Host unreachable or blocking requests");
    score -= 40;
  }

  // Check for open ports (simulate with DNS)
  // For demo: no real open port scan

  // Check TLS via fetch - simulate cert check
  // For demo, scoring lowered if hostname doesn't resolve on HTTPS or fetch ok false
  if (!fetchOk) {
    issues.push("No HTTPS service detected or unreachable");
    score -= 30;
  }

  // Normalize score minimum
  if (score < 0) score = 0;

  const grade = gradeFromScore(score);
  const recs = generateRecommendations(issues);

  // Compose final report
  return {
    name: subdomain,
    score,
    grade,
    issues,
    recommendations: recs,
    lastScanned: new Date().toISOString(),
  };
}

// Ranked grade from average scores
function calculateOverallScore(scores: number[]): { score: number; grade: Grade } {
  if (scores.length === 0) return { score: 0, grade: "F" };
  let s = scores.reduce((a, b) => a + b, 0) / scores.length;
  if (s < 0) s = 0;
  if (s > 100) s = 100;
  return { score: Math.round(s), grade: gradeFromScore(s) };
}

// Preview endpoint returns subset and simpler
export async function previewSubdomainExposureRankings(rawDomain: string): Promise<SubdomainExposureRankingsPreviewResult | { error: string }> {
  const domain = rawDomain.trim().toLowerCase();

  if (!domain.match(/^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,}$/)) {
    return { error: "Invalid domain format" };
  }

  const start = performance.now();

  const signal = AbortSignal.timeout(20000);

  try {
    // For preview, simulate simple enumeration by 5 common subdomains
    const commonSubs = ["www", "api", "mail", "admin", "dev"].map((s) => `${s}.${domain}`);

    // Analyze each in parallel with a small timeout
    const analyses = await Promise.all(
      commonSubs.map(async (subd) => {
        try {
          return await analyzeSubdomain(subd, signal);
        } catch {
          return {
            name: subd,
            score: 50,
            grade: "C" as Grade,
            issues: ["Analysis error"],
            recommendations: [],
          };
        }
      })
    );

    // Include domain itself
    const rootAnalysis = await analyzeSubdomain(domain, signal);

    const subdomains = [rootAnalysis, ...analyses];

    const summaryScores = subdomains.map((v) => v.score);
    const { score: summary_score, grade: summary_grade } = calculateOverallScore(summaryScores);

    const result: SubdomainExposureRankingsPreviewResult = {
      status: "ok",
      data: {
        domain,
        subdomains_found: subdomains.length,
        subdomains,
        summary_score,
        summary_grade,
        explanation: `Preview found ${subdomains.length} subdomains with basic exposure and configuration scoring.`,
      },
      meta: {
        timestamp: new Date().toISOString(),
        duration_ms: Math.round(performance.now() - start),
        api_version: "1.0.0",
      },
    };

    return result;
  } catch (e: any) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
}

// Full comprehensive enumeration and ranking
export async function fullSubdomainExposureRankings(rawDomain: string): Promise<SubdomainExposureRankingsFullResult | { error: string }> {
  const domain = rawDomain.trim().toLowerCase();

  if (!domain.match(/^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,}$/)) {
    return { error: "Invalid domain format" };
  }

  const start = performance.now();
  const signal = AbortSignal.timeout(30000);

  try {
    // Enumerate subdomains from multiple sources
    const subs = await enumerateSubdomains(domain, signal);

    // Analyze all enumerated subdomains in parallel
    const maxConcurrency = 10;
    const results: SubdomainReport[] = [];

    async function worker(subdomains: string[]) {
      for (const sub of subdomains) {
        if (signal.aborted) break;
        try {
          const res = await analyzeSubdomain(sub, signal);
          results.push(res);
        } catch {
          results.push({
            name: sub,
            score: 40,
            grade: "D",
            issues: ["Error analyzing subdomain"],
            recommendations: [],
          });
        }
      }
    }

    // Slice array into chunks for concurrency
    function chunkArray<T>(arr: T[], n: number): T[][] {
      const ret: T[][] = [];
      for (let i = 0; i < arr.length; i += n) {
        ret.push(arr.slice(i, i + n));
      }
      return ret;
    }

    const slices = chunkArray(subs, Math.ceil(subs.length / maxConcurrency));

    await Promise.all(slices.map((slice) => worker(slice)));

    // Calculate overall
    const scores = results.map((r) => r.score);
    const { score: overall_score, grade: overall_grade } = calculateOverallScore(scores);

    const explanation = `Comprehensive analysis enumerated ${subs.length} subdomains, analyzed ${results.length}. Overall security exposure score is ${overall_score} (${overall_grade}).`;

    return {
      domain,
      total_subdomains: subs.length,
      analyzed_subdomains: results.length,
      subdomains: results,
      overall_score,
      overall_grade,
      explanation,
      scannedAt: new Date().toISOString(),
    };
  } catch (e: any) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
}
