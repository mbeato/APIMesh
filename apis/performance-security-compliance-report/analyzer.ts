import { safeFetch, validateExternalUrl } from "../../shared/ssrf";

// -------------------------- TYPES --------------------------

export type LetterGrade = "A" | "B" | "C" | "D" | "F";

export interface PerformanceMetrics {
  firstContentfulPaint: number | null; // in ms
  largestContentfulPaint: number | null; // in ms
  cumulativeLayoutShift: number | null; // score
  totalBlockingTime: number | null; // in ms
  performanceScore: number; // 0-100
  grade: LetterGrade;
  details: string;
}

export interface SecurityHeaderAnalysis {
  header: string;
  present: boolean;
  value: string | null;
  score: number; // 0-100
  grade: LetterGrade;
  issues: string[];
}

export interface SslAnalysis {
  valid: boolean;
  expiryDays: number | null;
  signatureAlgorithm: string | null;
  strengthScore: number; // 0-100
  grade: LetterGrade;
  details: string;
}

export interface DnsAnalysis {
  resolvedIps: string[];
  cnameRecords: string[];
  dnsGrade: LetterGrade;
  issues: string[];
  recommendations: string[];
}

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface PerformanceReportResult {
  url: string;
  performance: PerformanceMetrics;
  securityHeaders: SecurityHeaderAnalysis[];
  sslInfo: SslAnalysis;
  dnsInfo: DnsAnalysis;
  overallScore: number; // 0-100
  grade: LetterGrade;
  recommendations: Recommendation[];
  checkedAt: string;
}

export interface PreviewReportResult {
  url: string;
  summaryScore: number; // 0-100
  grades: {
    performance: LetterGrade;
    securityHeaders: LetterGrade;
    ssl: LetterGrade;
    dns: LetterGrade;
  };
  issuesDetected: number;
  details: string;
  checkedAt: string;
}

// -------------------------- CONSTANTS --------------------------

const PERFORMANCE_GRADE_THRESHOLDS = [90, 75, 55, 40];
const SECURITY_GRADE_THRESHOLDS = [90, 75, 55, 40];
const SSL_GRADE_THRESHOLDS = [90, 75, 55, 40];
const DNS_GRADE_THRESHOLDS = [90, 75, 55, 40];

const SECURITY_HEADERS_TO_CHECK = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "x-xss-protection",
  "cross-origin-embedder-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
];

// -------------------------- UTILITIES --------------------------

function scoreToGrade(score: number): LetterGrade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 55) return "C";
  if (score >= 40) return "D";
  return "F";
}

function clampScore(score: number): number {
  if (score > 100) return 100;
  if (score < 0) return 0;
  return score;
}

function extractHeaderValue(headers: Headers, headerName: string): string | null {
  return headers.get(headerName) ?? null;
}

// -------------------------- PERFORMANCE --------------------------

// Simplified simulated performance metric gathering
// Since no puppeteer or lighthouse access, we do timing of main requests and CSP parsing for critical indicators

async function fetchPerformanceData(url: string): Promise<PerformanceMetrics> {
  try {
    const startTime = performance.now();
    const res = await safeFetch(url, { timeoutMs: 10000 });
    const duration = Math.round(performance.now() - startTime);

    const headers = res.headers;

    // Estimate performance based on request duration
    const fcp = duration * 0.7; // mock first contentful paint
    const lcp = duration * 0.9; // mock largest contentful paint
    const cls = 0.05; // mock
    const tbt = 80; // mock total blocking time

    // Calculate performance score from mock metrics
    let score = 100;
    // Penalize higher times
    if (fcp > 2000) score -= 25;
    if (lcp > 2500) score -= 20;
    if (cls > 0.1) score -= 20;
    if (tbt > 100) score -= 15;

    score = clampScore(score);
    const grade = scoreToGrade(score);

    return {
      firstContentfulPaint: Math.round(fcp),
      largestContentfulPaint: Math.round(lcp),
      cumulativeLayoutShift: cls,
      totalBlockingTime: tbt,
      performanceScore: score,
      grade,
      details: `Estimated FCP: ${Math.round(fcp)}ms, LCP: ${Math.round(lcp)}ms, CLS: ${cls}, TBT: ${tbt}ms`,
    };
  } catch (e) {
    return {
      firstContentfulPaint: null,
      largestContentfulPaint: null,
      cumulativeLayoutShift: null,
      totalBlockingTime: null,
      performanceScore: 0,
      grade: "F",
      details: `Failed to fetch performance data: ${(e instanceof Error) ? e.message : String(e)}`,
    };
  }
}

// -------------------------- SECURITY HEADER ANALYSIS --------------------------

// Adapted grading based on presence and quality of headers
// We reuse and simplify some ideas from security-headers api

function analyzeHeader(header: string, value: string | null): SecurityHeaderAnalysis {
  const hasValue = value !== null && value.trim() !== "";
  let score = 0;
  const issues: string[] = [];

  switch (header) {
    case "strict-transport-security":
      if (!hasValue) {
        issues.push("HSTS header missing");
        score = 0;
      } else {
        const valLower = value!.toLowerCase();
        const maxAgeMatch = valLower.match(/max-age=(\d+)/);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
        if (maxAge >= 31536000 && valLower.includes("includesubdomains")) {
          score = 100;
        } else if (maxAge >= 15768000) {
          score = 75;
          issues.push("HSTS max-age too low or missing includeSubDomains");
        } else {
          score = 40;
          issues.push("HSTS max-age very low or missing includeSubDomains");
        }
      }
      break;
    case "content-security-policy":
      if (!hasValue) {
        issues.push("Content-Security-Policy header missing");
        score = 0;
      } else {
        // Basic CSP validation
        const valLower = value!.toLowerCase();
        if (valLower.includes("'unsafe-inline'") || valLower.includes("'unsafe-eval'")) {
          score = 40;
          issues.push("CSP allows unsafe-inline or unsafe-eval");
        } else {
          score = 90;
        }
      }
      break;
    case "x-frame-options":
      if (!hasValue) {
        issues.push("X-Frame-Options header missing");
        score = 0;
      } else {
        const valUpper = value!.toUpperCase();
        if (valUpper === "DENY" || valUpper === "SAMEORIGIN") {
          score = 100;
        } else {
          score = 50;
          issues.push(`X-Frame-Options value unexpected: ${value}`);
        }
      }
      break;
    case "x-content-type-options":
      if (!hasValue) {
        issues.push("X-Content-Type-Options missing");
        score = 0;
      } else if (value!.toLowerCase() === "nosniff") {
        score = 100;
      } else {
        issues.push("X-Content-Type-Options expected 'nosniff'");
        score = 40;
      }
      break;
    case "referrer-policy":
      if (!hasValue) {
        issues.push("Referrer-Policy missing");
        score = 0;
      } else {
        const goodPolicies = new Set([
          "no-referrer",
          "same-origin",
          "strict-origin",
          "strict-origin-when-cross-origin",
          "no-referrer-when-downgrade",
        ]);
        if (goodPolicies.has(value!.toLowerCase())) {
          score = 90;
        } else {
          issues.push(`Referrer-Policy suboptimal: ${value}`);
          score = 50;
        }
      }
      break;
    case "permissions-policy":
      if (!hasValue) {
        issues.push("Permissions-Policy missing");
        score = 0;
      } else {
        // Simple heuristics: presence of restrictive features
        const val = value!.toLowerCase();
        const restricted = ["camera=()", "microphone=()", "geolocation=()"].filter(s => val.includes(s));
        if (restricted.length >= 3) {
          score = 100;
        } else if (restricted.length > 0) {
          score = 75;
          issues.push("Permissions-Policy only partly restrictive");
        } else {
          score = 30;
          issues.push("Permissions-Policy too permissive");
        }
      }
      break;
    case "x-xss-protection":
      if (!hasValue) {
        issues.push("X-XSS-Protection missing");
        score = 50; // deprecated but some protection
      } else if (value === "0") {
        score = 60; // disabled explicitly
      } else if (value && value.includes("1") && value.includes("mode=block")) {
        score = 90;
      } else {
        issues.push("X-XSS-Protection value suboptimal");
        score = 60;
      }
      break;
    case "cross-origin-embedder-policy":
      if (!hasValue) {
        issues.push("Cross-Origin-Embedder-Policy missing");
        score = 20;
      } else if (value!.toLowerCase() === "require-corp" || value!.toLowerCase() === "credentialless") {
        score = 90;
      } else {
        issues.push("Cross-Origin-Embedder-Policy suboptimal");
        score = 40;
      }
      break;
    case "cross-origin-opener-policy":
      if (!hasValue) {
        issues.push("Cross-Origin-Opener-Policy missing");
        score = 20;
      } else if (["same-origin", "same-origin-allow-popups"].includes(value!.toLowerCase())) {
        score = 85;
      } else {
        issues.push("Cross-Origin-Opener-Policy suboptimal");
        score = 40;
      }
      break;
    case "cross-origin-resource-policy":
      if (!hasValue) {
        issues.push("Cross-Origin-Resource-Policy missing");
        score = 20;
      } else if (["same-origin", "same-site"].includes(value!.toLowerCase())) {
        score = 90;
      } else if (value!.toLowerCase() === "cross-origin") {
        issues.push("Cross-Origin-Resource-Policy allows cross-origin embedding");
        score = 50;
      } else {
        issues.push("Cross-Origin-Resource-Policy suboptimal");
        score = 40;
      }
      break;
    default:
      score = 50;
  }

  score = clampScore(score);
  const grade = scoreToGrade(score);
  return {
    header,
    present: hasValue,
    value,
    score,
    grade,
    issues,
  };
}

async function analyzeSecurityHeaders(url: string): Promise<SecurityHeaderAnalysis[]> {
  try {
    const res = await safeFetch(url, { timeoutMs: 10000 });
    const headers = res.headers;
    const analyses: SecurityHeaderAnalysis[] = [];

    for (const header of SECURITY_HEADERS_TO_CHECK) {
      const val = extractHeaderValue(headers, header);
      analyses.push(analyzeHeader(header, val));
    }

    return analyses;
  } catch (e) {
    // Return all missing with error details
    const msg = (e instanceof Error) ? e.message : String(e);
    return SECURITY_HEADERS_TO_CHECK.map(hdr => ({
      header: hdr,
      present: false,
      value: null,
      score: 0,
      grade: "F",
      issues: [`Fetch error: ${msg}`],
    }));
  }
}

// -------------------------- SSL ANALYSIS --------------------------

async function fetchSslInfo(hostname: string): Promise<SslAnalysis> {
  try {
    // We perform a fetch HEAD to https://hostname to test availability
    const url = `https://${hostname}`;
    const res = await safeFetch(url, { method: "HEAD", timeoutMs: 8000 });

    if (!res.ok) {
      return {
        valid: false,
        expiryDays: null,
        signatureAlgorithm: null,
        strengthScore: 0,
        grade: "F",
        details: `HTTP status ${res.status} when connecting to HTTPS site`,
      };
    }

    // Use crt.sh public API to get cert info
    const crtShUrl = `https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`;
    const crtRes = await safeFetch(crtShUrl, { timeoutMs: 10000 });

    if (!crtRes.ok) {
      return {
        valid: false,
        expiryDays: null,
        signatureAlgorithm: null,
        strengthScore: 0,
        grade: "F",
        details: `crt.sh API status ${crtRes.status}`,
      };
    }

    const body = await crtRes.text();

    if (body === "[]" || body.trim() === "") {
      return {
        valid: false,
        expiryDays: null,
        signatureAlgorithm: null,
        strengthScore: 0,
        grade: "F",
        details: "No certificate data found on crt.sh",
      };
    }

    const certs = JSON.parse(body);
    if (!Array.isArray(certs) || certs.length === 0) {
      return {
        valid: false,
        expiryDays: null,
        signatureAlgorithm: null,
        strengthScore: 0,
        grade: "F",
        details: "No certificates returned from crt.sh",
      };
    }

    // Use the most recent certificate
    const cert = certs[certs.length - 1];

    const validFrom = cert.not_before ? new Date(cert.not_before) : null;
    const validTo = cert.not_after ? new Date(cert.not_after) : null;
    const now = new Date();

    let expiryDays: number | null = null;
    if (validTo !== null) {
      expiryDays = Math.round((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
      if (expiryDays < 0) expiryDays = 0;
    }

    let strengthScore = 70;
    if (expiryDays !== null) {
      if (expiryDays > 60) strengthScore += 20;
      if (expiryDays <= 30) strengthScore -= 30;
    }

    const sigAlgoRaw = cert.sig_alg || cert.signature_algorithm_name || "";
    const sigAlgo = typeof sigAlgoRaw === "string" ? sigAlgoRaw : "";
    if (sigAlgo.toLowerCase().includes("md5") || sigAlgo.toLowerCase().includes("sha1")) {
      strengthScore -= 50;
    } else {
      strengthScore += 10;
    }

    strengthScore = clampScore(strengthScore);

    const valid = validFrom !== null && validTo !== null && now >= validFrom && now <= validTo;
    const grade = scoreToGrade(strengthScore);

    return {
      valid,
      expiryDays,
      signatureAlgorithm: sigAlgo,
      strengthScore,
      grade,
      details: `Certificate valid: ${valid}, expires in ${expiryDays} days, signature algorithm: ${sigAlgo}`,
    };
  } catch (e) {
    return {
      valid: false,
      expiryDays: null,
      signatureAlgorithm: null,
      strengthScore: 0,
      grade: "F",
      details: `Error fetching SSL info: ${(e instanceof Error) ? e.message : String(e)}`,
    };
  }
}

// -------------------------- DNS ANALYSIS --------------------------

async function fetchDnsInfo(hostname: string): Promise<DnsAnalysis> {
  try {
    // Fetch A and AAAA records + CNAME records from DNS resolver API
    // Use Google's DNS over HTTPS API
    const dnsA = fetch(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`, { signal: AbortSignal.timeout(10000) });
    const dnsAAAA = fetch(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=AAAA`, { signal: AbortSignal.timeout(10000) });
    const dnsCNAME = fetch(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=CNAME`, { signal: AbortSignal.timeout(10000) });

    const [resA, resAAAA, resCNAME] = await Promise.all([dnsA, dnsAAAA, dnsCNAME]);

    if (!resA.ok || !resAAAA.ok || !resCNAME.ok) {
      return {
        resolvedIps: [],
        cnameRecords: [],
        dnsGrade: "F",
        issues: [
          `DNS queries failed: A(${resA.status}), AAAA(${resAAAA.status}), CNAME(${resCNAME.status})`,
        ],
        recommendations: ["Validate DNS configuration and ensure DNS servers respond correctly."],
      };
    }

    const dataA = await resA.json();
    const dataAAAA = await resAAAA.json();
    const dataCNAME = await resCNAME.json();

    // Parse IP addresses
    const ipsA = dataA.Answer?.filter((a: any) => a.type === 1).map((a: any) => a.data) ?? [];
    const ipsAAAA = dataAAAA.Answer?.filter((a: any) => a.type === 28).map((a: any) => a.data) ?? [];
    const cnames = dataCNAME.Answer?.filter((a: any) => a.type === 5).map((a: any) => a.data) ?? [];

    const allIps = [...ipsA, ...ipsAAAA];

    // Simple analysis
    const issues: string[] = [];
    const recommendations: string[] = [];

    if (allIps.length === 0) {
      issues.push("No A or AAAA DNS records found.");
      recommendations.push("Add A or AAAA DNS records pointing to the correct origin IP addresses.");
    }

    if (cnames.length > 1) {
      issues.push("Multiple CNAME records found; could cause inconsistent DNS resolution.");
      recommendations.push("Simplify CNAME records to a single canonical name.");
    }

    // Calculate grade based on presence and diversity
    let dnsScore = 80;

    if (allIps.length === 0) dnsScore = 0;
    else if (allIps.length < 2) dnsScore = 55;
    else dnsScore = 90;

    dnsScore = clampScore(dnsScore);
    const dnsGrade = scoreToGrade(dnsScore);

    return {
      resolvedIps: allIps,
      cnameRecords: cnames,
      dnsGrade,
      issues,
      recommendations,
    };
  } catch (e) {
    return {
      resolvedIps: [],
      cnameRecords: [],
      dnsGrade: "F",
      issues: [`DNS fetch error: ${(e instanceof Error) ? e.message : String(e)}`],
      recommendations: ["Check DNS configuration and resolver accessibility."],
    };
  }
}

// -------------------------- SCORE AGGREGATION --------------------------

function aggregateScores(
  performance: PerformanceMetrics,
  headers: SecurityHeaderAnalysis[],
  ssl: SslAnalysis,
  dns: DnsAnalysis
): { overallScore: number; grade: LetterGrade } {
  // Weighting the four sections
  const weightPerformance = 0.30;
  const weightHeaders = 0.30;
  const weightSsl = 0.20;
  const weightDns = 0.20;

  const avgHeaderScore = headers.reduce((acc, h) => acc + h.score, 0) / headers.length;

  let overall =
    performance.performanceScore * weightPerformance +
    avgHeaderScore * weightHeaders +
    ssl.strengthScore * weightSsl +
    (dns.dnsGrade === "F" ? 0 : dns.dnsGrade === "A" ? 100 : 75) * weightDns;

  overall = clampScore(overall);
  const grade = scoreToGrade(overall);

  return { overallScore: Math.round(overall), grade };
}

// -------------------------- RECOMMENDATION GENERATION --------------------------

function generateRecommendations(
  performance: PerformanceMetrics,
  headers: SecurityHeaderAnalysis[],
  ssl: SslAnalysis,
  dns: DnsAnalysis,
  overallScore: number,
  grade: LetterGrade
): Recommendation[] {
  const recs: Recommendation[] = [];

  // Performance related
  if (performance.performanceScore < 75) {
    recs.push({
      issue: "Performance score below optimal",
      severity: 70,
      suggestion:
        "Optimize server response times, use caching and minimize render-blocking resources.",
    });
  }

  // Security headers
  headers.forEach((hdr) => {
    if (hdr.grade === "F" || hdr.grade === "D" || hdr.grade === "C") {
      hdr.issues.forEach((issue) => {
        recs.push({
          issue: `${hdr.header.toUpperCase()} issue`,
          severity: hdr.score < 40 ? 80 : 50,
          suggestion: `Fix security header: ${issue}`,
        });
      });
    }
  });

  // SSL
  if (!ssl.valid) {
    recs.push({
      issue: "Invalid or missing SSL certificate",
      severity: 90,
      suggestion: "Obtain and correctly configure a valid SSL certificate for HTTPS.",
    });
  } else {
    if (ssl.expiryDays !== null && ssl.expiryDays < 30) {
      recs.push({
        issue: "SSL certificate expiring soon",
        severity: 60,
        suggestion: "Renew SSL certificate before expiry.",
      });
    }
    if (ssl.strengthScore < 70) {
      recs.push({
        issue: "Weak SSL signature algorithm or short validity",
        severity: 70,
        suggestion: "Use strong signature algorithms and longer validity period.",
      });
    }
  }

  // DNS
  dns.issues.forEach((issue) => {
    recs.push({ issue: issue, severity: 60, suggestion: "Review DNS configuration per issue." });
  });
  dns.recommendations.forEach((sug) => {
    recs.push({ issue: "DNS recommendation", severity: 40, suggestion: sug });
  });

  // If no issues, add no issues recommendation
  if (recs.length === 0) {
    recs.push({ issue: "No significant issues detected", severity: 10, suggestion: "Maintain current configuration and follow latest best practices." });
  }

  return recs;
}

// -------------------------- PUBLIC API --------------------------

/**
 * Performs a comprehensive combined audit for the target URL.
 * @param rawUrl user-provided url string
 * @returns PerformanceReportResult or { error: string }
 */
export async function fullReport(rawUrl: string): Promise<PerformanceReportResult | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: check.error };

  try {
    const urlObj = new URL(check.url.toString());
    // Run all analysis concurrently
    const [performance, securityHeaders, sslInfo, dnsInfo] = await Promise.all([
      fetchPerformanceData(check.url.toString()),
      analyzeSecurityHeaders(check.url.toString()),
      fetchSslInfo(urlObj.hostname),
      fetchDnsInfo(urlObj.hostname),
    ]);

    // Aggregate score
    const { overallScore, grade } = aggregateScores(performance, securityHeaders, sslInfo, dnsInfo);

    const recommendations = generateRecommendations(performance, securityHeaders, sslInfo, dnsInfo, overallScore, grade);

    return {
      url: check.url.toString(),
      performance,
      securityHeaders,
      sslInfo,
      dnsInfo,
      overallScore,
      grade,
      recommendations,
      checkedAt: new Date().toISOString(),
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Failed to generate report: ${msg}` };
  }
}

/**
 * Generates a fast preview report combining summary scores and issues count.
 * @param rawUrl user-provided URL string
 * @returns PreviewReportResult or { error: string }
 */
export async function previewReport(rawUrl: string): Promise<PreviewReportResult | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: check.error };

  try {
    const urlObj = new URL(check.url.toString());

    // Fetch performance and security headers summary concurrently
    const [performance, securityHeaders, sslInfo, dnsInfo] = await Promise.all([
      fetchPerformanceData(check.url.toString()),
      analyzeSecurityHeaders(check.url.toString()),
      fetchSslInfo(urlObj.hostname),
      fetchDnsInfo(urlObj.hostname),
    ]);

    // Basic summaries
    const perfGrade = performance.grade;
    // Average security headers grade
    const avgHeaderScore = securityHeaders.reduce((acc, h) => acc + h.score, 0) / securityHeaders.length;
    const secGrade = scoreToGrade(avgHeaderScore);
    const sslGrade = sslInfo.grade;
    const dnsGrade = dnsInfo.dnsGrade;

    // Count issues
    const issuesDetected =
      securityHeaders.reduce((acc, h) => acc + h.issues.length, 0) +
      (sslInfo.grade === "F" ? 1 : 0) +
      dnsInfo.issues.length;

    // Summary score weighted average
    const summaryScore = Math.round(
      performance.performanceScore * 0.3 +
      avgHeaderScore * 0.3 +
      sslInfo.strengthScore * 0.2 +
      (dnsGrade === "F" ? 0 : dnsGrade === "A" ? 100 : 75) * 0.2
    );

    return {
      url: check.url.toString(),
      summaryScore: clampScore(summaryScore),
      grades: {
        performance: perfGrade,
        securityHeaders: secGrade,
        ssl: sslGrade,
        dns: dnsGrade,
      },
      issuesDetected,
      details: `Summary preview checks performance, security headers, SSL, and DNS. Pay for full report with detailed graded analysis and prioritized recommendations.`,
      checkedAt: new Date().toISOString(),
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Failed to generate preview: ${msg}` };
  }
}
