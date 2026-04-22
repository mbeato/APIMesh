import {
  validateExternalUrl,
  safeFetch,
} from "../../shared/ssrf";

// ****************** TYPES *******************
export interface Recommendation {
  issue: string;
  severity: number; // 1=low, 2=medium, 3=high
  suggestion: string;
}

export interface SSLInfo {
  valid: boolean;
  issuer: string;
  expiryDays: number | null;
  signatureAlgorithm: string;
  score: number; // 0-100
  error?: string;
}

export interface DNSRecords {
  aRecords: string[];
  cnameRecords: string[];
  nsRecords: string[];
  mxRecords: string[];
  spfRecord: string | null;
  score: number; // 0-100
  error?: string;
}

export interface RedirectChain {
  redirects: string[];
  score: number; // 0-100
  error?: string;
}

export interface SecurityHeaders {
  strictTransportSecurity: string | null;
  xFrameOptions: string | null;
  contentSecurityPolicy: string | null;
  xContentTypeOptions: string | null;
  referrerPolicy: string | null;
  permissionsPolicy: string | null;
  // aggregate score
  overallScore: number; // 0-100
  error?: string;
}

export interface AssessmentResult {
  url: string;
  sslCertificate: SSLInfo;
  dnsRecords: DNSRecords;
  redirectChain: RedirectChain;
  securityHeaders: SecurityHeaders;
  overallScore: number; // 0-100
  grade: string; // A-F
  recommendations: Recommendation[];
  checkedAt: string; // ISO8601
}

export interface PreviewResult {
  url: string;
  sslValid: boolean;
  dnsARecordCount: number;
  minimalHeadersPresent: boolean;
  overallScore: number; // 0-100
  grade: string; // A-F
  recommendations: Recommendation[];
  checkedAt: string;
}

// ****************** HELPERS *******************

// Compute letter grade from score
function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 55) return "D";
  return "F";
}

// Clamp 0-100
function clampScore(n: number): number {
  if (n < 0) return 0;
  if (n > 100) return 100;
  return n;
}

// Fetch SSL Certificate info by calling crt.sh JSON API and check cert validity window
async function fetchSslCertificateInfo(hostname: string): Promise<SSLInfo> {
  try {
    // Use crt.sh API to fetch cert info
    const crtRes = await safeFetch(`https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`, {
      timeoutMs: 10000,
    });
    if (!crtRes.ok) {
      return {
        valid: false,
        issuer: "",
        expiryDays: null,
        signatureAlgorithm: "",
        score: 0,
        error: `crt.sh HTTP status ${crtRes.status}`,
      };
    }
    const textBody = await crtRes.text();
    if (!textBody || textBody === "[]") {
      return {
        valid: false,
        issuer: "",
        expiryDays: null,
        signatureAlgorithm: "",
        score: 0,
        error: "No certificate data found",
      };
    }
    const certs = JSON.parse(textBody);
    if (!Array.isArray(certs) || certs.length === 0) {
      return {
        valid: false,
        issuer: "",
        expiryDays: null,
        signatureAlgorithm: "",
        score: 0,
        error: "No certificate data found",
      };
    }
    // Use latest cert
    const cert = certs[certs.length - 1];
    const validFrom = new Date(cert.not_before);
    const validTo = new Date(cert.not_after);
    const now = new Date();
    const expiryDays = validTo > now ? Math.round((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)) : 0;
    const signatureAlgorithm = cert.sig_alg || cert.signature_algorithm_name || "";
    const valid = now >= validFrom && now <= validTo;

    let score = 70;
    if (expiryDays > 60) score += 20;
    else if (expiryDays <= 30) score -= 30;
    if (signatureAlgorithm.toLowerCase().includes("md5") || signatureAlgorithm.toLowerCase().includes("sha1")) {
      score -= 50;
    } else {
      score += 10;
    }

    score = clampScore(score);

    return {
      valid,
      issuer: cert.issuer_name || "",
      expiryDays,
      signatureAlgorithm,
      score,
    };
  } catch (e: unknown) {
    return {
      valid: false,
      issuer: "",
      expiryDays: null,
      signatureAlgorithm: "",
      score: 0,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

// Fetch DNS records using public DNS over HTTPS from Google
async function fetchDnsRecords(hostname: string): Promise<DNSRecords> {
  const base = "https://dns.google/resolve";
  try {
    const [aRes, cnameRes, nsRes, mxRes, txtRes] = await Promise.all([
      safeFetch(`${base}?name=${encodeURIComponent(hostname)}&type=A`, { timeoutMs: 10000 }),
      safeFetch(`${base}?name=${encodeURIComponent(hostname)}&type=CNAME`, { timeoutMs: 10000 }),
      safeFetch(`${base}?name=${encodeURIComponent(hostname)}&type=NS`, { timeoutMs: 10000 }),
      safeFetch(`${base}?name=${encodeURIComponent(hostname)}&type=MX`, { timeoutMs: 10000 }),
      safeFetch(`${base}?name=${encodeURIComponent(hostname)}&type=TXT`, { timeoutMs: 10000 }),
    ]);

    // Helper to parse answers array
    async function parseAnswers(res: Response): Promise<string[]> {
      if (!res.ok) {
        return [];
      }
      const data = await res.json();
      if (!data.Answer || !Array.isArray(data.Answer)) return [];
      return data.Answer.map((a: any) => String(a.data).replace(/"/g, ""));
    }

    const [aRecords, cnameRecords, nsRecords, mxRecords, txtRecords] = await Promise.all([
      parseAnswers(aRes),
      parseAnswers(cnameRes),
      parseAnswers(nsRes),
      parseAnswers(mxRes),
      parseAnswers(txtRes),
    ]);

    // Identify SPF record inside TXT
    const spfRecord = txtRecords.find((txt) => txt.toLowerCase().startsWith("v=spf")) || null;

    // Simple scoring
    let score = 60;
    if (aRecords.length > 0) score += 15;
    if (nsRecords.length > 0) score += 10;
    if (mxRecords.length > 0) score += 10;
    if (spfRecord) score += 5;
    if (cnameRecords.length > 0) score -= 3; // cname on apex maybe less desirable

    score = clampScore(score);

    return {
      aRecords,
      cnameRecords,
      nsRecords,
      mxRecords,
      spfRecord,
      score,
    };
  } catch (e: unknown) {
    return {
      aRecords: [],
      cnameRecords: [],
      nsRecords: [],
      mxRecords: [],
      spfRecord: null,
      score: 0,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

// Fetch redirect chain (max 10 redirects) for given URL
async function fetchRedirectChain(url: string): Promise<RedirectChain> {
  const redirects: string[] = [];
  let currentUrl = url;
  try {
    for (let i = 0; i < 10; i++) {
      const res = await safeFetch(currentUrl, {
        method: "HEAD",
        redirect: "manual",
        timeoutMs: 8000,
      });
      redirects.push(currentUrl);
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get("location");
        if (!loc) break;
        let nextUrl = loc;
        try {
          const resolved = new URL(loc, currentUrl);
          nextUrl = resolved.toString();
        } catch {}
        if (redirects.includes(nextUrl)) break; // loop
        currentUrl = nextUrl;
      } else {
        break; // no more redirects
      }
    }

    // Score: good if <= 2 redirects and all HTTPS
    let score = 80;
    if (redirects.length > 4) score -= 40;
    else if (redirects.length > 2) score -= 20;
    if (redirects.some((r) => !r.toLowerCase().startsWith("https://"))) score -= 20;
    score = clampScore(score);

    return {
      redirects,
      score,
    };
  } catch (e: unknown) {
    return {
      redirects,
      score: 0,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

// Fetch security headers and analyze their presence/scores
async function fetchSecurityHeaders(url: string): Promise<SecurityHeaders> {
  try {
    // Fetch with GET request
    const res = await safeFetch(url, { timeoutMs: 10000 });
    const h = res.headers;

    const sts = h.get("strict-transport-security");
    const xfo = h.get("x-frame-options");
    const csp = h.get("content-security-policy");
    const xcto = h.get("x-content-type-options");
    const rp = h.get("referrer-policy");
    const pp = h.get("permissions-policy");

    // Scoring
    let score = 80;

    if (!sts) score -= 25;
    if (!xfo) score -= 15;
    if (!csp) score -= 20;
    if (!xcto) score -= 10;
    if (!rp) score -= 5;
    if (!pp) score -= 5;

    score = clampScore(score);

    return {
      strictTransportSecurity: sts,
      xFrameOptions: xfo,
      contentSecurityPolicy: csp,
      xContentTypeOptions: xcto,
      referrerPolicy: rp,
      permissionsPolicy: pp,
      overallScore: score,
    };
  } catch (e: unknown) {
    return {
      strictTransportSecurity: null,
      xFrameOptions: null,
      contentSecurityPolicy: null,
      xContentTypeOptions: null,
      referrerPolicy: null,
      permissionsPolicy: null,
      overallScore: 0,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

// Generate recommendations from analyses
function generateRecommendations(ssl: SSLInfo, dns: DNSRecords, redirects: RedirectChain, headers: SecurityHeaders): Recommendation[] {
  const recs: Recommendation[] = [];

  if (!ssl.valid) {
    recs.push({ issue: "SSL certificate invalid", severity: 3, suggestion: "Obtain a valid, trusted SSL certificate with proper expiry." });
  } else {
    if (ssl.expiryDays !== null && ssl.expiryDays < 30) {
      recs.push({
        issue: `SSL cert expiring soon in ${ssl.expiryDays} days`,
        severity: 2,
        suggestion: "Renew SSL certificate before expiration to avoid service disruption.",
      });
    }
    if (ssl.signatureAlgorithm.toLowerCase().includes("md5") || ssl.signatureAlgorithm.toLowerCase().includes("sha1")) {
      recs.push({
        issue: "Weak SSL signature algorithm",
        severity: 3,
        suggestion: "Upgrade to a stronger signature algorithm (SHA-256 or better).",
      });
    }
  }

  if (dns.aRecords.length === 0) {
    recs.push({ issue: "No A records found", severity: 3, suggestion: "Ensure DNS A records exist and resolve correctly." });
  }
  if (!dns.spfRecord) {
    recs.push({ issue: "Missing SPF record", severity: 1, suggestion: "Add an SPF DNS TXT record to reduce email spoofing risks." });
  }
  if (dns.nsRecords.length === 0) {
    recs.push({ issue: "No NS records found", severity: 3, suggestion: "Configure authoritative NS records for reliable DNS resolution." });
  }

  if (redirects.redirects.length > 5) {
    recs.push({
      issue: "Excessive redirects",
      severity: 2,
      suggestion: "Reduce redirect chain length to improve load times and security.",
    });
  }
  if (redirects.redirects.some((r) => !r.toLowerCase().startsWith("https://"))) {
    recs.push({
      issue: "Redirects to non-HTTPS URLs",
      severity: 3,
      suggestion: "Use HTTPS URLs in redirect chain for encrypted transport.",
    });
  }

  // Security headers
  if (!headers.strictTransportSecurity) {
    recs.push({
      issue: "Missing Strict-Transport-Security header",
      severity: 3,
      suggestion: "Add HSTS header to enforce HTTPS connections.",
    });
  }
  if (!headers.contentSecurityPolicy) {
    recs.push({
      issue: "Missing Content-Security-Policy header",
      severity: 3,
      suggestion: "Implement a CSP header to reduce XSS and data injection risks.",
    });
  }
  if (!headers.xFrameOptions) {
    recs.push({
      issue: "Missing X-Frame-Options header",
      severity: 2,
      suggestion: "Add X-Frame-Options to prevent clickjacking.",
    });
  }
  if (!headers.xContentTypeOptions) {
    recs.push({
      issue: "Missing X-Content-Type-Options header",
      severity: 2,
      suggestion: "Add X-Content-Type-Options: nosniff to prevent MIME sniffing.",
    });
  }

  if (recs.length === 0) {
    recs.push({ issue: "No significant issues detected", severity: 0, suggestion: "Maintain current configurations and monitor regularly." });
  }

  return recs;
}

// Compute overall score from individual scores
function computeOverallScore(ssl: SSLInfo, dns: DNSRecords, redirects: RedirectChain, headers: SecurityHeaders): number {
  // Weighted average
  const weights = {
    ssl: 0.35,
    dns: 0.25,
    redirects: 0.15,
    headers: 0.25,
  };
  const score =
    (ssl.score || 0) * weights.ssl +
    (dns.score || 0) * weights.dns +
    (redirects.score || 0) * weights.redirects +
    (headers.overallScore || 0) * weights.headers;
  return Math.round(clampScore(score));
}

// ****************** PUBLIC API *******************

// Comprehensive assessment
export async function performFullAssessment(rawUrl: string): Promise<AssessmentResult> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) {
    throw new Error(check.error);
  }
  const url = check.url.toString();

  // Parse hostname
  let hostname: string;
  try {
    const u = new URL(url);
    hostname = u.hostname;
  } catch {
    throw new Error("Malformed URL");
  }

  // Run all analyses parallel where possible
  // SSL info, DNS records, Redirect chain, Security headers
  try {
    const [sslInfo, dnsRecords, redirectChain, securityHeaders] = await Promise.all([
      fetchSslCertificateInfo(hostname),
      fetchDnsRecords(hostname),
      fetchRedirectChain(url),
      fetchSecurityHeaders(url),
    ]);

    const overallScore = computeOverallScore(sslInfo, dnsRecords, redirectChain, securityHeaders);
    const grade = scoreToGrade(overallScore);
    const recommendations = generateRecommendations(sslInfo, dnsRecords, redirectChain, securityHeaders);

    return {
      url,
      sslCertificate: sslInfo,
      dnsRecords: dnsRecords,
      redirectChain: redirectChain,
      securityHeaders: securityHeaders,
      overallScore,
      grade,
      recommendations,
      checkedAt: new Date().toISOString(),
    };
  } catch (e: unknown) {
    throw e instanceof Error ? e : new Error(String(e));
  }
}

// Preview assessment - cheap and free, no payment
export async function performPreviewAssessment(rawUrl: string): Promise<PreviewResult> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) {
    throw new Error(check.error);
  }
  const url = check.url.toString();

  // Parse hostname
  let hostname: string;
  try {
    const u = new URL(url);
    hostname = u.hostname;
  } catch {
    throw new Error("Malformed URL");
  }

  const start = performance.now();
  try {
    // We do minimal analysis:
    // - SSL validity
    // - DNS A record count
    // - minimal headers presence (HSTS + XFO + X-Content-Type-Options)

    const [sslInfo, dnsRecords] = await Promise.all([
      fetchSslCertificateInfo(hostname),
      fetchDnsRecords(hostname),
    ]);

    // Fetch HEAD headers
    let minimalHeadersPresent = false;
    try {
      const res = await safeFetch(url, { method: "HEAD", timeoutMs: 15000 });
      const h = res.headers;
      minimalHeadersPresent = [
        h.has("strict-transport-security"),
        h.has("x-frame-options"),
        h.has("x-content-type-options"),
      ].filter(Boolean).length >= 2;
    } catch {}

    const sslValid = sslInfo.valid;
    const dnsARecordCount = dnsRecords.aRecords.length;

    // Compute simplified score
    let score = 50;
    if (sslValid) score += 30;
    if (dnsARecordCount > 0) score += 10;
    if (minimalHeadersPresent) score += 10;

    score = clampScore(score);
    const grade = scoreToGrade(score);

    const recommendations: Recommendation[] = [];
    if (!sslValid) {
      recommendations.push({ issue: "SSL invalid or missing", severity: 3, suggestion: "Use valid SSL certificate to secure traffic." });
    }
    if (dnsARecordCount === 0) {
      recommendations.push({ issue: "Missing A records", severity: 3, suggestion: "Configure DNS A records to resolve hostname." });
    }
    if (!minimalHeadersPresent) {
      recommendations.push({ issue: "Missing critical security headers", severity: 2, suggestion: "Add HSTS, X-Frame-Options, and X-Content-Type-Options headers." });
    }

    if (recommendations.length === 0) {
      recommendations.push({ issue: "No significant issues detected in preview", severity: 0, suggestion: "Consider full assessment for detailed analysis and scoring." });
    }

    return {
      url,
      sslValid,
      dnsARecordCount,
      minimalHeadersPresent,
      overallScore: score,
      grade,
      recommendations,
      checkedAt: new Date().toISOString(),
    };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(msg);
  }
}
