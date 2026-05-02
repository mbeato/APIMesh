import {
  safeFetch,
  validateExternalUrl,
  readBodyCapped
} from "../../shared/ssrf";

// ------------- Types -------------

export interface DNSRecords {
  a: string[] | null;
  ns: string[] | null;
  cname: string | null;
  mx: string[] | null;
}

export interface HttpsCertificate {
  valid: boolean;
  subject: string;
  issuer: string;
  validFrom: string | null;
  validTo: string | null;
  expiryDays: number | null;
  signatureAlgorithm?: string;
  strengthScore: number; // 0-100
  error?: string;
}

export interface SecurityHeadersAnalysis {
  present: string[];
  missing: string[];
  deprecated: string[];
}

export interface Recommendation {
  issue: string;
  severity: "low" | "medium" | "high";
  suggestion: string;
}

export interface SubdomainSecurityAuditResult {
  url: string;
  dnsRecords: DNSRecords;
  httpsCertificate: HttpsCertificate;
  securityHeaders: SecurityHeadersAnalysis;
  overallScore: number;
  grade: string; // A-F letter grade
  recommendations: Recommendation[];
  explanation: string;
}

export interface SubdomainSecurityPreviewResult {
  url: string;
  dnsResolved: boolean;
  httpsAvailable: boolean;
  issues: string[];
  scannedAt: string;
}

// ------------- Constants -------------

const DNS_OVER_HTTPS = "https://dns.google/resolve";

const SECURITY_HEADERS = [
  "Strict-Transport-Security",
  "Content-Security-Policy",
  "X-Frame-Options",
  "X-Content-Type-Options",
  "Referrer-Policy",
  "Permissions-Policy",
  "X-XSS-Protection",
  "Cross-Origin-Embedder-Policy",
  "Cross-Origin-Opener-Policy",
  "Cross-Origin-Resource-Policy",
];

const DEPRECATED_HEADERS = [
  // Hypothetical deprecated headers for example
  "Feature-Policy",
  "X-Powered-By"
];

// Letters grades thresholds
function gradeFromScore(score: number): string {
  if (score >= 90) return "A";
  else if (score >= 80) return "B";
  else if (score >= 70) return "C";
  else if (score >= 60) return "D";
  else if (score >= 40) return "E";
  return "F";
}

// ------------- Helper functions -------------

/**
 * Fetch DNS records using DNS-over-HTTPS from Google DNS.
 * Returns null properties on error.
 */
async function fetchDnsRecords(hostname: string): Promise<DNSRecords> {
  const records: DNSRecords = {
    a: null,
    ns: null,
    cname: null,
    mx: null
  };

  try {
    // A records
    const aRes = await safeFetch(`${DNS_OVER_HTTPS}?name=${encodeURIComponent(hostname)}&type=A`, { timeoutMs: 10000 });
    if (!aRes.ok) throw new Error(`DNS A query failed status ${aRes.status}`);
    const aData = await aRes.json();
    records.a = aData.Answer?.filter((a: any) => a.type === 1).map((a: any) => a.data) ?? null;

    // NS records
    const nsRes = await safeFetch(`${DNS_OVER_HTTPS}?name=${encodeURIComponent(hostname)}&type=NS`, { timeoutMs: 10000 });
    if (nsRes.ok) {
      const nsData = await nsRes.json();
      records.ns = nsData.Answer?.filter((r: any) => r.type === 2).map((r: any) => r.data) ?? null;
    }

    // CNAME
    const cnameRes = await safeFetch(`${DNS_OVER_HTTPS}?name=${encodeURIComponent(hostname)}&type=CNAME`, { timeoutMs: 10000 });
    if (cnameRes.ok) {
      const cnameData = await cnameRes.json();
      const cnameRecord = cnameData.Answer?.find((r: any) => r.type === 5);
      records.cname = cnameRecord ? cnameRecord.data : null;
    }

    // MX
    const mxRes = await safeFetch(`${DNS_OVER_HTTPS}?name=${encodeURIComponent(hostname)}&type=MX`, { timeoutMs: 10000 });
    if (mxRes.ok) {
      const mxData = await mxRes.json();
      records.mx = mxData.Answer?.filter((r: any) => r.type === 15).map((r: any) => r.data) ?? null;
    }
  } catch (e) {
    // On errors, leave nulls
    // We do not throw because DNS incomplete info can occur
  }

  return records;
}

/**
 * Fetch HTTPS certificate info using crt.sh JSON API.
 * Returns null on failure.
 */
async function fetchHttpsCertificate(hostname: string): Promise<HttpsCertificate> {
  try {
    // Preliminary check to ensure HTTPS is reachable
    const httpsUrl = `https://${hostname}`;
    const headRes = await safeFetch(httpsUrl, { method: "HEAD", timeoutMs: 8000 });
    if (!headRes.ok && headRes.status !== 301 && headRes.status !== 302) {
      return {
        valid: false,
        subject: "",
        issuer: "",
        validFrom: null,
        validTo: null,
        expiryDays: null,
        signatureAlgorithm: undefined,
        strengthScore: 0,
        error: `HTTPS unreachable, status ${headRes.status}`
      };
    }

    // Fetch certificates from crt.sh
    const crtUrl = `https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`;
    const crtRes = await safeFetch(crtUrl, { timeoutMs: 10000 });
    if (!crtRes.ok) {
      return {
        valid: false,
        subject: "",
        issuer: "",
        validFrom: null,
        validTo: null,
        expiryDays: null,
        signatureAlgorithm: undefined,
        strengthScore: 0,
        error: `crt.sh fetch failed with status ${crtRes.status}`
      };
    }

    const body = await crtRes.text();
    if (!body || body === "[]") {
      return {
        valid: false,
        subject: "",
        issuer: "",
        validFrom: null,
        validTo: null,
        expiryDays: null,
        signatureAlgorithm: undefined,
        strengthScore: 0,
        error: "No certificates found at crt.sh"
      };
    }

    const certs = JSON.parse(body);
    if (!Array.isArray(certs) || certs.length === 0) {
      return {
        valid: false,
        subject: "",
        issuer: "",
        validFrom: null,
        validTo: null,
        expiryDays: null,
        signatureAlgorithm: undefined,
        strengthScore: 0,
        error: "No certificate data found"
      };
    }

    // Use latest certificate
    const cert = certs[certs.length - 1];

    const validFrom = new Date(cert.not_before);
    const validTo = new Date(cert.not_after);
    const now = new Date();
    const expiryDays = validTo > now ? Math.round((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)) : 0;
    
    // Score based on expiry and algo
    let strengthScore = 70;
    if (expiryDays > 60) strengthScore += 20;
    if (expiryDays <= 30) strengthScore -= 30;

    const sigAlgo = cert.sig_alg || cert.signature_algorithm_name || "";
    if (sigAlgo.toLowerCase().includes("md5") || sigAlgo.toLowerCase().includes("sha1")) {
      strengthScore -= 50;
    } else {
      strengthScore += 10;
    }

    if (strengthScore > 100) strengthScore = 100;
    if (strengthScore < 0) strengthScore = 0;

    const valid = now >= validFrom && now <= validTo;

    return {
      valid,
      subject: cert.name_value || "",
      issuer: cert.issuer_name || "",
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      expiryDays,
      signatureAlgorithm: sigAlgo,
      strengthScore
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      valid: false,
      subject: "",
      issuer: "",
      validFrom: null,
      validTo: null,
      expiryDays: null,
      signatureAlgorithm: undefined,
      strengthScore: 0,
      error: msg
    };
  }
}

/**
 * Fetch HTTP headers from a target URL
 */
async function fetchHttpHeaders(url: string): Promise<Headers> {
  const res = await safeFetch(url, {
    method: "HEAD",
    timeoutMs: 10000,
    headers: { "User-Agent": "subdomain-security-audit/1.0 apimesh.xyz" }
  });
  return res.headers;
}

/**
 * Analyze presence, missing, deprecated security headers
 */
function analyzeSecurityHeaders(headers: Headers): SecurityHeadersAnalysis {
  const present: string[] = [];
  const missing: string[] = [];
  const deprecated: string[] = [];

  for (const hdr of SECURITY_HEADERS) {
    if (headers.has(hdr)) {
      present.push(hdr);
    } else {
      missing.push(hdr);
    }
  }

  for (const hdr of DEPRECATED_HEADERS) {
    if (headers.has(hdr)) deprecated.push(hdr);
  }

  return { present, missing, deprecated };
}

/**
 * Compute overall score 0-100 combining DNS, HTTPS cert, headers
 */
function computeOverallScore(result: {
  dns: DNSRecords;
  httpsCert: HttpsCertificate;
  headers: SecurityHeadersAnalysis;
}): number {
  let score = 100;

  // DNS checks
  if (!result.dns.a || result.dns.a.length === 0) score -= 40;
  if (!result.dns.ns || result.dns.ns.length === 0) score -= 10;

  // HTTPS cert
  if (!result.httpsCert.valid) score -= 40;
  else score -= (100 - result.httpsCert.strengthScore) * 0.4;

  // Missing security headers
  score -= result.headers.missing.length * 5;

  // Deprecated headers present
  score -= result.headers.deprecated.length * 5;

  if (score < 0) score = 0;
  if (score > 100) score = 100;
  return Math.round(score);
}

/**
 * Generate human-readable recommendations based on findings
 */
function generateRecommendations(
  dns: DNSRecords,
  httpsCert: HttpsCertificate,
  headers: SecurityHeadersAnalysis,
  overallScore: number
): Recommendation[] {
  const recs: Recommendation[] = [];

  // DNS
  if (!dns.a || dns.a.length === 0) {
    recs.push({
      issue: "No A records found",
      severity: "high",
      suggestion: "Ensure subdomain DNS has valid A or AAAA records configured."
    });
  }
  if (!dns.ns || dns.ns.length === 0) {
    recs.push({
      issue: "Name servers missing",
      severity: "medium",
      suggestion: "Configure authoritative name servers for the subdomain."
    });
  }

  // HTTPS cert
  if (!httpsCert.valid) {
    recs.push({
      issue: "Invalid or missing SSL certificate",
      severity: "high",
      suggestion: httpsCert.error
        ? `SSL issue: ${httpsCert.error}`
        : "Obtain a valid SSL certificate for the subdomain."
    });
  } else {
    if (httpsCert.expiryDays !== null && httpsCert.expiryDays < 30) {
      recs.push({
        issue: "SSL certificate expiring soon",
        severity: "high",
        suggestion: "Renew the SSL certificate to avoid service interruption."
      });
    }
    if (httpsCert.signatureAlgorithm && httpsCert.signatureAlgorithm.toLowerCase().includes("md5")) {
      recs.push({
        issue: "Weak signature algorithm in SSL certificate",
        severity: "medium",
        suggestion: "Use stronger signature algorithm like SHA-256 in SSL certificate."
      });
    }
  }

  // Security headers
  if (headers.missing.length > 0) {
    for (const missingHdr of headers.missing) {
      recs.push({
        issue: `Missing HTTP security header: ${missingHdr}`,
        severity: "medium",
        suggestion: `Add the HTTP header '${missingHdr}' with an appropriate secure configuration.`
      });
    }
  }
  if (headers.deprecated.length > 0) {
    for (const deprecHdr of headers.deprecated) {
      recs.push({
        issue: `Deprecated HTTP header present: ${deprecHdr}`,
        severity: "low",
        suggestion: `Remove deprecated header '${deprecHdr}' to reduce attack surface.`
      });
    }
  }

  if (recs.length === 0) {
    recs.push({
      issue: "No significant issues detected",
      severity: "low",
      suggestion: "Maintain current security configuration and monitor regularly."
    });
  }

  return recs;
}

// ------------- Main public functions -------------

/**
 * Free preview: basic DNS resolution and HTTPS availability
 */
export async function previewAudit(rawUrl: string): Promise<SubdomainSecurityPreviewResult> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return Promise.reject(new Error(check.error));

  const urlObj = check.url;
  const hostname = urlObj.hostname;

  const start = performance.now();

  // DNS Resolve A record to at least check if subdomain resolves
  let dnsResolved = false;
  try {
    const dnsRes = await safeFetch(
      `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`,
      { timeoutMs: 15000 }
    );
    if (dnsRes.ok) {
      const dnsJson = await dnsRes.json();
      dnsResolved = Array.isArray(dnsJson.Answer) && dnsJson.Answer.length > 0;
    }
  } catch {
    dnsResolved = false;
  }

  // HTTPS availability check
  let httpsAvailable = false;
  try {
    const httpsRes = await safeFetch(rawUrl, { method: "HEAD", timeoutMs: 15000 });
    httpsAvailable = httpsRes.ok;
  } catch {
    httpsAvailable = false;
  }

  const issues: string[] = [];
  if (!dnsResolved) issues.push("DNS resolution failed");
  if (!httpsAvailable) issues.push("HTTPS unavailable or not responding");

  const duration_ms = Math.round(performance.now() - start);

  return {
    url: urlObj.toString(),
    dnsResolved,
    httpsAvailable,
    issues,
    scannedAt: new Date().toISOString(),
  };
}

/**
 * Full comprehensive audit combining DNS, HTTPS cert, Headers
 */
export async function fullAudit(rawUrl: string): Promise<SubdomainSecurityAuditResult | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: check.error };

  const urlObj = check.url;
  const hostname = urlObj.hostname;

  // Timing
  const start = performance.now();

  // Run fetches parallel where possible
  // 1) DNS
  // 2) HTTPS cert
  // 3) HTTP headers

  let dnsRecords: DNSRecords;
  let httpsCert: HttpsCertificate;
  let httpHeaders: Headers;

  try {
    [dnsRecords, httpsCert, httpHeaders] = await Promise.all([
      fetchDnsRecords(hostname),
      fetchHttpsCertificate(hostname),
      fetchHttpHeaders(rawUrl)
    ]);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return { error: `Data fetch failed: ${msg}` };
  }

  const securityHeaders = analyzeSecurityHeaders(httpHeaders);
  
  const overallScore = computeOverallScore({ dns: dnsRecords, httpsCert, headers: securityHeaders });
  const grade = gradeFromScore(overallScore);
  const recommendations = generateRecommendations(dnsRecords, httpsCert, securityHeaders, overallScore);

  // Compose explanation text
  let explanation = `The audit for subdomain ${urlObj.host} identified the following: `;
  if (!dnsRecords.a || dnsRecords.a.length === 0) {
    explanation += "No DNS A records found, which is critical. ";
  } else {
    explanation += `DNS A records resolved: ${dnsRecords.a.join(", ")}. `;
  }

  if (!httpsCert.valid) {
    explanation += `HTTPS certificate invalid or missing. ${httpsCert.error ?? ""} `;
  } else {
    explanation += `HTTPS certificate is valid, issued by ${httpsCert.issuer}. `;
    if (httpsCert.expiryDays !== null && httpsCert.expiryDays < 30) {
      explanation += `Warning: certificate expires in ${httpsCert.expiryDays} days. `;
    }
  }

  if (securityHeaders.missing.length > 0) {
    explanation += `Missing security HTTP headers: ${securityHeaders.missing.join(", ")}. `;
  }

  if (securityHeaders.deprecated.length > 0) {
    explanation += `Deprecated headers found: ${securityHeaders.deprecated.join(", ")}. `;
  }

  explanation += `Overall security grade is ${grade} with a score of ${overallScore}.`;

  const duration_ms = Math.round(performance.now() - start);

  return {
    url: urlObj.toString(),
    dnsRecords,
    httpsCertificate: httpsCert,
    securityHeaders,
    overallScore,
    grade,
    recommendations,
    explanation
  };
}
