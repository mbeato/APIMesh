import { safeFetch, validateExternalUrl } from "../../shared/ssrf";

// --- Types ---
export type Grade = "A" | "B" | "C" | "D" | "F";

export interface Recommendation {
  issue: string;
  severity: "low" | "medium" | "high";
  suggestion: string;
}

export interface CipherSuites {
  strong: string[];
  weak: string[];
}

export interface SSLEvaluationResult {
  domain: string;
  sslEvaluationScore: number; // 0-100 score
  sslEvaluationGrade: Grade;
  weakestProtocols: string[]; // e.g., ["SSLv3", "TLSv1"]
  cipherSuites: CipherSuites;
  recommendations: Recommendation[];
  details: string; // human-readable aggregate explanation
  scannedAt: string; // ISO8601
}

export interface PreviewResult {
  domain: string;
  quickScore: number; // 0-100 quick estimate
  quickGrade: Grade;
  notes: string;
  scannedAt: string;
  error?: string;
}

export interface APIInfoResponse {
  api: string;
  status: string;
  version: string;
  docs: {
    endpoints: Array<{
      method: string;
      path: string;
      description: string;
      parameters: Array<{ name: string; description: string; required: boolean; type: string }>;
      exampleResponse: any;
    }>;
    parameters: Array<{ name: string; description: string; type: string; required: boolean }>;
    examples: string[];
  };
  pricing: {
    paidEndpoint: string;
    description: string;
    pricePerCall: string;
  };
}

// --- Analysis Helpers ---

const SSL_PROTOCOLS = [
  "SSLv2",
  "SSLv3",
  "TLSv1",
  "TLSv1.1",
  "TLSv1.2",
  "TLSv1.3"
];

const STRONG_PROTOCOLS = new Set(["TLSv1.2", "TLSv1.3"]);
const WEAK_PROTOCOLS = new Set(["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]);

const WEAK_CIPHER_INDICATORS = ["RC4", "MD5", "DES", "3DES", "NULL", "EXPORT"];

// Helper to grade score to letter
function gradeFromScore(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 45) return "D";
  return "F";
}

// --- Safe fetch wrapper for SSL Labs API and others ---

async function fetchSslLabsData(domain: string, signal: AbortSignal): Promise<any> {
  // Poll SSL Labs API until status ready or aborted with timeout
  // API: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs.md

  const apiBase = `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(domain)}&all=done&fromCache=on`;

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  let attempts = 0;
  const maxAttempts = 20;
  try {
    while (attempts++ < maxAttempts) {
      const res = await safeFetch(apiBase, {
        method: "GET",
        signal,
        timeoutMs: 10000
      });

      const data = await res.json();
      if (data.status === "READY" || data.status === "ERROR") {
        return data;
      }
      // Pending statuses: IN_PROGRESS, DNS, STARTING, etc.
      await sleep(2000);
    }
    throw new Error("SSL Labs scan timed out waiting for ready status");
  } catch (e) {
    throw new Error(`Unable to fetch SSL Labs data: ${(e as Error).message}`);
  }
}

async function fetchDnsTlsRecords(domain: string, signal: AbortSignal): Promise<{ protocols: string[] }> {
  // We do a DNS over HTTPS query for TLSA and CAA records
  // Also grab DNSSEC info if possible
  // Use Google DNS over HTTPS endpoint
  try {
    const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TLSA`;
    const res = await safeFetch(url, { signal, timeoutMs: 10000 });
    const data = await res.json();

    // Extract TLSA data for protocols if present
    // For simplicity, parse RDATA for protocols is complex, treat presence of TLSA as hint
    const protocols = data?.Answer ? ["TLS"] : [];

    return { protocols };
  } catch {
    return { protocols: [] };
  }
}

async function fetchCertificateTransparencyLogs(domain: string, signal: AbortSignal): Promise<{ certs: any[] }> {
  // Query crt.sh JSON URL for certificates
  try {
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    const res = await safeFetch(url, { signal, timeoutMs: 10000 });
    const body = await res.text();
    if (!body) return { certs: [] };
    const entries = JSON.parse(body);
    if (!Array.isArray(entries)) return { certs: [] };
    return { certs: entries };
  } catch {
    return { certs: [] };
  }
}

function analyzeProtocols(protocols: string[]): { weak: string[], strong: string[] } {
  const strong: string[] = [];
  const weak: string[] = [];
  for (const proto of protocols) {
    if (STRONG_PROTOCOLS.has(proto)) strong.push(proto);
    else if (WEAK_PROTOCOLS.has(proto)) weak.push(proto);
  }
  return { strong, weak };
}

function classifyCipherSuites(suites: string[]): CipherSuites {
  const strong: string[] = [];
  const weak: string[] = [];
  for (const suite of suites) {
    const upperSuite = suite.toUpperCase();
    if (WEAK_CIPHER_INDICATORS.some((w) => upperSuite.includes(w))) {
      weak.push(suite);
    } else {
      strong.push(suite);
    }
  }
  return { strong, weak };
}

function calculateScore(weakProtocols: string[], weakSuites: string[], certAgeDays: number | null): number {
  // Score 0-100 based on inputs
  // Start at 100
  let score = 100;

  // Deduct for each weak protocol detected (more critical)
  score -= weakProtocols.length * 10;

  // Deduct for weak cipher suites
  score -= weakSuites.length * 3;

  // Deduct for old certificate (more than 395 days backwards compatible recommendations)
  if (certAgeDays !== null) {
    if (certAgeDays > 825) score -= 15; // older than 2.25 years
    else if (certAgeDays > 395) score -= 10; // older than 13 months
  }

  if (score < 0) score = 0;
  if (score > 100) score = 100;

  return score;
}

function scoreToGrade(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 45) return "D";
  return "F";
}

function generateRecommendations(
  weakProtocols: string[],
  weakSuites: string[],
  certAgeDays: number | null
): Recommendation[] {
  const recs: Recommendation[] = [];

  if (weakProtocols.length > 0) {
    recs.push({
      issue: "Weak protocols enabled",
      severity: "high",
      suggestion: `Disable the following weak protocols: ${weakProtocols.join(", ")}`
    });
  }
  if (weakSuites.length > 0) {
    recs.push({
      issue: "Weak or insecure cipher suites enabled",
      severity: "medium",
      suggestion: `Remove or disable weak cipher suites including: ${weakSuites.join(", ")}`
    });
  }
  if (certAgeDays !== null) {
    if (certAgeDays > 825) {
      recs.push({
        issue: "SSL certificate is very old",
        severity: "medium",
        suggestion: "Replace certificate with a newer one issued within the past 2 years."
      });
    } else if (certAgeDays > 395) {
      recs.push({
        issue: "SSL certificate older than 13 months",
        severity: "low",
        suggestion: "Consider renewing your certificate more frequently to comply with modern standards."
      });
    }
  }

  if (recs.length === 0) {
    recs.push({
      issue: "No major issues detected",
      severity: "low",
      suggestion: "SSL/TLS configuration appears strong and up to date."
    });
  }

  return recs;
}

function getLatestCertificate(ctEntries: any[]): { notBefore: string | null; notAfter: string | null } | null {
  if (!ctEntries.length) return null;

  // Filter only entries with not_before and not_after
  const validEntries = ctEntries.filter(e => e.not_before && e.not_after);
  if (validEntries.length === 0) return null;

  // Sort by not_after descending (most recent expires later)
  validEntries.sort((a, b) => (new Date(b.not_after).getTime()) - (new Date(a.not_after).getTime()));
  const latest = validEntries[0];

  return { notBefore: latest.not_before, notAfter: latest.not_after };
}

// --- Public API Functions ---

export async function fullAudit(rawUrl: string): Promise<SSLEvaluationResult | { error: string }> {
  const validation = validateExternalUrl(rawUrl);
  if ("error" in validation) return { error: validation.error };

  const domain = validation.url.hostname;

  // Provide AbortSignal.timeout to parallel fetches
  const signal = AbortSignal.timeout(10000);

  try {
    // Fetch SSL Labs data, DNS TLS records, CT Logs in parallel
    const [sslLabsData, dnsTls, ctLogs] = await Promise.all([
      fetchSslLabsData(domain, signal),
      fetchDnsTlsRecords(domain, signal),
      fetchCertificateTransparencyLogs(domain, signal)
    ]);

    if (sslLabsData.status === "ERROR") {
      return { error: `SSL Labs scan error: ${sslLabsData.statusMessage || "unknown error"}` };
    }

    // Analyze protocols
    const protocols: string[] = [];
    const protocolsSet = new Set<string>();

    if (sslLabsData.endpoints && sslLabsData.endpoints.length > 0) {
      // Collect protocols from all endpoints
      for (const ep of sslLabsData.endpoints) {
        if (ep.details && ep.details.protocols) {
          for (const p of ep.details.protocols) {
            if (p.name && !protocolsSet.has(p.name)) {
              protocols.push(p.name);
              protocolsSet.add(p.name);
            }
          }
        }
      }
    }

    // Protocols from DNS TLS records (add if missing)
    for (const p of dnsTls.protocols) {
      if (!protocolsSet.has(p)) {
        protocols.push(p);
        protocolsSet.add(p);
      }
    }

    const { weak: weakProtocols, strong: strongProtocols } = analyzeProtocols(protocols);

    // Extract cipher suites from SSL Labs
    const allCipherSuites: string[] = [];
    if (sslLabsData.endpoints && sslLabsData.endpoints.length > 0) {
      for (const ep of sslLabsData.endpoints) {
        if (ep.details && ep.details.suites && ep.details.suites.list) {
          for (const suite of ep.details.suites.list) {
            if (suite.name) allCipherSuites.push(suite.name);
          }
        }
      }
    }

    const cipherSuites = classifyCipherSuites(allCipherSuites);

    // Certificate age from CT logs
    let certAgeDays: number | null = null;
    const certInfo = getLatestCertificate(ctLogs.certs);
    if (certInfo && certInfo.notBefore) {
      try {
        const notBefore = new Date(certInfo.notBefore);
        const now = new Date();
        certAgeDays = Math.floor((now.getTime() - notBefore.getTime()) / (1000 * 60 * 60 * 24));
      } catch {
        certAgeDays = null;
      }
    }

    // Calculate score
    const score = calculateScore(weakProtocols, cipherSuites.weak, certAgeDays);
    const grade = scoreToGrade(score);

    // Recommendations
    const recommendations = generateRecommendations(weakProtocols, cipherSuites.weak, certAgeDays);

    // Compose details (human-readable)
    let details = `Aggregated scan from SSL Labs, DNS records, and Certificate Transparency logs.\n`;
    details += `Detected protocols: ${protocols.length > 0 ? protocols.join(", ") : "none"}.\n`;
    details += `Weak protocols: ${weakProtocols.length > 0 ? weakProtocols.join(", ") : "none"}.\n`;
    details += `Cipher suites analyzed: ${allCipherSuites.length}. Weak suites: ${cipherSuites.weak.length}.\n`;
    if (certAgeDays !== null) {
      details += `Certificate age: ${certAgeDays} days.\n`;
    } else {
      details += `Certificate age: unknown.\n`;
    }

    const scannedAt = new Date().toISOString();

    return {
      domain,
      sslEvaluationScore: score,
      sslEvaluationGrade: grade,
      weakestProtocols: weakProtocols,
      cipherSuites,
      recommendations,
      details,
      scannedAt
    };
  } catch (e: any) {
    return { error: e.message ?? "Unexpected error during audit" };
  }
}

export async function previewAudit(rawUrl: string): Promise<PreviewResult | { error: string }> {
  const validation = validateExternalUrl(rawUrl);
  if ("error" in validation) return { error: validation.error };
  const domain = validation.url.hostname;

  const signal = AbortSignal.timeout(20000); // Longer for preview

  try {
    // Fetch SSL Labs summary with minimal details
    // We do a quick fetch only once (do not wait full status)
    const apiUrl = `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(domain)}&startNew=on&maxAge=1&all=done`;

    // Will likely get IN_PROGRESS status, get some cached data if available
    const res = await safeFetch(apiUrl, { signal, timeoutMs: 15000 });
    if (!res.ok) {
      return { error: `Failed to fetch from SSL Labs API: HTTP ${res.status}` };
    }
    const data = await res.json();

    // Extract protocols briefly
    let protocols: string[] = [];
    if (data.endpoints && Array.isArray(data.endpoints)) {
      protocols = [];
      const protocolsSet = new Set<string>();
      for (const ep of data.endpoints) {
        if (ep.details && ep.details.protocols) {
          for (const p of ep.details.protocols) {
            if (!protocolsSet.has(p.name)) {
              protocolsSet.add(p.name);
              protocols.push(p.name);
            }
          }
        }
      }
    }

    const { weak: weakProtocols } = analyzeProtocols(protocols);
    // Quick score just on weak protocols count
    let score = 100 - weakProtocols.length * 25;
    if (score < 0) score = 0;
    const grade = scoreToGrade(score);

    const notes = "Preview checks protocols availability only with limited detail. Use /check for comprehensive audit.";

    return {
      domain,
      quickScore: score,
      quickGrade: grade,
      notes,
      scannedAt: new Date().toISOString()
    };
  } catch (e: any) {
    const msg = e.message ?? String(e);
    return { error: msg, domain, quickScore: 0, quickGrade: "F", notes: "Preview check failed.", scannedAt: new Date().toISOString() };
  }
}
