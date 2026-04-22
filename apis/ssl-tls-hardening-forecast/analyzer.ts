import { safeFetch } from "../../shared/ssrf";

// ── Types ──────────────────────────────────────────────────────────────────────

export interface SslScanResult {
  host: string;
  certExpiryDays: number | null;
  certValidFrom: string | null;
  certValidTo: string | null;
  certIssuer: string | null;
  protocols: string[]; // e.g., ["TLS 1.2", "TLS 1.3"]
  ciphers: string[];   // List of strong/weak cipher names
  warnings: Warning[];
  secure: boolean; // overall SSL/TLS perceived security
  checkedAt: string;
}

export interface Warning {
  level: number; // 0-100 severity
  issue: string;
  detail?: string;
}

export interface DnsTlsRecord {
  protocolName: string; // e.g., "DOT", "DOH", "TLS"
  hostname: string;
  ipAddresses: string[];
  port: number;
  certExpiryDays: number | null;
  certIssuer: string | null;
  protocols: string[];
  ciphers: string[];
  valid: boolean;
  error?: string;
}

export interface DnsTlsRecordsResult {
  host: string;
  records: DnsTlsRecord[];
  warnings: Warning[];
  checkedAt: string;
}

export interface ForecastInput {
  sslScan: SslScanResult;
  dnsTls: DnsTlsRecordsResult;
}

export interface Recommendation {
  issue: string;
  severity: number;
  suggestion: string;
}

export interface ForecastData {
  expiryForecastDays: number | null;
  protocolSupportGrade: string; // letter A-F
  cipherSupportGrade: string;   // letter A-F
  nextRenewalDate?: string;
  vulnerableProtocols: string[];
  weakCiphers: string[];
  explanation: string;
}

export interface ForecastResult {
  host: string;
  sslReport: SslScanResult;
  dnsTlsReport: DnsTlsRecordsResult;
  forecast: ForecastData;
  score: number; // 0-100
  grade: string; // A-F
  recommendations: Recommendation[];
  checkedAt: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function letterGradeFromScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  if (score >= 35) return "E";
  return "F";
}

// Strong cipher patterns
const WEAK_CIPHERS = [
  "RC4",
  "3DES",
  "DES",
  "MD5",
  "NULL",
  "EXP",
  "CBC",
  "MD4",
  "SHA1"
];

const VULNERABLE_PROTOCOLS = ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"];

// ── External Data Fetchers ──────────────────────────────────────────────────────

async function fetchSslLabs(host: string, signal: AbortSignal): Promise<SslScanResult> {
  // Use SSL Labs public API to fetch endpoint info
  // API docs: https://github.com/ssllabs/ssllabs-scan

  const apiBase = "https://api.ssllabs.com/api/v3/evaluate";

  // Step 1: initiate or retrieve scan
  const url = `${apiBase}?host=${encodeURIComponent(host)}&all=done`;

  // We may retry to wait for scan completion with timeout max 8s in here
  let attempt = 0;
  while (attempt < 4) {
    attempt++;
    const res = await safeFetch(url, { signal, timeoutMs: 10000 });
    if (!res.ok) {
      throw new Error(`SSL Labs API ${res.status} ${res.statusText}`);
    }
    const json = await res.json();

    if (json.status === "READY" && Array.isArray(json.endpoints) && json.endpoints.length > 0) {
      // Use first endpoint
      return parseSslLabsResult(json.endpoints[0], host);
    } else if (json.status === "ERROR") {
      throw new Error(`SSL Labs scan error: ${json.statusMessage || "Unknown error"}`);
    }

    // Status PENDING or IN_PROGRESS
    await new Promise((r) => setTimeout(r, 2500));
    // Signal timeout aborted will throw
  }

  throw new Error("SSL Labs scan did not complete within timeout");
}

function parseSslLabsResult(endpoint: any, host: string): SslScanResult {
  const now = new Date().toISOString();

  // Extract cert info
  let certExpiryDays: number | null = null;
  let certValidFrom: string | null = null;
  let certValidTo: string | null = null;
  let certIssuer: string | null = null;

  if (endpoint.details && endpoint.details.cert) {
    const cert = endpoint.details.cert;
    const validTo = new Date(cert.notAfter);
    const validFromDate = new Date(cert.notBefore);
    const nowDate = new Date();

    certValidFrom = cert.notBefore;
    certValidTo = cert.notAfter;
    certIssuer = cert.issuerLabel || cert.issuerSubject;
    certExpiryDays = validTo > nowDate
      ? Math.round((validTo.getTime() - nowDate.getTime()) / (1000 * 3600 * 24))
      : 0;
  }

  // Protocols
  const protocols: string[] = [];
  if (endpoint.details && Array.isArray(endpoint.details.protocols)) {
    for (const p of endpoint.details.protocols) {
      if (typeof p.name === "string" && typeof p.version === "string") {
        protocols.push(`${p.name} ${p.version}`);
      }
    }
  }

  // Ciphers
  const ciphers: string[] = [];
  if (endpoint.details && Array.isArray(endpoint.details.suites?.list)) {
    for (const suite of endpoint.details.suites.list) {
      if (typeof suite.name === "string") {
        ciphers.push(suite.name);
      }
    }
  }

  // Determine secure or warnings
  // Security: warning on expiry under 30 days, weak cipher or vulnerable protocol
  const warnings: Warning[] = [];
  let secure = true;

  if (certExpiryDays !== null && certExpiryDays < 30) {
    warnings.push({
      level: 80,
      issue: "SSL certificate expiring soon",
      detail: `${certExpiryDays} days left until expiry.`
    });
    secure = false;
  }

  // Check for weak protocols
  const vulnerableProts = protocols.filter((p) => VULNERABLE_PROTOCOLS.includes(p));
  if (vulnerableProts.length > 0) {
    warnings.push({
      level: 90,
      issue: "Old vulnerable TLS/SSL protocols supported",
      detail: `Protocols: ${vulnerableProts.join(", ")}`
    });
    secure = false;
  }

  // Check for weak ciphers
  const weakCiphers = ciphers.filter((c) =>
    WEAK_CIPHERS.some((weak) => c.toUpperCase().includes(weak))
  );
  if (weakCiphers.length > 0) {
    warnings.push({
      level: 70,
      issue: "Weak ciphers supported",
      detail: `Ciphers: ${weakCiphers.join(", ")}`
    });
    secure = false;
  }

  return {
    host: host.toLowerCase(),
    certExpiryDays,
    certValidFrom,
    certValidTo,
    certIssuer,
    protocols,
    ciphers,
    warnings,
    secure,
    checkedAt: now,
  };
}

// DNS TLS Record fetcher - uses DNS over HTTPS for TLSA records and DoH/DoT
// This is a simplified impl: fetch TLSA records (type 52) from DNS over HTTPS and parse

async function fetchDnsTlsaRecords(host: string, signal: AbortSignal): Promise<DnsTlsRecordsResult> {
  // Fetch TLSA records for _443._tcp.host
  const recordName = `_443._tcp.${host}`;
  const dohUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(recordName)}&type=52`;

  const now = new Date().toISOString();
  try {
    const res = await safeFetch(dohUrl, {
      headers: { Accept: "application/dns-json" },
      signal,
      timeoutMs: 10000,
    });
    if (!res.ok) {
      return {
        host,
        records: [],
        warnings: [{ level: 50, issue: `DNS TLSA query HTTP status ${res.status}` }],
        checkedAt: now
      };
    }
    const data = await res.json();

    if (!data.Answer || !Array.isArray(data.Answer)) {
      return {
        host,
        records: [],
        warnings: [{ level: 40, issue: `No TLSA DNS records found` }],
        checkedAt: now
      };
    }

    const records: DnsTlsRecord[] = [];

    // Parse TLSA record data from DNS answer
    for (const ans of data.Answer) {
      if (typeof ans.data === "string") {
        const record: DnsTlsRecord = {
          protocolName: "TLSA",
          hostname: recordName,
          ipAddresses: [],
          port: 443,
          certExpiryDays: null,
          certIssuer: null,
          protocols: [],
          ciphers: [],
          valid: true,
        };
        // Data is hex encoded TLSA RR fields; skipping detailed parsing for brevity
        records.push(record);
      }
    }

    return {
      host,
      records,
      warnings: [],
      checkedAt: now,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      host,
      records: [],
      warnings: [{ level: 90, issue: `Error fetching DNS TLS records`, detail: msg }],
      checkedAt: now,
    };
  }
}

// ── Analysis merging and forecasting ──────────────────────────────────────────

/**
 * Merge SSL Labs and DNS TLS results into unified forecast input
 */
export function mergeForecasts(
  sslScan: SslScanResult,
  dnsTls: DnsTlsRecordsResult
): ForecastData {
  // Expiry forecast: take minimal cert expiry days from available sources
  const expiryCandidates: number[] = [];
  if (sslScan.certExpiryDays !== null) expiryCandidates.push(sslScan.certExpiryDays);
  for (const rec of dnsTls.records) {
    if (rec.certExpiryDays !== null) expiryCandidates.push(rec.certExpiryDays);
  }

  const minExpiry = expiryCandidates.length > 0 ? Math.min(...expiryCandidates) : null;
  const nextRenewalDate = minExpiry !== null ?
    new Date(Date.now() + minExpiry * 86400 * 1000).toISOString() : undefined;

  // Protocol support grade
  // Combine all protocols supported
  const protocolsSet = new Set<string>(sslScan.protocols);
  for (const rec of dnsTls.records) {
    for (const p of rec.protocols) {
      protocolsSet.add(p);
    }
  }

  // Score protocol support: penalize for vulnerable protocols
  let protocolScore = 100;
  const vulnerableProtocolsFound: string[] = [];
  protocolsSet.forEach((p) => {
    if (VULNERABLE_PROTOCOLS.includes(p)) {
      protocolScore -= 30;
      vulnerableProtocolsFound.push(p);
    }
  });
  if (protocolScore < 0) protocolScore = 0;

  // Cipher support grade
  const allCiphers = new Set<string>(sslScan.ciphers);
  for (const rec of dnsTls.records) {
    for (const c of rec.ciphers) allCiphers.add(c);
  }
  const weakCiphersFound = Array.from(allCiphers).filter((c) =>
    WEAK_CIPHERS.some((weak) => c.toUpperCase().includes(weak))
  );

  let cipherScore = 100 - weakCiphersFound.length * 10;
  if (cipherScore < 0) cipherScore = 0;

  // Calculate final score weighted 50% expiry, 25% protocol, 25% cipher
  let expiryScore = 50;
  if (minExpiry === null) expiryScore = 20; // no expiry info
  else if (minExpiry < 15) expiryScore = 10;
  else if (minExpiry < 30) expiryScore = 30;
  else if (minExpiry < 90) expiryScore = 40;

  const finalScore = Math.round(expiryScore + protocolScore * 0.25 + cipherScore * 0.25);
  const grade = letterGradeFromScore(finalScore);

  const explanationParts = [];
  explanationParts.push(`Certificate expires in ${minExpiry ?? "unknown"} days.`);
  if (vulnerableProtocolsFound.length > 0) {
    explanationParts.push(
      `Using vulnerable protocols: ${vulnerableProtocolsFound.join(", ")}.`
    );
  } else {
    explanationParts.push("No vulnerable protocols detected.");
  }
  if (weakCiphersFound.length > 0) {
    explanationParts.push(
      `Weak ciphers detected: ${weakCiphersFound.join(", ")}.`
    );
  } else {
    explanationParts.push("No weak ciphers detected.");
  }

  // Recommendations
  const recommendations: Recommendation[] = [];
  if (minExpiry !== null && minExpiry < 30) {
    recommendations.push({
      issue: "Upcoming SSL cert expiry",
      severity: 90,
      suggestion: "Renew certificate at least 15 days before expiry."
    });
  }
  if (vulnerableProtocolsFound.length > 0) {
    recommendations.push({
      issue: "Supports vulnerable TLS/SSL protocols",
      severity: 85,
      suggestion: `Disable TLS/SSL versions: ${vulnerableProtocolsFound.join(", ")}`
    });
  }
  if (weakCiphersFound.length > 0) {
    recommendations.push({
      issue: "Supports weak cipher suites",
      severity: 70,
      suggestion: `Remove weak TLS ciphers: ${weakCiphersFound.join(", ")}`
    });
  }

  if (recommendations.length === 0) {
    recommendations.push({
      issue: "Good SSL/TLS health",
      severity: 0,
      suggestion: "No immediate action required. Continue regular monitoring."
    });
  }

  return {
    expiryForecastDays: minExpiry,
    protocolSupportGrade: letterGradeFromScore(protocolScore),
    cipherSupportGrade: letterGradeFromScore(cipherScore),
    nextRenewalDate,
    vulnerableProtocols: vulnerableProtocolsFound,
    weakCiphers: weakCiphersFound,
    explanation: explanationParts.join(" "),
  };
}

/**
 * Wrapper to run full analysis of SSL scan from SSL Labs
 */
export async function analyzeSslScanResults(host: string, signal: AbortSignal): Promise<SslScanResult> {
  try {
    return await fetchSslLabs(host, signal);
  } catch (e) {
    const now = new Date().toISOString();
    const errMsg = e instanceof Error ? e.message : String(e);
    return {
      host,
      certExpiryDays: null,
      certValidFrom: null,
      certValidTo: null,
      certIssuer: null,
      protocols: [],
      ciphers: [],
      warnings: [{ level: 100, issue: "SSL scan failed", detail: errMsg }],
      secure: false,
      checkedAt: now
    };
  }
}

/**
 * Wrapper to run DNS TLS record fetch
 */
export async function analyzeDnsTlsRecords(host: string, signal: AbortSignal): Promise<DnsTlsRecordsResult> {
  try {
    return await fetchDnsTlsaRecords(host, signal);
  } catch (e) {
    const now = new Date().toISOString();
    const errMsg = e instanceof Error ? e.message : String(e);
    return {
      host,
      records: [],
      warnings: [{ level: 100, issue: "DNS TLS record fetch failed", detail: errMsg }],
      checkedAt: now
    };
  }
}

/**
 * Compute overall grade and recommendations from merged forecast
 */
export function forecastExpiryAndSecurity(forecast: ForecastData): {
  score: number;
  grade: string;
  recommendations: Recommendation[];
} {
  const score = Math.min(100, Math.max(0, forecast.expiryForecastDays !== null ? forecast.expiryForecastDays : 0));

  let gradeScore = score;

  // Adjust grade score by protocols and cipher grades
  const protocolGradeScore = gradeLetterToScore(forecast.protocolSupportGrade);
  const cipherGradeScore = gradeLetterToScore(forecast.cipherSupportGrade);

  gradeScore = Math.round(Math.min(100, gradeScore * 0.5 + protocolGradeScore * 0.25 + cipherGradeScore * 0.25));

  const grade = letterGradeFromScore(gradeScore);

  const recommendations: Recommendation[] = [];

  // Encourage renewal if expiry less than 30 days
  if (forecast.expiryForecastDays !== null && forecast.expiryForecastDays < 30) {
    recommendations.push({
      issue: "Pending certificate expiry",
      severity: 90,
      suggestion: "Renew SSL/TLS certificate promptly to avoid downtime."
    });
  }

  if (forecast.vulnerableProtocols.length > 0) {
    recommendations.push({
      issue: "Vulnerable protocols detected",
      severity: 80,
      suggestion: `Disable protocols: ${forecast.vulnerableProtocols.join(", ")}`
    });
  }

  if (forecast.weakCiphers.length > 0) {
    recommendations.push({
      issue: "Weak cipher suites detected",
      severity: 70,
      suggestion: `Remove or disable weak ciphers: ${forecast.weakCiphers.join(", ")}`
    });
  }

  if (recommendations.length === 0) {
    recommendations.push({
      issue: "No critical issues detected",
      severity: 0,
      suggestion: "Maintain current SSL/TLS best practices and monitor regularly."
    });
  }

  return { score: gradeScore, grade, recommendations };
}

function gradeLetterToScore(letter: string): number {
  switch (letter.toUpperCase()) {
    case "A": return 90;
    case "B": return 80;
    case "C": return 65;
    case "D": return 50;
    case "E": return 35;
    case "F": return 0;
    default: return 0;
  }
}

