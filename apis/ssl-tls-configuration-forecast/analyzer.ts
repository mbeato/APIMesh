import { safeFetch } from "../../shared/ssrf";

// -----------------------------
// Types
// -----------------------------

export interface CipherSuite {
  name: string;
  strengthScore: number; // 0-100
}

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface FullAuditResult {
  domain: string;
  certificateExpiryDays: number | null;
  certificateSubject: string;
  protocolsSupported: string[];
  cipherSuites: CipherSuite[];
  overallScore: number; // 0-100
  grade: string; // A-F
  recommendations: Recommendation[];
  details: string;
}

export interface PreviewResult {
  domain: string;
  certificateExpiryDays: number | null;
  protocolsSupported: string[];
  cipherStrengthSummary: string;
  score: number; // 0-100
  grade: string; // A-F
  recommendations: Recommendation[];
  details: string;
}

// -----------------------------
// Utilities
// -----------------------------

function letterGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function scoreToLetter(score: number): string {
  return letterGrade(score);
}

function protocolStrengthScore(protocol: string): number {
  // Heuristic scoring for TLS versions
  switch (protocol.toUpperCase()) {
    case "TLSV1.3": return 100;
    case "TLSV1.2": return 85;
    case "TLSV1.1": return 50;
    case "TLSV1.0": return 20;
    default: return 0;
  }
}

function cipherNameStrengthScore(name: string): number {
  // Simple heuristic based on common strong cipher naming
  if (!name) return 0;
  const n = name.toUpperCase();
  if (n.includes("AES") && (n.includes("GCM") || n.includes("CCM"))) return 95;
  if (n.includes("ECDHE") || n.includes("DHE")) return 90;
  if (n.includes("CHACHA20")) return 95;
  if (n.includes("AES")) return 80;
  if (n.includes("3DES")) return 30;
  if (n.includes("RC4")) return 10;
  return 50;
}

// -----------------------------
// Fetch Public SSL Report
// We combine DNS, crt.sh, and a public SSL analysis API
// -----------------------------

interface PublicSslScan {
  protocolsSupported: string[]; // e.g. ["TLSv1.2", "TLSv1.3"]
  cipherSuites: string[];      // List of cipher suite names
  certificateExpiry: string | null; // ISO date or null
  certificateSubject: string;
}

async function fetchPublicSslScan(domain: string, signal: AbortSignal): Promise<PublicSslScan> {
  // Using public SSL Labs API
  // Docs: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs.md

  const apiBase = "https://api.ssllabs.com/api/v3/analyze";
  const params = new URLSearchParams({ host: domain, all: "done", fromCache: "on" });
  const url = `${apiBase}?${params.toString()}`;

  const maxRetries = 6;
  let attempt = 0;

  while (attempt < maxRetries) {
    attempt++;
    try {
      const res = await safeFetch(url, { timeoutMs: 10000, signal });
      if (!res.ok) throw new Error(`SSL Labs HTTP ${res.status}`);
      const json = await res.json();

      if (json.status === "ERROR") {
        throw new Error(json.statusMessage || "SSL Labs error");
      }

      if (json.status === "IN_PROGRESS" || json.status === "DNS") {
        // Wait and retry
        await new Promise((r) => setTimeout(r, 5000));
        continue;
      }

      if (!json.endpoints || json.endpoints.length === 0) {
        throw new Error("No endpoint data");
      }

      // Take first endpoint
      const endpoint = json.endpoints[0];

      const protocolsSupported: string[] = [];
      if (endpoint.details?.protocols) {
        for (const p of endpoint.details.protocols) {
          if (p.name && p.version) {
            protocolsSupported.push(`TLSv${p.version}`);
          }
        }
      }

      const cipherSuites: string[] = [];
      if (endpoint.details?.suites?.list) {
        for (const ciph of endpoint.details.suites.list) {
          if (ciph.name) {
            cipherSuites.push(ciph.name);
          }
        }
      }

      const cert = endpoint.cert || {};
      const certificateExpiry = cert.notAfter || null;
      const certificateSubject = cert.subject || "";

      return {
        protocolsSupported,
        cipherSuites,
        certificateExpiry,
        certificateSubject,
      };

    } catch (e) {
      // On timeout or network error, rethrow
      if (e instanceof Error && /timeout|timed out|abort/i.test(e.message)) {
        throw e;
      }
      // For other errors, eventually fail
      if (attempt >= maxRetries) {
        throw e;
      }
      // Wait before retry
      await new Promise((r) => setTimeout(r, 3000));
    }
  }

  throw new Error("SSL Labs API not available");
}

// -----------------------------
// Fetch crt.sh cert info
// -----------------------------

interface CrtShCert {
  not_before: string;
  not_after: string;
  name_value: string;
  issuer_name: string;
  sig_alg: string;
}

async function fetchCrtShCert(domain: string, signal: AbortSignal): Promise<CrtShCert | null> {
  const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;

  try {
    const res = await safeFetch(url, { timeoutMs: 10000, signal });
    if (!res.ok) return null;
    const text = await res.text();
    if (!text || text === "[]") return null;
    const certs = JSON.parse(text);
    if (!Array.isArray(certs) || certs.length === 0) return null;

    // Return the newest cert
    const sorted = certs.sort((a: any, b: any) => {
      return new Date(b.not_before).getTime() - new Date(a.not_before).getTime();
    });

    const cert = sorted[0];
    return {
      not_before: cert.not_before,
      not_after: cert.not_after,
      name_value: cert.name_value,
      issuer_name: cert.issuer_name,
      sig_alg: cert.sig_alg || cert.signature_algorithm_name || "",
    };
  } catch {
    return null;
  }
}

// -----------------------------
// Compute Protocol & Cipher Scores
// -----------------------------

function calculateProtocolScore(protocols: string[]): number {
  if (!protocols || protocols.length === 0) return 0;
  // Average score of supported protocols weighted higher for newer
  let total = 0;
  for (const p of protocols) {
    total += protocolStrengthScore(p);
  }
  return Math.round(total / protocols.length);
}

function calculateCipherScore(ciphers: string[]): number {
  if (!ciphers || ciphers.length === 0) return 0;

  let total = 0;
  for (const c of ciphers) {
    total += cipherNameStrengthScore(c);
  }
  return Math.round(total / ciphers.length);
}

// -----------------------------
// Analyze and Score Certificate Expiry
// -----------------------------

function calculateCertExpiryDays(certExpiry: string | null): number | null {
  if (!certExpiry) return null;
  try {
    const expiryDate = new Date(certExpiry);
    const now = new Date();
    const diffMs = expiryDate.getTime() - now.getTime();
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    return diffDays >= 0 ? diffDays : 0;
  } catch {
    return null;
  }
}

// -----------------------------
// Generate Recommendations
// -----------------------------

function generateRecommendations(
  protocols: string[],
  certExpiryDays: number | null,
  cipherSuites: string[],
): Recommendation[] {
  const recs: Recommendation[] = [];

  // TLS versions to disable
  const oldVersions = ["TLSv1.0", "TLSv1.1"];
  const supportedOld = protocols.filter((p) => oldVersions.includes(p));
  if (supportedOld.length > 0) {
    recs.push({
      issue: `Old TLS versions enabled: ${supportedOld.join(", ")}`,
      severity: 50,
      suggestion: "Disable TLS 1.0 and TLS 1.1 support to improve security.",
    });
  }

  // Certificate expiry
  if (certExpiryDays !== null) {
    if (certExpiryDays < 30) {
      recs.push({
        issue: `Certificate expiry in less than 30 days: ${certExpiryDays} day(s)`,
        severity: 80,
        suggestion: "Renew the SSL/TLS certificate promptly.",
      });
    } else if (certExpiryDays < 90) {
      recs.push({
        issue: `Certificate expiry in less than 90 days: ${certExpiryDays} day(s)`,
        severity: 60,
        suggestion: "Plan to renew the SSL/TLS certificate soon.",
      });
    }
  }

  // Weak ciphers
  if (cipherSuites.length > 0) {
    for (const c of cipherSuites) {
      const score = cipherNameStrengthScore(c);
      if (score < 50) {
        recs.push({
          issue: `Weak cipher suite in use: ${c}`,
          severity: 70,
          suggestion: "Remove or disable weak cipher suites such as 3DES or RC4.",
        });
        break;
      }
    }
  }

  if (recs.length === 0) {
    recs.push({
      issue: "No significant SSL/TLS issues detected.",
      severity: 0,
      suggestion: "Maintain the current SSL/TLS configuration and monitor regularly.",
    });
  }

  return recs;
}

// -----------------------------
// Compose Grade
// -----------------------------

function calculateOverallScore(
  certExpiryDays: number | null,
  protocolScore: number,
  cipherScore: number,
): number {
  let score = 100;

  if (certExpiryDays !== null) {
    if (certExpiryDays < 30) score -= 40;
    else if (certExpiryDays < 90) score -= 20;
  } else {
    score -= 40; // no data
  }

  // Deduct based on protocol score
  if (protocolScore < 80) {
    score -= 30;
  } else if (protocolScore < 90) {
    score -= 15;
  }

  // Deduct based on cipher score
  if (cipherScore < 80) {
    score -= 25;
  } else if (cipherScore < 90) {
    score -= 10;
  }

  if (score < 0) score = 0;
  if (score > 100) score = 100;

  return Math.round(score);
}

// -----------------------------
// Main Full Audit function
// -----------------------------

export async function fullAudit(domain: string): Promise<FullAuditResult | { error: string }> {
  // AbortSignal for fetch calls
  const controller = new AbortController();
  const { signal } = controller;

  // Run fetches in parallel
  try {
    const [sslScan, crtshCert] = await Promise.all([
      fetchPublicSslScan(domain, signal),
      fetchCrtShCert(domain, signal),
    ]);

    // certificate expiry days from cert.sh or SSL Labs
    let expiryDateStr = sslScan.certificateExpiry;
    if (!expiryDateStr && crtshCert) expiryDateStr = crtshCert.not_after;

    const certExpiryDays = calculateCertExpiryDays(expiryDateStr);

    // Compose cipher suites with strength
    const cipherSuites: CipherSuite[] = (sslScan.cipherSuites || []).map((c) => ({
      name: c,
      strengthScore: cipherNameStrengthScore(c),
    }));

    // Protocol score
    const protocolScore = calculateProtocolScore(sslScan.protocolsSupported);

    // Cipher score
    const cipherScore = calculateCipherScore(sslScan.cipherSuites);

    const overallScore = calculateOverallScore(certExpiryDays, protocolScore, cipherScore);

    const recs = generateRecommendations(
      sslScan.protocolsSupported,
      certExpiryDays,
      sslScan.cipherSuites
    );

    const grade = scoreToLetter(overallScore);

    const details = "Combined data from SSL Labs public API and crt.sh certificate info. Recommendations prioritize disabling outdated protocols, renewing certificates, and removing weak ciphers.";

    const result: FullAuditResult = {
      domain,
      certificateExpiryDays: certExpiryDays,
      certificateSubject: sslScan.certificateSubject || (crtshCert ? crtshCert.name_value : ""),
      protocolsSupported: sslScan.protocolsSupported,
      cipherSuites,
      overallScore,
      grade,
      recommendations: recs,
      details,
    };

    return result;

  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: msg };
  }
}

// -----------------------------
// Preview Audit (free)
// More limited: only protocol detection via SSL Labs, no cipher suites detail
// -----------------------------

export async function previewAudit(domain: string): Promise<PreviewResult | { error: string }> {
  // AbortSignal for fetch calls
  const controller = new AbortController();
  const { signal } = controller;

  try {
    const sslScan = await fetchPublicSslScan(domain, signal);

    const certExpiryDays = calculateCertExpiryDays(sslScan.certificateExpiry);

    const protocolScore = calculateProtocolScore(sslScan.protocolsSupported);

    // Cipher strength summary heuristic
    let cipherStrengthSummary = "Unknown";
    if (sslScan.cipherSuites && sslScan.cipherSuites.length > 0) {
      const cipherScore = calculateCipherScore(sslScan.cipherSuites);
      if (cipherScore >= 90) cipherStrengthSummary = "Strong";
      else if (cipherScore >= 70) cipherStrengthSummary = "Medium";
      else cipherStrengthSummary = "Weak";
    }

    // Simple scoring combining protocol and cert expiry
    let score = 100;

    if (certExpiryDays !== null) {
      if (certExpiryDays < 30) score -= 40;
      else if (certExpiryDays < 90) score -= 20;
    } else {
      score -= 40;
    }

    if (protocolScore < 80) {
      score -= 40;
    } else if (protocolScore < 90) {
      score -= 20;
    }

    if (score < 0) score = 0;
    if (score > 100) score = 100;

    const grade = scoreToLetter(score);

    const recs = generateRecommendations(
      sslScan.protocolsSupported,
      certExpiryDays,
      sslScan.cipherSuites || []
    );

    const details = "Limited preview: only primary SSL Labs data is used without cipher suite detailed analysis or crt.sh data.";

    return {
      domain,
      certificateExpiryDays: certExpiryDays,
      protocolsSupported: sslScan.protocolsSupported,
      cipherStrengthSummary,
      score,
      grade,
      recommendations: recs,
      details,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: msg };
  }
}
