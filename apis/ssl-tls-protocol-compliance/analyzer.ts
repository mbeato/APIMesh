import { safeFetch, validateExternalUrl } from "../../shared/ssrf";
import type { SslScanReport, DnsRecord, TlsHandshakeInfo, ComplianceScores, Recommendation, AuditResult, PreviewResult } from "./types";

const SSL_SCAN_API = "https://api.ssllabs.com/api/v3/analyze?host=";
const DNS_OVER_HTTPS = "https://dns.google/resolve?name=";

// Run a safe fetch with 10s timeout
async function fetchJson(url: string, timeoutMs = 10000): Promise<any> {
  const res = await safeFetch(url, { timeoutMs });
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  return res.json();
}

// Parse grade from numeric score
function scoreToGrade(score: number): ComplianceScores["grade"] {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

function analyzeTlsVersions(supportedVersions: string[]): { weakDetected: boolean; score: number; explanation: string } {
  // Allow only TLS 1.2 and 1.3 for 'modern'
  const weakProtocols = supportedVersions.filter(v => {
    const vn = v.toLowerCase();
    return vn.startsWith("ssl") || vn === "tls 1.0" || vn === "tls 1.1";
  });
  const weakDetected = weakProtocols.length > 0;
  const score = weakDetected ? 50 : 100;
  const explanation = weakDetected
    ? `Weak SSL/TLS protocols detected: ${weakProtocols.join(", ")}. Consider disabling them and supporting only TLS 1.2+.`
    : "Only modern TLS protocols (1.2 and newer) are supported.";
  return { weakDetected, score, explanation };
}

function analyzeCiphers(ciphers: any[] | undefined): { weakCount: number; total: number; score: number; explanation: string } {
  if (!ciphers || ciphers.length === 0) {
    return { weakCount: 0, total: 0, score: 0, explanation: "No cipher information available." };
  }
  // Treat ciphers with 'RC4', 'DES', 'NULL', or with < 128 bits as weak
  let weakCount = 0;
  ciphers.forEach((cipher) => {
    const name = cipher.name.toUpperCase();
    const bits = cipher.bits || 0;
    const kx = (cipher.kx || "").toUpperCase();
    if (
      bits < 128 ||
      name.includes("RC4") ||
      name.includes("DES") ||
      name.includes("NULL") ||
      name.includes("EXPORT") ||
      name.includes("MD5") ||
      kx.includes("NULL")
    ) {
      weakCount++;
    }
  });

  const total = ciphers.length;
  // Score: strong ciphers fraction * 100
  const strong = total - weakCount;
  const score = total > 0 ? Math.round((strong / total) * 100) : 0;
  const explanation = `Out of ${total} cipher suites, ${weakCount} are considered weak or insecure.`;
  return { weakCount, total, score, explanation };
}

async function fetchSslScan(domain: string): Promise<SslScanReport> {
  // We call SSL Labs public API, which may queue, so do polling
  let pollCount = 0;
  const maxPolls = 6;
  let data: any;

  while (pollCount < maxPolls) {
    try {
      data = await fetchJson(`${SSL_SCAN_API}${encodeURIComponent(domain)}&publish=off&all=done`, 10000);
    } catch (e) {
      throw new Error(`SSL scan fetch error: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (data.status === "READY" || data.status === "ERROR") break;
    // Wait 3 seconds between polls
    await new Promise(r => setTimeout(r, 3000));
    pollCount++;
  }

  if (!data || data.status !== "READY" || !data.endpoints || data.endpoints.length === 0) {
    throw new Error("SSL Labs scan did not complete or returned no endpoints");
  }

  const endpoint = data.endpoints[0];

  const supportedTlsVersions = new Set<string>();
  if (endpoint.details && endpoint.details.sessions) {
    // TODO: ignored sessions for now
  }

  // Extract supported protocols
  if (endpoint.details && endpoint.details.protocols) {
    for (const v of endpoint.details.protocols) {
      supportedTlsVersions.add(v.name);
    }
  }

  // Extract cipher suites
  const ciphers = endpoint.details?.suites?.list || [];

  // Compose report
  const { weakDetected: weakProtocolsDetected, score: tlsScore, explanation: tlsExplanation } = analyzeTlsVersions(Array.from(supportedTlsVersions));

  const { weakCount, total, score: cipherScore, explanation: cipherExplanation } = analyzeCiphers(ciphers);

  return {
    supportsTlsVersions: Array.from(supportedTlsVersions),
    weakProtocolsDetected,
    ciphersSummary: {
      total,
      weak: weakCount,
      strong: total - weakCount
    },
    detailsUrl: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(domain)}`
  };
}

async function fetchDnsRecords(domain: string): Promise<DnsRecord[] | null> {
  try {
    const resp = await fetchJson(`${DNS_OVER_HTTPS}${encodeURIComponent(domain)}&type=DNSKEY`, 10000);

    if (resp && Array.isArray(resp.Answer)) {
      return resp.Answer.map((a: any) => ({ type: String(a.type), host: domain, value: String(a.data), ttl: a.TTL }));
    }

    // fallback if no Answer array
    return null;
  } catch (e) {
    return null;
  }
}

async function performTlsHandshake(domain: string): Promise<TlsHandshakeInfo> {
  // We try to open a TLS connection via fetch with signal timeout 10s to get info
  // Since fetch API does not expose TLS info, we will attempt a TLS 1.2+ request
  // We'll try HTTPS HEAD request and parse server cert info from response headers

  try {
    // We do a fetch to https://domain with timeout
    const url = `https://${domain}`;
    const res = await safeFetch(url, { method: "HEAD", timeoutMs: 10000 });

    // We can't access cipher suite or protocol version directly from fetch in Bun
    // Fallback: parse TLS version from custom header if present (unlikely)
    // Instead, just mark success

    return {
      protocolVersion: null,
      cipherSuite: null,
      sessionResumed: false,
      serverCertificates: [],
    };
  } catch (e) {
    return {
      protocolVersion: null,
      cipherSuite: null,
      sessionResumed: false,
      serverCertificates: [],
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

function calculateComplianceScore(tlsScore: number, cipherScore: number): ComplianceScores {
  // Weighted average: TLS 60%, Cipher 40%
  const overall = Math.round((tlsScore * 0.6) + (cipherScore * 0.4));
  return {
    tlsSupportScore: tlsScore,
    cipherStrengthScore: cipherScore,
    overall,
    grade: scoreToGrade(overall),
  };
}

function generateRecommendations(sslScan: SslScanReport, compliance: ComplianceScores): Recommendation[] {
  const recs: Recommendation[] = [];
  if (sslScan.weakProtocolsDetected) {
    recs.push({
      issue: "Weak SSL/TLS protocols supported",
      severity: "high",
      suggestion: "Disable SSLv3, TLS 1.0, and TLS 1.1 protocols; enable only TLS 1.2 and TLS 1.3 for better security.",
    });
  }
  if (sslScan.ciphersSummary.weak > 0) {
    recs.push({
      issue: "Presence of weak cipher suites",
      severity: "high",
      suggestion: `Remove weak cipher suites such as RC4, DES, NULL, EXPORT, and ensure TLS uses strong ciphers with minimum 128-bit keys. Found ${sslScan.ciphersSummary.weak} weak ciphers out of ${sslScan.ciphersSummary.total}.`,
    });
  }
  if (compliance.overall < 60) {
    recs.push({
      issue: "Overall SSL/TLS compliance is poor",
      severity: "high",
      suggestion: "Review SSL/TLS configurations to meet modern security standards, use well-reviewed configurations from reputable sources.",
    });
  } else if (compliance.overall < 80) {
    recs.push({
      issue: "SSL/TLS compliance is moderate",
      severity: "medium",
      suggestion: "Consider upgrading weak settings and removing legacy protocol support.",
    });
  } else {
    recs.push({
      issue: "Good SSL/TLS compliance",
      severity: "low",
      suggestion: "Configuration is generally secure; keep updated and monitor for vulnerabilities.",
    });
  }

  return recs;
}

export async function previewAudit(domain: string): Promise<PreviewResult | { error: string }> {
  // Validate domain
  const check = validateExternalUrl(domain.startsWith("https://") || domain.startsWith("http://") ? domain : `https://${domain}`);
  if ("error" in check) return { error: check.error };

  const hostname = check.url.hostname;

  try {
    const sslScan = await fetchSslScan(hostname);

    const tlsSummary = sslScan.supportsTlsVersions.length > 0 
      ? sslScan.supportsTlsVersions.join(", ")
      : "No TLS version info available";

    const recommendations = [];
    if (sslScan.weakProtocolsDetected) {
      recommendations.push({
        issue: "Weak SSL/TLS protocols detected",
        severity: "high",
        suggestion: "Disable SSLv3 and TLS 1.0/1.1; use only TLS 1.2 and 1.3 for security."
      });
    }
    if (sslScan.ciphersSummary.weak > 0) {
      recommendations.push({
        issue: "Weak ciphers detected",
        severity: "medium",
        suggestion: "Remove weak cipher suites (RC4, DES, NULL)."
      });
    }

    return {
      domain: hostname,
      preview: true,
      tlsSupportSummary: tlsSummary,
      recommendations,
      note: "Preview provides TLS version summary and basic recommendations. Pay for full compliance audit combining multiple data sources.",
    };
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Preview analysis failed: ${msg}` };
  }
}

export async function fullAudit(domain: string): Promise<AuditResult | { error: string }> {
  const check = validateExternalUrl(domain.startsWith("https://") || domain.startsWith("http://") ? domain : `https://${domain}`);
  if ("error" in check) return { error: check.error };
  const hostname = check.url.hostname;

  // Run in parallel: sslScan, dnsRecords, tlsHandshake
  try {
    const [sslScan, dnsRecords, tlsHandshake] = await Promise.all([
      fetchSslScan(hostname),
      fetchDnsRecords(hostname),
      performTlsHandshake(hostname),
    ]);

    // Compute scores
    const { weakDetected, score: tlsScore, explanation: tlsExplanation } = analyzeTlsVersions(sslScan.supportsTlsVersions);
    const { weakCount, total, score: cipherScore, explanation: cipherExplanation } = analyzeCiphers(sslScan.ciphersSummary.total > 0 ? sslScan.ciphersSummary.total > 0 ? sslScan.ciphersSummary : undefined : undefined);

    // But reuse cipherScore from sslScan
    const complianceScores = calculateComplianceScore(tlsScore, sslScan.ciphersSummary ? ((sslScan.ciphersSummary.strong / sslScan.ciphersSummary.total) * 100) : 0);

    // Compose explanation
    const explanation = `TLS versions analysis: ${tlsExplanation} Cipher suites analysis: ${cipherExplanation}`;

    const recommendations = generateRecommendations(sslScan, complianceScores);

    return {
      domain: hostname,
      sslScan,
      dnsRecords,
      tlsHandshake,
      complianceScores,
      recommendations,
      explanation,
    };
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Full audit failed: ${msg}` };
  }
}
