import { safeFetch, validateExternalUrl } from "../../shared/ssrf";
import type {
  CipherSuiteInfo,
  CertificateTransparencyEntry,
  DnsTlsRecords,
  RiskAssessment,
  RiskRecommendation,
  RiskScore,
  SslProtocolScore
} from "./types";

// Timeout constants
const ABORT_TIMEOUT_MS = 10000;
const LONG_ABORT_TIMEOUT_MS = 15000;

// TLS Protocol list and known deprecated versions
const TLS_PROTOCOLS = [
  { protocol: "SSL 2.0", deprecated: true },
  { protocol: "SSL 3.0", deprecated: true },
  { protocol: "TLS 1.0", deprecated: true },
  { protocol: "TLS 1.1", deprecated: true },
  { protocol: "TLS 1.2", deprecated: false },
  { protocol: "TLS 1.3", deprecated: false },
];

// Weak cipher suites known for vulnerabilities
const WEAK_CIPHERS_NAMES = new Set([
  "RC4", "DES", "3DES", "MD5", "NULL", "EXP", "EXPORT", "LOW", "ANON", "TLS_RSA_WITH_DES_CBC_SHA",
  "TLS_RSA_EXPORT_WITH_RC4_40_MD5"
]);


// Grading helpers
function gradeFromScore(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 50) return "C";
  if (score >= 30) return "D";
  return "F";
}


// Public API: analyze SSL/TLS risk for given hostname
export async function analyzeRisk(hostnameRaw: string): Promise<RiskAssessment | { error: string }> {
  const validated = validateExternalUrl(hostnameRaw);
  if ("error" in validated) return { error: validated.error };

  const hostname = validated.url.hostname;
  const checkedAt = new Date().toISOString();

  try {
    // Run data fetches in parallel with Promise.all
    const [scanData, dnsRecords, ctLogs] = await Promise.all([
      fetchSslScanData(hostname),
      fetchDnsTlsRecords(hostname),
      fetchCtLogs(hostname),
    ]);

    // Analyze protocols
    const protocolsEvaluated = analyzeProtocols(scanData.protocols);

    // Analyze cipher suites
    const weakCiphers = analyzeCipherSuites(scanData.cipherSuites);

    // Analyze CT logs
    const ctIssues = analyzeCtEntries(ctLogs);

    // Analyze DNS TLS data
    const dnsTlsDetails = analyzeDnsTlsRecords(dnsRecords);

    // Compute overall score
    const overallScore = computeOverallScore(protocolsEvaluated, weakCiphers, ctIssues, dnsTlsDetails);

    // Compose human explanation and recommendations
    const { explanation, recommendations } = composeExplanationAndRecommendations(
      protocolsEvaluated,
      weakCiphers,
      ctIssues,
      dnsTlsDetails,
      overallScore
    );

    const result: RiskAssessment = {
      overallScore,
      protocolsEvaluated,
      weakCiphers,
      certTransparencyIssues: ctIssues,
      dnsTlsRecords: dnsTlsDetails,
      recommendations,
      explanation,
      checkedAt,
      targetHost: hostname
    };

    return result;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`Internal analysis failure: ${msg}`);
  }
}



/**
 * Fetch SSL/TLS scan data from public API that aggregates SSL details like protocols and cipher suites.
 * Use a free API such as cryptcheck or TLS survey if available.
 * Simulate with placeholder data here.
 */
async function fetchSslScanData(hostname: string): Promise<{ protocols: string[]; cipherSuites: string[] }> {
  // Example public API: https://tls.imirhil.fr or https://www.ssllabs.com/ssltest/ (no official API)
  // We will use tls.imirhil.fr JSON API

  const url = `https://tls.imirhil.fr/api/v1/json/scan/${hostname}`;

  try {
    const res = await safeFetch(url, { signal: AbortSignal.timeout(ABORT_TIMEOUT_MS) });
    if (!res.ok) throw new Error(`Failed to fetch SSL scan data: HTTP status ${res.status}`);

    const json = await res.json();

    // Example expected: json.protocols: array like ["TLS 1.0", "TLS 1.2", ...]
    // json.cipherSuites: array of cipher suite names

    // Minimal validation
    if (!Array.isArray(json.protocols) || !Array.isArray(json.cipherSuites)) {
      throw new Error("Malformed SSL scan data received.");
    }

    return {
      protocols: json.protocols,
      cipherSuites: json.cipherSuites,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    throw Object.assign(new Error(`Analysis temporarily unavailable: ${msg}`), { status });
  }
}

/**
 * Fetch DNS TLS records (TLSA on _443._tcp etc) and CAA records.
 * Use DNS over HTTPS public resolver API (e.g., Google DNS).
 */
async function fetchDnsTlsRecords(hostname: string): Promise<{ tlsa: string[]; cAA: string[] }> {
  const tlsaPromise = queryDnsRecords(`_443._tcp.${hostname}`, "TLSA");
  const caaPromise = queryDnsRecords(hostname, "CAA");
  const [tlsaRecords, caaRecords] = await Promise.all([tlsaPromise, caaPromise]);
  return {
    tlsa: tlsaRecords,
    cAA: caaRecords,
  };
}

// Query DNS over HTTPS for records of type
async function queryDnsRecords(domain: string, type: string): Promise<string[]> {
  const dnsQueryUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`;
  try {
    const res = await safeFetch(dnsQueryUrl, { signal: AbortSignal.timeout(ABORT_TIMEOUT_MS) });
    if (!res.ok) throw new Error(`DNS query failed: status ${res.status}`);
    const json = await res.json();
    if (!json.Answer || !Array.isArray(json.Answer)) return [];
    // Extract data strings
    return json.Answer.map((a: any) => a.data ?? "").filter((d: string) => d.length > 0);
  } catch (e) {
    // On failure return empty list (safe fail)
    return [];
  }
}


/**
 * Fetch certificate transparency log entries for given hostname.
 * Use public CT log APIs like crt.sh JSON API.
 */
async function fetchCtLogs(hostname: string): Promise<CertificateTransparencyEntry[]> {
  const crtShUrl = `https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`;
  try {
    const res = await safeFetch(crtShUrl, { signal: AbortSignal.timeout(LONG_ABORT_TIMEOUT_MS) });
    if (!res.ok) throw new Error(`Failed to fetch CT logs: HTTP status ${res.status}`);
    const body = await res.text();
    if (!body || body === "[]") return [];
    const entriesRaw = JSON.parse(body);
    if (!Array.isArray(entriesRaw)) return [];

    // Map to CertificateTransparencyEntry[]
    const entries: CertificateTransparencyEntry[] = entriesRaw.map((entry: any) => {
      return {
        loggedAt: entry.entry_timestamp || new Date().toISOString(),
        issuer: entry.issuer_name || "",
        subject: entry.name_value || "",
        isValid: true, // We don't know validity here
        notBefore: entry.not_before || "",
        notAfter: entry.not_after || "",
        signatureAlgorithm: entry.sig_alg || "",
      };
    });
    return entries;
  } catch (e) {
    // On failure return empty list, CT logs optional
    return [];
  }
}


// ----------- Analysis helpers -----------

function analyzeProtocols(observedProtocols: string[]): SslProtocolScore[] {
  // observedProtocols: e.g. ["TLS 1.2", "TLS 1.3", "TLS 1.0"]
  const lowerObserved = observedProtocols.map((p) => p.toUpperCase());

  return TLS_PROTOCOLS.map(({ protocol, deprecated }) => {
    const found = lowerObserved.includes(protocol.toUpperCase());
    const scoreImpact = found
      ? deprecated
        ? 30 // deprecated protocol seen, bad score
        : 100 // supported protocol
      : 0; // not supported

    const explanation = found
      ? deprecated
        ? `${protocol} is present but deprecated and insecure.`
        : `${protocol} is supported and considered secure.`
      : `${protocol} is not supported.`;

    return {
      protocol,
      deprecated,
      scoreImpact,
      explanation,
    };
  });
}

function analyzeCipherSuites(suites: string[]): CipherSuiteInfo[] {
  // suites: array of cipher suite string names
  const mapped = suites.map((name) => {
    const upperName = name.toUpperCase();
    const deprecated = [...WEAK_CIPHERS_NAMES].some((w) => upperName.includes(w));
    const strengthScore = deprecated ? 20 : 90; // simplified
    const explanation = deprecated
      ? `${name} is weak or deprecated cipher suite potentially vulnerable to attacks.`
      : `${name} is considered a strong cipher suite.`;
    return {
      name,
      strengthScore,
      deprecated,
      explanation,
    };
  });

  // Return only weak cipher suites for focus
  return mapped.filter((c) => c.deprecated);
}

function analyzeCtEntries(entries: CertificateTransparencyEntry[]): string[] {
  // Identify issues with CT logs
  const issues: string[] = [];

  if (!entries.length) {
    issues.push("No certificate transparency log entries found for this hostname.");
    return issues;
  }

  const now = new Date();
  let hasExpiredCert = false;

  for (const e of entries) {
    try {
      if (e.notAfter) {
        const notAfterDate = new Date(e.notAfter);
        if (notAfterDate < now) {
          hasExpiredCert = true;
          issues.push(`CT log shows expired certificate valid until ${e.notAfter}.`);
          break;
        }
      }
    } catch {
      // ignore parse errors
    }
  }

  if (hasExpiredCert === false) {
    issues.push("Certificate transparency logs appear clean with no expired certs detected.");
  }

  return issues;
}

function analyzeDnsTlsRecords(records: { tlsa: string[]; cAA: string[] }): DnsTlsRecords {
  let explanation = "";
  if (records.tlsa.length === 0) {
    explanation += "No TLSA (DANE) DNS records found. This may allow MITM attacks if TLS validation is weak. ";
  } else {
    explanation += `Found TLSA DNS records (${records.tlsa.length}) indicating attempt to harden TLS security via DANE. `;
  }

  if (records.cAA.length === 0) {
    explanation += "No Certificate Authority Authorization (CAA) DNS records present, which could prevent unauthorized issuance. ";
  } else {
    explanation += `Found CAA records (${records.cAA.length}) restricting certificate issuers. `;
  }

  return {
    tlsa: records.tlsa,
    cAA: records.cAA,
    dANE: [],
    explanation
  };
}

function computeOverallScore(
  protocols: SslProtocolScore[],
  weakCiphers: CipherSuiteInfo[],
  ctIssues: string[],
  dnsTls: DnsTlsRecords
): RiskScore {
  let score = 100;

  // Penalize deprecated protocols seen
  for (const p of protocols) {
    if (p.deprecated && p.scoreImpact > 0) {
      score -= 35; // heavy penalty
    }
  }

  // Penalize weak cipher suites found, 5 points each up to 30 max
  score -= Math.min(weakCiphers.length * 5, 30);

  // Penalize no CT logs
  if (ctIssues.length === 1 && ctIssues[0].includes("No certificate transparency")) {
    score -= 20;
  }

  // Penalize no DNS TLSA or CAA records
  if (dnsTls.tlsa.length === 0) {
    score -= 10;
  }
  if (dnsTls.cAA.length === 0) {
    score -= 8;
  }

  // Clamp score
  if (score < 0) score = 0;
  if (score > 100) score = 100;

  return {
    numeric: score,
    grade: gradeFromScore(score),
  };
}

function composeExplanationAndRecommendations(
  protocols: SslProtocolScore[],
  weakCiphers: CipherSuiteInfo[],
  ctIssues: string[],
  dnsTls: DnsTlsRecords,
  overall: RiskScore
): { explanation: string; recommendations: RiskRecommendation[] } {
  const explanations: string[] = [];
  const recommendations: RiskRecommendation[] = [];

  // Protocols explanation
  protocols.forEach((p) => explanations.push(p.explanation));

  // Weak ciphers explanation
  if (weakCiphers.length > 0) {
    explanations.push(`Detected ${weakCiphers.length} weak or deprecated cipher suites.`);
    weakCiphers.forEach((c) => {
      recommendations.push({
        issue: `Weak cipher detected: ${c.name}`,
        severity: 8,
        suggestion: `Disable or remove cipher suite ${c.name} from server configuration.`
      });
    });
  } else {
    explanations.push("No weak cipher suites detected.");
  }

  // CT log issues
  ctIssues.forEach((issue) => {
    explanations.push(issue);
    if (issue.includes("No certificate transparency log entries")) {
      recommendations.push({
        issue: "Missing CT logs",
        severity: 6,
        suggestion: "Obtain certificates from CAs that log to certificate transparency to improve trust and detection of misissuance."
      });
    }
    if (issue.toLowerCase().includes("expired certificate")) {
      recommendations.push({
        issue: "Expired certificate in CT logs",
        severity: 9,
        suggestion: "Renew or replace expired certificates promptly to maintain security."
      });
    }
  });

  // DNS TLS explanation
  explanations.push(dnsTls.explanation);

  if (dnsTls.tlsa.length === 0) {
    recommendations.push({
      issue: "Missing TLSA DNS records",
      severity: 5,
      suggestion: "Configure DNS TLSA records for DANE to enable DNS-based TLS authentication if applicable."
    });
  }
  if (dnsTls.cAA.length === 0) {
    recommendations.push({
      issue: "Missing CAA DNS records",
      severity: 4,
      suggestion: "Add CAA DNS records to specify authorized certificate authorities and reduce risk of unauthorized issuance."
    });
  }

  // Overall explanation
  explanations.push(`Overall security grade is ${overall.grade} with a score of ${overall.numeric} out of 100.`);

  if (overall.numeric >= 90) {
    recommendations.push({
      issue: "Good overall security",
      severity: 1,
      suggestion: "Maintain current secure configuration and regularly monitor for new vulnerabilities."
    });
  } else if (overall.numeric >= 70) {
    recommendations.push({
      issue: "Moderate security issues detected",
      severity: 5,
      suggestion: "Review deprecated protocols and weak ciphers; update server configuration accordingly."
    });
  } else {
    recommendations.push({
      issue: "Significant security risks",
      severity: 8,
      suggestion: "Urgently update TLS configuration to disable deprecated protocols and weak ciphers, and review certificate transparency compliance."
    });
  }

  return {
    explanation: explanations.join(" "),
    recommendations,
  };
}
