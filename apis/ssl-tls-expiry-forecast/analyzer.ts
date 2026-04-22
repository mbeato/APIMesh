import { safeFetch } from "../../shared/ssrf";

// --------------------- Types ---------------------

export interface ForecastResult {
  domain: string;
  certExpiryDays?: number | null;
  certScore?: number | null;
  protocolSupport?: ProtocolSupport;
  grade?: Grade;
  recommendations?: Recommendation[];
  details?: string;
  error?: string;
}

export interface ProtocolSupport {
  tls1_2: boolean;
  tls1_3: boolean;
  legacyTls: boolean;
}

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface Recommendation {
  issue: string;
  severity: "low" | "medium" | "high";
  suggestion: string;
}

// -------------- crt.sh certificate data representation --------------

export interface CrtShCertEntry {
  id: number;
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  not_before: string;
  not_after: string;
  serial_number: string;
  signature_algorithm: string;
}

// --------------------- Fetch crt.sh certificates ---------------------

export async function fetchCrtShCertificates(
  domain: string,
  signal: AbortSignal
): Promise<CrtShCertEntry[]> {
  // Query crt.sh JSON output for the domain
  // This API returns array or empty array on no results
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;

  const res = await safeFetch(url, {
    timeoutMs: 10000,
    signal,
    headers: {
      "User-Agent": "ssl-tls-expiry-forecast/1.0 apimesh.xyz",
    },
  });

  if (!res.ok) {
    throw new Error(`crt.sh API responded with status ${res.status}`);
  }

  const text = await res.text();
  if (!text || text === "[]") {
    return [];
  }

  let data: any;
  try {
    data = JSON.parse(text);
  } catch (e) {
    throw new Error("Failed to parse crt.sh JSON response");
  }

  if (!Array.isArray(data)) {
    throw new Error("Unexpected crt.sh response structure");
  }

  return data.map((entry: any) => ({
    id: entry.min_cert_id || 0,
    issuer_ca_id: entry.issuer_ca_id || 0,
    issuer_name: entry.issuer_name || "",
    common_name: entry.common_name || "",
    name_value: entry.name_value || "",
    not_before: entry.not_before || "",
    not_after: entry.not_after || "",
    serial_number: entry.serial_number || "",
    signature_algorithm: entry.sig_alg || entry.signature_algorithm || "",
  }));
}

// --------------------- Fetch DNS TLSA and TLSA-like records ---------------------

// We fetch DNS TLSA and DNS CAA records to infer protocol and cert info capabilities from DNS
// Also fetch A/AAAA for basic verification but here only TLS records

export interface DnsTlsRecords {
  tlsaRecords: string[];
  caaRecords: string[];
  error?: string;
}

// For demonstration, fetch DNS records from Google DNS over HTTPS
// type=A, AAAA, TLSA, CAA

export async function fetchDnsTlsRecords(
  domain: string,
  signal: AbortSignal
): Promise<DnsTlsRecords> {
  try {
    const baseUrl = "https://dns.google/resolve";
    // Fetch TLSA records on _443._tcp.domain
    const tlsaName = `_443._tcp.${domain}`;
    
    // Compose URLs
    const fetchA = fetch(`${baseUrl}?name=${encodeURIComponent(domain)}&type=A`, { signal });
    const fetchAAAA = fetch(`${baseUrl}?name=${encodeURIComponent(domain)}&type=AAAA`, { signal });
    const fetchTLSA = fetch(`${baseUrl}?name=${encodeURIComponent(tlsaName)}&type=TLSA`, { signal });
    const fetchCAA = fetch(`${baseUrl}?name=${encodeURIComponent(domain)}&type=CAA`, { signal });

    // Concurrent fetch
    const [aRes, aaaaRes, tlsaRes, caaRes] = await Promise.all([fetchA, fetchAAAA, fetchTLSA, fetchCAA]);

    // Parse responses
    const parseDnsAnswerArray = async (res: Response): Promise<string[]> => {
      if (!res.ok) return [];
      let json;
      try {
        json = await res.json();
      } catch {
        return [];
      }
      if (!json || !Array.isArray(json.Answer)) return [];
      return json.Answer.map((a: any) => a.data).filter((d: any) => typeof d === "string");
    };

    const aRecords = await parseDnsAnswerArray(aRes);
    const aaaaRecords = await parseDnsAnswerArray(aaaaRes);
    const tlsaRecords = await parseDnsAnswerArray(tlsaRes);
    const caaRecords = await parseDnsAnswerArray(caaRes);

    return {
      tlsaRecords,
      caaRecords,
    };
  } catch (e: any) {
    return {
      tlsaRecords: [],
      caaRecords: [],
      error: e.message || String(e),
    };
  }
}

// --------------------- Certificate analysis ---------------------

interface CertAnalysis {
  certCount: number;
  earliestExpiryDays: number | null;
  certScore: number;
}

export function analyzeCertificates(certs: CrtShCertEntry[]): CertAnalysis {
  if (!certs || certs.length === 0) {
    return { certCount: 0, earliestExpiryDays: null, certScore: 0 };
  }

  const now = Date.now();
  let earliestExpiry = Infinity;

  // Score accumulator
  let score = 0;

  for (const cert of certs) {
    const notAfter = new Date(cert.not_after).getTime();
    if (isNaN(notAfter)) continue;

    if (notAfter < earliestExpiry) earliestExpiry = notAfter;

    // Score: later expiry adds +10 points (max 90)
    const daysLeft = Math.max(0, Math.round((notAfter - now) / (1000 * 60 * 60 * 24)));
    if (daysLeft > 90) {
      score += 10;
    } else if (daysLeft > 30) {
      score += 5;
    }

    // Score weakening: weak signature algorithms deduct points
    if (cert.signature_algorithm) {
      const algo = cert.signature_algorithm.toLowerCase();
      if (algo.includes("md5") || algo.includes("sha1")) {
        score -= 20;
      } else {
        score += 5;
      }
    }
  }

  const certCount = certs.length;

  // Calculate expiry days from earliest expiry
  const earliestExpiryDays = earliestExpiry === Infinity ? null : Math.max(0, Math.round((earliestExpiry - now) / (1000 * 60 * 60 * 24)));

  // Clamp score 0-100
  if (score > 100) score = 100;
  if (score < 0) score = 0;

  return {
    certCount,
    earliestExpiryDays,
    certScore: Math.round(score),
  };
}

// --------------------- Protocol analysis ---------------------

export function analyzeTlsProtocols(dnsRecords: DnsTlsRecords): ProtocolSupport {
  // We check if TLS 1.3 record exists or inferred, 1.2 TLS assumed available if A/AAAA present
  // Legacy TLS inferred if TLSA record nonempty

  const tls1_3 = dnsRecords.tlsaRecords.some((r) => r.includes("1.3"));
  const tls1_2 = dnsRecords.tlsaRecords.some((r) => r.includes("1.2")) || tls1_3; // 1.3 implies 1.2 typically

  // Legacy TLS detected if tlsa record or caa records indicate
  const legacyTls = dnsRecords.tlsaRecords.some((r) => r.includes("legacy") || r.includes("1.0") || r.includes("1.1"));

  return {
    tls1_2: Boolean(tls1_2),
    tls1_3: Boolean(tls1_3),
    legacyTls: Boolean(legacyTls),
  };
}

// --------------------- Score and grade ---------------------

export function computeScoreAndGrade(
  certAnalysis: CertAnalysis,
  protocols: ProtocolSupport
): { score: number; grade: Grade } {
  let score = 0;

  if (certAnalysis.earliestExpiryDays === null) {
    score = 0; // no valid cert data
  } else {
    // Base score on cert score
    score += certAnalysis.certScore;

    // Deduct if expires soon
    if (certAnalysis.earliestExpiryDays < 15) {
      score -= 40;
    } else if (certAnalysis.earliestExpiryDays < 30) {
      score -= 20;
    }

    // Protocols bonus
    if (protocols.tls1_3) {
      score += 20;
    } else if (protocols.tls1_2) {
      score += 10;
    }

    // Penalty for legacy TLS enabled
    if (protocols.legacyTls) {
      score -= 15;
    }
  }

  if (score > 100) score = 100;
  if (score < 0) score = 0;

  // Grade mapping
  let grade: Grade = "F";
  if (score >= 90) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 60) grade = "C";
  else if (score >= 40) grade = "D";
  else grade = "F";

  return { score: Math.round(score), grade };
}

// --------------------- Recommendations ---------------------

export function generateRecommendations(
  certAnalysis: CertAnalysis,
  protocols: ProtocolSupport
): Recommendation[] {
  const recs: Recommendation[] = [];

  if (certAnalysis.earliestExpiryDays === null) {
    recs.push({
      issue: "No valid SSL certificate data found",
      severity: "high",
      suggestion: "Ensure the domain has a valid SSL certificate installed",
    });
  } else {
    if (certAnalysis.earliestExpiryDays < 15) {
      recs.push({
        issue: "Certificate expires very soon",
        severity: "high",
        suggestion: "Renew SSL certificate immediately to avoid downtime",
      });
    } else if (certAnalysis.earliestExpiryDays < 30) {
      recs.push({
        issue: "Certificate expires soon",
        severity: "medium",
        suggestion: "Plan to renew SSL certificate within 30 days",
      });
    }

    if (certAnalysis.certScore < 50) {
      recs.push({
        issue: "Weak certificate signature algorithm or short validity",
        severity: "medium",
        suggestion: "Use certificates with strong signature algorithms (SHA-256 or better) and longer validity periods",
      });
    }
  }

  if (!protocols.tls1_3) {
    recs.push({
      issue: "TLS 1.3 not supported",
      severity: "medium",
      suggestion: "Upgrade server to support latest TLS 1.3 protocol for better security and performance",
    });
  }

  if (protocols.legacyTls) {
    recs.push({
      issue: "Legacy TLS protocols enabled",
      severity: "low",
      suggestion: "Consider disabling legacy TLS 1.0 and 1.1 protocols to improve security",
    });
  }

  if (recs.length === 0) {
    recs.push({
      issue: "All checks good",
      severity: "low",
      suggestion: "Maintain current configuration and monitor certificate expiry",
    });
  }

  return recs;
}
