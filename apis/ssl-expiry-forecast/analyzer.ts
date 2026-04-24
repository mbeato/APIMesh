import { safeFetch } from "../../shared/ssrf";

// Interfaces for structured results

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface DomainSslForecast {
  domain: string;
  expiryDate: string | null; // ISO date string or null if unknown
  expiryDays: number | null; // days until expiry or null
  dnsARecords: string[]; // IPv4 addresses from DNS A records
  certTransparencyEntries?: number; // count of CT log entries (only full)
  ctFirstSeen?: string | null; // ISO date first seen in CT logs
  ctLastSeen?: string | null; // ISO date last seen in CT logs
  score: number; // 0-100
  grade: string; // A-F letter grade
  recommendations: Recommendation[];
  details: string; // human-readable explanation
}

export interface SslExpiryForecastResult {
  results: DomainSslForecast[];
}

export interface SslExpiryForecastPreviewResult {
  results: (Pick<DomainSslForecast, "domain" | "expiryDate" | "expiryDays" | "dnsARecords" | "score" | "grade" | "recommendations" | "details">)[];
}

const CT_LOG_API = "https://crt.sh/";
const DNS_GOOGLE_RESOLVE = "https://dns.google/resolve";

// Grade thresholds
function getGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

// Helper: safe fetch with 10s timeout
async function safeFetchWithTimeout(url: string, options: RequestInit = {}): Promise<Response> {
  return safeFetch(url, { ...options, timeoutMs: 10000 });
}

// Fetch DNS A records (IPv4) using Google DNS over HTTPS
async function fetchDnsARecords(domain: string): Promise<string[]> {
  try {
    const url = `${DNS_GOOGLE_RESOLVE}?name=${encodeURIComponent(domain)}&type=A`;
    const res = await safeFetchWithTimeout(url);
    if (!res.ok) throw new Error(`DNS query failed with status ${res.status}`);
    const data = await res.json();
    if (!data.Answer) return [];
    const ips: string[] = [];
    for (const ans of data.Answer) {
      if (ans.type === 1 && typeof ans.data === "string") {
        ips.push(ans.data);
      }
    }
    return ips;
  } catch {
    return [];
  }
}

// Fetch latest SSL certificate info from crt.sh for a domain
async function fetchLatestCertInfo(domain: string): Promise<{
  expiryDate: string | null;
} | null> {
  try {
    // crt.sh returns JSON for output=json
    const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
    const res = await safeFetchWithTimeout(url);
    if (!res.ok) {
      return null;
    }
    const text = await res.text();
    if (text === "[]") return null;

    const certs = JSON.parse(text);
    if (!Array.isArray(certs) || certs.length === 0) return null;

    // Sort certs by not_after descending to get latest
    certs.sort((a: any, b: any) => {
      const dateA = new Date(a.not_after).getTime();
      const dateB = new Date(b.not_after).getTime();
      return dateB - dateA;
    });

    const latest = certs[0];
    if (!latest.not_after) return null;

    return { expiryDate: new Date(latest.not_after).toISOString() };
  } catch {
    return null;
  }
}

// Fetch certificate transparency info: count of entries, earliest and latest seen
async function fetchCertTransparencyLogStats(domain: string): Promise<{
  entryCount: number;
  firstSeen: string | null;
  lastSeen: string | null;
} | null> {
  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;

    const res = await safeFetchWithTimeout(url);
    if (!res.ok) throw new Error(`CT API returned status ${res.status}`);

    const text = await res.text();
    if (!text || text === "[]") return null;

    const certs = JSON.parse(text);
    if (!Array.isArray(certs) || certs.length === 0) return null;

    // Extract dates
    const dates = certs
      .map((c: any) => {
        try {
          return new Date(c.not_before);
        } catch {
          return null;
        }
      })
      .filter((d: Date | null) => d !== null);

    if (dates.length === 0) return null;

    const minDate = new Date(Math.min(...dates.map((d) => d!.getTime())));
    const maxDate = new Date(Math.max(...dates.map((d) => d!.getTime())));

    return {
      entryCount: certs.length,
      firstSeen: minDate.toISOString(),
      lastSeen: maxDate.toISOString(),
    };
  } catch {
    return null;
  }
}

// Calculate score based on days to expiry and CT log presence
function calculateScore(
  expiryDays: number | null,
  ctEntryCount: number | null
): number {
  let score = 100;

  if (expiryDays === null) {
    score -= 50; // missing expiry info
  } else if (expiryDays <= 14) {
    score -= 80; // very urgent
  } else if (expiryDays <= 30) {
    score -= 50; // urgent
  } else if (expiryDays <= 90) {
    score -= 20; // warning
  }

  if (ctEntryCount === null) {
    score -= 20; // unknown CT log data
  } else if (ctEntryCount < 1) {
    score -= 30; // no CT entries (possible transparency failure)
  }

  if (score < 0) score = 0;
  if (score > 100) score = 100;

  return score;
}

// Compose human-readable recommendations based on score and data
function generateRecommendations(
  expiryDays: number | null,
  ctEntryCount: number | null
): Recommendation[] {
  const recs: Recommendation[] = [];

  if (expiryDays === null) {
    recs.push({
      issue: "NoExpiryInfo",
      severity: 70,
      suggestion: "SSL expiry date information not available; verify your SSL certificate configuration.",
    });
  } else if (expiryDays <= 14) {
    recs.push({
      issue: "ExpiryImminent",
      severity: 100,
      suggestion: "SSL certificate expires very soon; renew immediately to avoid downtime.",
    });
  } else if (expiryDays <= 30) {
    recs.push({
      issue: "ExpirySoon",
      severity: 80,
      suggestion: "Plan SSL certificate renewal soon to avoid service interruption.",
    });
  } else if (expiryDays <= 90) {
    recs.push({
      issue: "ExpiryUpcoming",
      severity: 40,
      suggestion: "Consider scheduling SSL renewal within the next 3 months.",
    });
  }

  if (ctEntryCount === null) {
    recs.push({
      issue: "NoCTInfo",
      severity: 60,
      suggestion: "Certificate transparency log data unavailable; ensure certificates are logged for security.",
    });
  } else if (ctEntryCount === 0) {
    recs.push({
      issue: "NotInCT",
      severity: 90,
      suggestion: "No certificate transparency log entries found; consider using publicly logged certificates.",
    });
  } else {
    recs.push({
      issue: "MonitorCT",
      severity: 20,
      suggestion: "Regularly monitor certificate transparency logs for unauthorized certificates.",
    });
  }

  return recs;
}

// Main forecast function
/**
 * Forecast SSL expiry and DNS info for multiple domains
 * @param domains List of domain names
 * @param isPreview Whether this is a free preview (less detail, more timeout)
 * @returns Forecast results
 */
export async function forecastSslExpiry(
  domains: string[],
  isPreview: boolean
): Promise<SslExpiryForecastResult | SslExpiryForecastPreviewResult> {
  // Limit concurrency to avoid long waits, but run in parallel

  // For each domain fetch:
  // - DNS A records
  // - Latest cert expiry date
  // - CT logs info (only for full, skip or mock for preview)

  // Timeout for preview is longer (20s), for paid 10s per fetch

  const results: DomainSslForecast[] = [];

  // Helper to fetch for a single domain
  async function analyzeDomain(domain: string): Promise<DomainSslForecast> {
    // Parallel fetch DNS and cert info

    const dnsP = fetchDnsARecords(domain);
    const certInfoP = fetchLatestCertInfo(domain);

    // For CT logs, only fetch in full mode
    const ctP = isPreview ? Promise.resolve(null) : fetchCertTransparencyLogStats(domain);

    let dnsARecords: string[] = [];
    let certInfo: { expiryDate: string | null } | null = null;
    let ctInfo: { entryCount: number; firstSeen: string | null; lastSeen: string | null } | null = null;

    try {
      [dnsARecords, certInfo, ctInfo] = await Promise.all([dnsP, certInfoP, ctP]);
    } catch {
      // Partial failures allowed
      dnsARecords = [];
      certInfo = null;
      ctInfo = null;
    }

    // Calculate expiry days
    let expiryDays: number | null = null;
    if (certInfo && certInfo.expiryDate) {
      const now = new Date();
      const expiry = new Date(certInfo.expiryDate);
      expiryDays = Math.max(0, Math.round((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)));
    }

    // Calculate score
    const score = calculateScore(expiryDays, ctInfo?.entryCount ?? null);
    const grade = getGrade(score);

    // Generate recommendations
    const recommendations = generateRecommendations(expiryDays, ctInfo?.entryCount ?? null);

    // Compose details
    const detailsParts = [];
    if (certInfo && certInfo.expiryDate) {
      detailsParts.push(`SSL certificate expires on ${certInfo.expiryDate}`);
    } else {
      detailsParts.push("SSL expiry date not available");
    }

    if (dnsARecords.length > 0) {
      detailsParts.push(`DNS A record(s) found: ${dnsARecords.join(", ")}`);
    } else {
      detailsParts.push("No DNS A records found");
    }

    if (ctInfo) {
      detailsParts.push(`Certificate transparency log entries: ${ctInfo.entryCount}`);
      if (ctInfo.firstSeen) {
        detailsParts.push(`First seen: ${ctInfo.firstSeen}`);
      }
      if (ctInfo.lastSeen) {
        detailsParts.push(`Last seen: ${ctInfo.lastSeen}`);
      }
    }

    return {
      domain,
      expiryDate: certInfo?.expiryDate ?? null,
      expiryDays,
      dnsARecords,
      certTransparencyEntries: ctInfo?.entryCount,
      ctFirstSeen: ctInfo?.firstSeen ?? null,
      ctLastSeen: ctInfo?.lastSeen ?? null,
      score,
      grade,
      recommendations,
      details: detailsParts.join("; "),
    };
  }

  // Validate domain count to prevent too large input
  if (domains.length === 0) {
    throw new Error("No domains provided");
  }
  if (isPreview && domains.length > 5) {
    throw new Error("Maximum 5 domains allowed for preview");
  }
  if (!isPreview && domains.length > 10) {
    throw new Error("Maximum 10 domains allowed for full check");
  }

  // Run all analyses with Promise.all
  try {
    const forecasts = await Promise.all(domains.map((d) => analyzeDomain(d)));
    return { results: forecasts };
  } catch (e) {
    throw e;
  }
}
