import { safeFetch } from "../../shared/ssrf";

// -----------------------------
// Types
// -----------------------------

export interface EnrichmentResult {
  ip: string;
  asn: string; // e.g., AS15169
  isp: string; // ISP or org name
  country: string; // Country name
  city: string; // City name or empty string
  latitude: number | null;
  longitude: number | null;
  routing: {
    prefix: string; // CIDR block
    routeOrigin: string; // Origin ASN for route
  };
  score: number; // 0-100 numeric
  grade: "A" | "B" | "C" | "D" | "F";
  details: string; // Human readable analysis
  recommendations: Array<{ issue: string; severity: number; suggestion: string }>;
  checkedAt: string; // ISO timestamp
}

export interface PreviewResult {
  ip: string;
  country: string;
  isp: string;
  asn: string;
  checkedAt: string;
}

// -----------------------------
// Utils
// -----------------------------

function isValidIp(ip: string): boolean {
  // Simple regex checks for IPv4 and IPv6
  const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  const ipv6 = /^([\da-f]{1,4}:){7}[\da-f]{1,4}$/i;
  const ipv6Short = /^[\da-f]{0,4}(:[\da-f]{0,4}){1,7}$/i;
  if (ipv4.test(ip)) return true;
  if (ipv6.test(ip)) return true;
  if (ipv6Short.test(ip)) return true;
  return false;
}

function gradeFromScore(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

function calculateScore(
  asnRank: number, // 0-50
  geoConfidence: number, // 0-30
  routingStability: number, // 0-20
  suspiciousFlags: number // negative precision, 0-30, deduct
): number {
  let score = asnRank + geoConfidence + routingStability - suspiciousFlags;
  if (score > 100) score = 100;
  if (score < 0) score = 0;
  return Math.round(score);
}

// -----------------------------
// Data source fetchers
// -----------------------------

// All calls timed out after 10 seconds
const TIMEOUT = 10_000;

interface IpApiResponse {
  status: string;
  country: string;
  countryCode: string;
  regionName: string;
  city: string;
  lat: number;
  lon: number;
  isp: string;
  org: string;
  query: string;
  as?: string; // e.g. "AS15169 Google LLC"
  // other fields omitted
}

async function fetchIpApi(ip: string, signal: AbortSignal): Promise<IpApiResponse | null> {
  try {
    const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,query,as`;
    const res = await safeFetch(url, { signal, timeoutMs: TIMEOUT });
    if (!res.ok) return null;
    const data = (await res.json()) as IpApiResponse;
    if (data.status !== "success") return null;
    return data;
  } catch {
    return null;
  }
}

interface IpinfoOrgResponse {
  ip: string;
  hostname?: string;
  city?: string;
  region?: string;
  country?: string;
  loc?: string; // "lat,lon"
  org?: string; // e.g. "AS15169 Google LLC"
  postal?: string;
  timezone?: string;
  readme?: string;
}

async function fetchIpinfoOrg(ip: string, signal: AbortSignal): Promise<IpinfoOrgResponse | null> {
  try {
    const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json`;
    const res = await safeFetch(url, { signal, timeoutMs: TIMEOUT });
    if (!res.ok) return null;
    const data = (await res.json()) as IpinfoOrgResponse;
    if (data.ip !== ip) return null;
    return data;
  } catch {
    return null;
  }
}

interface WhoisXmlApiResponse {
  WhoisRecord?: {
    registryData?: {
      nameServers?: {
        hostNames?: string[];
      };
      createdDateNormalized?: string;
      updatedDateNormalized?: string;
      expiresDateNormalized?: string;
      rawText?: string;
    };
    registrant?: {
      organization?: string;
    };
  };
}

// WhoisXMLAPI endpoint: but API keys are forbidden, so we skip
// For demonstration, we won't call this

// -----------------------------
// Main enrich functions
// -----------------------------

/**
 * Preview endpoint: quick summary with limited data
 */
export async function previewEnrichIp(
  ip: string,
  signal: AbortSignal
): Promise<PreviewResult | { error: string }> {
  if (!isValidIp(ip)) return { error: "Invalid IP address format" };

  const asnFetch = fetchIpApi(ip, signal);
  const ipinfoFetch = fetchIpinfoOrg(ip, signal);

  let asnData: IpApiResponse | null = null;
  let ipinfoData: IpinfoOrgResponse | null = null;

  try {
    // Promise.all with separate error catches to tolerate partial fail
    [asnData, ipinfoData] = await Promise.all([asnFetch, ipinfoFetch]);
  } catch (e) {
    // pass, partial may still be available
  }

  // Basic checks
  if (!asnData && !ipinfoData) {
    return { error: "Failed to fetch data from free public IP info providers" };
  }

  // Compose preview data with fallbacks
  const country = asnData?.country || ipinfoData?.country || "Unknown";
  const isp = asnData?.isp || ipinfoData?.org || "Unknown ISP";
  const asnRaw = asnData?.as || ipinfoData?.org || "Unknown ASN";
  const asn = asnRaw.split(" ")[0] || "Unknown ASN";

  return {
    ip,
    country,
    isp,
    asn,
    checkedAt: new Date().toISOString(),
  };
}

/**
 * Full enrich endpoint: combines multiple sources, parses, scores, and recommends
 */
export async function fullEnrichIp(
  ip: string,
  signal: AbortSignal
): Promise<EnrichmentResult | { error: string }> {
  if (!isValidIp(ip)) return { error: "Invalid IP address format" };

  // Start parallel fetches
  const ipApiPromise = fetchIpApi(ip, signal);
  const ipinfoPromise = fetchIpinfoOrg(ip, signal);

  // Wait for all results
  let ipApiData: IpApiResponse | null = null;
  let ipinfoData: IpinfoOrgResponse | null = null;

  try {
    [ipApiData, ipinfoData] = await Promise.all([ipApiPromise, ipinfoPromise]);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Failed to fetch IP data: ${msg}` };
  }

  if (!ipApiData && !ipinfoData) {
    return { error: "Could not obtain IP data from any source" };
  }

  // Extract best data for fields
  const asnRaw = ipApiData?.as || ipinfoData?.org || "Unknown ASN";
  const asnMatch = asnRaw.match(/(AS\d+)/i);
  const asn = asnMatch ? asnMatch[1].toUpperCase() : "Unknown ASN";

  const isp = ipApiData?.isp || ipinfoData?.org || "Unknown ISP";
  const country = ipApiData?.country || ipinfoData?.country || "Unknown";
  const city = ipApiData?.city || ipinfoData?.city || "";

  const latitude = ipApiData?.lat ?? null;
  const longitude = ipApiData?.lon ?? null;

  // For routing info fallback, we attempt BGP info from ipinfo (e.g. org field)
  // or from ip-api as fallback
  let routingPrefix = "";
  let routingOrigin = "";

  if (ipinfoData?.loc) {
    // Rough approximation: combined loc with org field to guess route origin
    routingOrigin = asn;
    routingPrefix = "unknown prefix";
  } else if (ipApiData?.as) {
    routingOrigin = asn;
    routingPrefix = "unknown prefix";
  } else {
    routingOrigin = "Unknown";
    routingPrefix = "Unknown";
  }

  // Build analysis details and scoring
  // Heuristic scoring:
  // asnRank: prefer well-known ASNs like Google and popular providers
  // geoConfidence: country and city match (we have single source only, so moderate)
  // routingStability: placeholder for route origin assessment
  // suspiciousFlags: sum of flags such as private IP, unlikely ASN, or inconsistencies

  let asnRank = 30; // base
  const knownLargeAsns = new Set(["AS15169", "AS7922", "AS16509", "AS13335", "AS6939"]);
  if (knownLargeAsns.has(asn)) {
    asnRank = 50;
  } else if (asn.startsWith("AS")) {
    asnRank = 35;
  } else {
    asnRank = 15;
  }

  const geoConfidence = latitude !== null && longitude !== null ? 25 : 10;

  const routingStability = routingOrigin === asn ? 15 : 5;

  // Detect suspicious IPs:
  // private ranges penalty
  const privateIpPatterns = [
    /^10\./,
    /^172\.(1[6-9]|2\d|3[0-1])\./,
    /^192\.168\./,
    /^127\./,
    /^0\./,
    /^::1$/,
    /^fc00:/i,
    /^fe80:/i,
  ];
  let suspiciousFlags = 0;
  if (privateIpPatterns.some((re) => re.test(ip))) {
    suspiciousFlags += 30;
  }

  // Check for mismatch between ASN and ISP names (basic string fuzz)
  if (asn !== "Unknown ASN" && isp !== "Unknown ISP") {
    const asnLower = asn.toLowerCase();
    const ispLower = isp.toLowerCase();
    if (!ispLower.includes(asnLower.replace(/^as/, ""))) {
      // No ASN digits substring in ISP, small penalty
      suspiciousFlags += 10;
    }
  }

  // Calculate total score and convert grade
  const score = calculateScore(asnRank, geoConfidence, routingStability, suspiciousFlags);
  const grade = gradeFromScore(score);

  // Compose human readable explanation
  let details = `IP address ${ip} is assigned to ASN ${asn}, operated by ISP "${isp}".`;
  details += ` Located in ${city ? city + ", " : ""}${country}.`;
  details += ` Latitude ${latitude !== null ? latitude.toFixed(4) : "N/A"}, Longitude ${longitude !== null ? longitude.toFixed(4) : "N/A"}.`;
  details += ` Routing prefix is approx. ${routingPrefix}, route origin ASN ${routingOrigin}.`;

  if (suspiciousFlags > 20) {
    details += " Suspicious IP detected: private or reserved range or inconsistent data.";
  } else if (score > 80) {
    details += " IP is considered reliable and well-known.";
  } else if (score > 50) {
    details += " IP has moderate confidence with minor issues.";
  } else {
    details += " IP shows warning signs; please review details carefully.";
  }

  // Recommendations based on flags
  const recommendations: Array<{ issue: string; severity: number; suggestion: string }> = [];
  if (privateIpPatterns.some((re) => re.test(ip))) {
    recommendations.push({
      issue: "Private or reserved IP range",
      severity: 90,
      suggestion: "Use public routable IP address for external services or monitoring.",
    });
  }

  if (grade === "F" || grade === "D") {
    recommendations.push({
      issue: "Low confidence in IP data",
      severity: 70,
      suggestion: "Verify IP assignment and routing with your ISP or hosting provider.",
    });
  }

  if (recommendations.length === 0) {
    recommendations.push({
      issue: "No issues detected",
      severity: 0,
      suggestion: "No action needed. Maintain monitoring for changes.",
    });
  }

  return {
    ip,
    asn,
    isp,
    country,
    city,
    latitude,
    longitude,
    routing: {
      prefix: routingPrefix,
      routeOrigin: routingOrigin,
    },
    score,
    grade,
    details,
    recommendations,
    checkedAt: new Date().toISOString(),
  };
}
