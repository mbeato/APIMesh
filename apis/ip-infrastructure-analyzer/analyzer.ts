import { safeFetch } from "../../shared/ssrf";

// ---------- TYPES ----------

export interface AsnInfo {
  asn: number;
  name: string;
  isp: string;
  country: string; // ISO 2-letter code
}

export interface GeoLocation {
  country: string; // ISO 2-letter
  region: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
}

export interface RoutingInfo {
  bgpPrefix: string | null;
  bgpOrigin: string | null;
  bgpAsPath: number[]; // path of ASNs
  isBogon: boolean;
}

export interface Recommendation {
  issue: string;
  severity: number; // 0-100, higher is more severe
  suggestion: string;
}

export interface IpInfrastructureInfo {
  ip: string;
  asn: AsnInfo | null;
  geolocation: GeoLocation;
  routing: RoutingInfo;
  score: number; // 0-100 overall
  grade: string; // Letter grade A-F
  explanation: string;
  recommendations: Recommendation[];
}

export interface IpBasicPreview {
  ip: string;
  asn: { asn: number; isp: string; country: string } | null;
  country: string | null;
  city: string | null;
  region: string | null;
  note: string;
}

export type IpAnalysisResult = IpInfrastructureInfo | { error: string };
export type IpPreviewResult = IpBasicPreview | { error: string };

// ---------- CONSTANTS ----------

const BOGON_RANGES: string[] = [
  // Common bogon prefixes (not exhaustive)
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4",
];

const LETTER_GRADES = ["F", "D", "C", "B", "A"];

// ---------- UTILS ----------

function ipToUint32(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let num = 0;
  for (const p of parts) {
    const n = Number(p);
    if (isNaN(n) || n < 0 || n > 255) return null;
    num = (num << 8) + n;
  }
  return num >>> 0; // force uint32
}

function cidrToRange(cidr: string): [number, number] | null {
  // For IPv4 only, returns start and end uint32
  const [ip, maskStr] = cidr.split("/");
  const mask = Number(maskStr);
  if (mask < 0 || mask > 32) return null;
  const ipNum = ipToUint32(ip);
  if (ipNum === null) return null;
  const maskBits = mask === 0 ? 0 : (0xffffffff << (32 - mask)) >>> 0;
  const start = ipNum & maskBits;
  const end = start + (2 ** (32 - mask)) - 1;
  return [start, end];
}

function isIpInCidr(ip: string, cidr: string): boolean {
  const ipNum = ipToUint32(ip);
  if (ipNum === null) return false;
  const range = cidrToRange(cidr);
  if (!range) return false;
  const [start, end] = range;
  return ipNum >= start && ipNum <= end;
}

function isBogonIp(ip: string): boolean {
  for (const cidr of BOGON_RANGES) {
    if (isIpInCidr(ip, cidr)) return true;
  }
  return false;
}

function gradeFromScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

// Validate IP basic format (IPv4 only for now)
function isValidIPv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (!/^(\d+)$/.test(p)) return false;
    const n = Number(p);
    if (n < 0 || n > 255) return false;
  }
  return true;
}

// ---------- SERVICE LOGIC ----------

// Fetch ASN/ISP and basic info from https://ipinfo.io/
async function fetchIpinfo(ip: string, signal: AbortSignal): Promise<{ asn: AsnInfo | null; geo: GeoLocation | null }> {
  const url = `https://ipinfo.io/${ip}/json`;
  try {
    const res = await safeFetch(url, {
      signal,
      timeoutMs: 10_000,
      headers: { "User-Agent": "ip-infrastructure-analyzer/1.0 apimesh.xyz" },
    });
    if (!res.ok) {
      throw new Error(`ipinfo.io HTTP ${res.status}`);
    }
    const data = await res.json();

    // ASN structure from ipinfo: { asn: {asn, name, country} }
    let asnInfo: AsnInfo | null = null;
    if (data.asn && data.asn.asn) {
      asnInfo = {
        asn: Number(data.asn.asn.replace(/^AS/i, "")) || 0,
        name: data.asn.name || "",
        isp: data.org || data.asn.name || "",
        country: data.country || "",
      };
    }

    let geo: GeoLocation | null = null;
    if (data.loc) {
      const [latStr, lonStr] = data.loc.split(",");
      geo = {
        country: data.country || "",
        region: data.region || null,
        city: data.city || null,
        lat: latStr ? Number(latStr) : null,
        lon: lonStr ? Number(lonStr) : null,
      };
    } else {
      geo = {
        country: data.country || "",
        region: data.region || null,
        city: data.city || null,
        lat: null,
        lon: null,
      };
    }

    return { asn: asnInfo, geo };
  } catch (e) {
    return { asn: null, geo: null };
  }
}

// Fetch routing info from https://stat.ripe.net/data/announced-prefixes/data.json?resource=IP
async function fetchRoutingInfo(ip: string, signal: AbortSignal): Promise<RoutingInfo> {
  // RIPEstat announced prefixes
  try {
    const ripeUrl = `https://stat.ripe.net/data/announced-prefixes/data.json?resource=${ip}`;
    const res = await safeFetch(ripeUrl, { signal, timeoutMs: 10_000 });
    if (!res.ok) throw new Error(`RIPEstat Announced Prefixes failed code ${res.status}`);
    const data = await res.json();

    const prefixes = data.data && Array.isArray(data.data.prefixes) ? data.data.prefixes : [];
    // Find most specific prefix that covers IP
    // Because announced prefixes are arbitrary length, find exact match
    let matchedPrefix: string | null = null;

    // We check for first prefix containing IP by checking if IP is within prefix CIDR
    for (const prefixEntry of prefixes) {
      const prefix = prefixEntry.prefix;
      if (prefix && isIpInCidr(ip, prefix)) {
        // Prefer longer prefixes
        if (!matchedPrefix || prefix.length > matchedPrefix.length) matchedPrefix = prefix;
      }
    }

    if (!matchedPrefix) {
      // No matching prefix
      return {
        bgpPrefix: null,
        bgpOrigin: null,
        bgpAsPath: [],
        isBogon: isBogonIp(ip),
      };
    }

    // Fetch BGP origin info from RIPE stat routeinfo
    const routeinfoUrl = `https://stat.ripe.net/data/route-data/data.json?resource=${matchedPrefix}`;
    const routeRes = await safeFetch(routeinfoUrl, { signal, timeoutMs: 10_000 });
    if (!routeRes.ok) throw new Error(`RIPEstat RouteData failed ${routeRes.status}`);
    const routeData = await routeRes.json();

    let origin = null;
    let asPath: number[] = [];
    if (routeData.data && Array.isArray(routeData.data.routes) && routeData.data.routes.length > 0) {
      // Take the first route
      const r = routeData.data.routes[0];
      if (r && r.as_path && Array.isArray(r.as_path)) {
        asPath = r.as_path.map((asn: string) => Number(asn)).filter((n: number) => !isNaN(n));
        origin = asPath.length > 0 ? asPath[asPath.length - 1].toString() : null;
      }
    }

    return {
      bgpPrefix: matchedPrefix,
      bgpOrigin: origin,
      bgpAsPath: asPath,
      isBogon: isBogonIp(ip),
    };
  } catch (e) {
    return { bgpPrefix: null, bgpOrigin: null, bgpAsPath: [], isBogon: isBogonIp(ip) };
  }
}

// ---------- SCORING & RECOMMENDATION ----------

function computeScore(info: IpInfrastructureInfo): { score: number; grade: string } {
  let score = 100;
  const recs: Recommendation[] = [];

  // Deduct for bogon IP
  if (info.routing.isBogon) {
    score -= 50;
    recs.push({ issue: "IP belongs to a bogon (reserved/private/unrouted) range.", severity: 90, suggestion: "Use a publicly routable IP address to avoid routing issues and blacklisting." });
  }

  // ASN info missing penalty
  if (!info.asn) {
    score -= 40;
    recs.push({ issue: "No ASN/ISP information found.", severity: 70, suggestion: "Check IP allocation or use alternative IP info providers." });
  } else {
    // ASN numeric sanity
    if (info.asn.asn === 0) {
      score -= 20;
      recs.push({ issue: "ASN number is zero, unexpected.", severity: 50, suggestion: "Verify IP allocation correctness and ISP details." });
    }
  }

  // Geo location quality
  if (!info.geolocation.country) {
    score -= 25;
    recs.push({ issue: "Geolocation country data missing.", severity: 60, suggestion: "Geolocation data may be incomplete or IP not well known." });
  }

  // Check BGP origin
  if (!info.routing.bgpOrigin) {
    score -= 30;
    recs.push({ issue: "BGP origin AS not found.", severity: 65, suggestion: "Check routing tables for accurate BGP information." });
  }

  // Cap score boundaries
  if (score < 0) score = 0;
  if (score > 100) score = 100;

  const grade = gradeFromScore(score);

  // Combine explanation
  const lines = [];
  if (info.asn) {
    lines.push(`ASN: AS${info.asn.asn} (${info.asn.name}) ISP: ${info.asn.isp} Country: ${info.asn.country}`);
  } else {
    lines.push("ASN data unavailable.");
  }
  lines.push(`Geolocation: ${info.geolocation.city ?? "N/A"}, ${info.geolocation.region ?? "N/A"}, ${info.geolocation.country || "N/A"}`);
  if (info.routing.bgpPrefix) {
    lines.push(`BGP Prefix: ${info.routing.bgpPrefix} Origin AS: ${info.routing.bgpOrigin ?? "N/A"} AS Path Length: ${info.routing.bgpAsPath.length}`);
  } else {
    lines.push("BGP routing info unavailable.");
  }
  if (info.routing.isBogon) lines.push("Warning: IP is in a bogon range (private or reserved). Routing problems likely.");

  return { score, grade };
}

// Generate final recommendations (merge existing plus new)
function finalizeRecommendations(
  base: Recommendation[],
  computed: Recommendation[],
): Recommendation[] {
  const combined = [...base];
  for (const c of computed) {
    if (!combined.find(r => r.issue === c.issue)) combined.push(c);
  }
  if (combined.length === 0) {
    combined.push({
      issue: "No issues detected.",
      severity: 0,
      suggestion: "Maintain current IP allocation and monitor regularly.",
    });
  }
  return combined;
}

// Main analyzeIp function
export async function analyzeIp(ip: string): Promise<IpAnalysisResult> {
  // Validate IP basic format (only IPv4 supported now)
  if (!isValidIPv4(ip)) {
    return { error: "Invalid or unsupported IP address format (IPv4 only)." };
  }

  try {
    // Use AbortSignal.timeout(10000) per requirements
    const signal = AbortSignal.timeout(10_000);

    // Fetch info in parallel
    const [ipinfoRes, routingRes] = await Promise.all([
      fetchIpinfo(ip, signal),
      fetchRoutingInfo(ip, signal),
    ]);

    const ipInfo: IpInfrastructureInfo = {
      ip,
      asn: ipinfoRes.asn,
      geolocation: ipinfoRes.geo || { country: "", region: null, city: null, lat: null, lon: null },
      routing: routingRes,
      score: 0,
      grade: "F",
      explanation: "",
      recommendations: [],
    };

    // Compute score and grade
    const { score, grade } = computeScore(ipInfo);
    ipInfo.score = score;
    ipInfo.grade = grade;

    // Recommendations from computeScore
    ipInfo.recommendations = finalizeRecommendations(ipInfo.recommendations, []);

    ipInfo.explanation = `IP ${ip} analysis: ASN ${ipinfoRes.asn?.asn ?? "unknown"}, ISP: ${ipinfoRes.asn?.isp ?? "unknown"}. ` +
      `Geolocation: ${ipinfoRes.geo?.city ?? ""}, ${ipinfoRes.geo?.region ?? ""}, ${ipinfoRes.geo?.country ?? ""}. ` +
      (routingRes.isBogon ? "Note: IP is a bogon (private or reserved). " : "") +
      `BGP Prefix: ${routingRes.bgpPrefix ?? "unknown"}, Origin AS: ${routingRes.bgpOrigin ?? "unknown"}. Score: ${score}. Grade: ${grade}.`;

    return ipInfo;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Failed to analyze IP: ${msg}` };
  }
}

// Preview version for free endpoint – basic ASN and geo only, no routing or scoring, generous timeout
export async function previewAnalyzeIp(ip: string): Promise<IpPreviewResult> {
  if (!isValidIPv4(ip)) {
    return { error: "Invalid or unsupported IP address format (IPv4 only)." };
  }

  try {
    const signal = AbortSignal.timeout(20_000);
    const ipinfoRes = await fetchIpinfo(ip, signal);
    return {
      ip,
      asn: ipinfoRes.asn
        ? { asn: ipinfoRes.asn.asn, isp: ipinfoRes.asn.isp, country: ipinfoRes.asn.country }
        : null,
      country: ipinfoRes.geo?.country || null,
      city: ipinfoRes.geo?.city || null,
      region: ipinfoRes.geo?.region || null,
      note: "Preview gives only partial info. Pay for full report.",
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Failed to fetch preview info: ${msg}` };
  }
}
