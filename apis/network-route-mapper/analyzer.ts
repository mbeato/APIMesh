import { safeFetch, validateExternalUrl } from "../../shared/ssrf";

// Types
export interface ASNHop {
  asn: number;
  name: string;
  country: string;
  latencyMs?: number;
  suspicious?: boolean;
}

export interface GeoLocation {
  country: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
}

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface NetworkRouteResult {
  target: string;
  detectedIp: string;
  asnHops: ASNHop[];
  geolocation: GeoLocation;
  summaryScore: number; // 0-100
  grade: string; // letter grade A-F
  details: string;
  recommendations: Recommendation[];
}

export interface NetworkRoutePreviewResult {
  target: string;
  detectedIp: string;
  asnHops: ASNHop[];
  geolocation: {
    country?: string;
    city?: string;
  };
  summaryScore: number;
  grade: string;
  details: string;
  recommendations: Recommendation[];
}

// Helper: letter grade from score
function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

// Internal: Query multiple ASN databases (no keys) in parallel
async function fetchAsnInfo(ip: string, signal: AbortSignal): Promise<ASNHop | null> {
  // Use publicly available free APIs
  // We'll try ipinfo.io (limited but no key needed), and whois.arin.net

  // We call ipinfo.io/json?token= - no token allowed so skip
  // Instead use https://ipapi.co/{ip}/json/ no API key needed

  try {
    const ipapiUrl = `https://ipapi.co/${encodeURIComponent(ip)}/json/`;
    const res = await safeFetch(ipapiUrl, { signal, timeoutMs: 10000 });
    if (!res.ok) return null;
    const data = await res.json();
    if (!data || !data.org) return null;
    const asnInfo = data.org as string; // e.g. "AS15169 Google LLC"

    const m = asnInfo.match(/^AS(\d+)\s(.+)$/i);
    if (!m) return null;
    const asn = parseInt(m[1], 10);
    const name = m[2];
    const country = data.country || "";

    return { asn, name, country };
  } catch {
    return null;
  }
}

// Internal: Geolocation from IP using ip-api.com and ipinfo.io fallback
async function fetchGeolocation(ip: string, signal: AbortSignal): Promise<GeoLocation> {
  // try ip-api.com first (no key for http)
  try {
    const res = await safeFetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,regionName,city,lat,lon`, {
      signal,
      timeoutMs: 10000,
    });
    const data = await res.json();
    if (data.status === "success") {
      return {
        country: data.country || "",
        region: data.regionName || undefined,
        city: data.city || undefined,
        latitude: data.lat || undefined,
        longitude: data.lon || undefined,
      };
    }
  } catch {
    // ignored
  }
  // fallback ipinfo.io (limited info)
  try {
    const res = await safeFetch(`https://ipinfo.io/${encodeURIComponent(ip)}/json`, {
      signal,
      timeoutMs: 10000,
    });
    const data = await res.json();
    return {
      country: data.country || "",
      region: data.region || undefined,
      city: data.city || undefined,
    };
  } catch {
    return {
      country: "",
    };
  }
}

// Internal: Resolve domain to IP (IPv4 preferred)
async function resolveTargetToIp(target: string, signal: AbortSignal): Promise<string> {
  // if IP literal, return as is
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(target)) {
    return target;
  }
  // Use DNS over HTTPS via Google
  try {
    const res = await safeFetch(
      `https://dns.google/resolve?name=${encodeURIComponent(target)}&type=A`,
      { signal, timeoutMs: 10000 }
    );
    if (!res.ok) throw new Error(`DNS lookup failed status ${res.status}`);
    const json = await res.json();
    if (json && Array.isArray(json.Answer) && json.Answer.length > 0) {
      for (const ans of json.Answer) {
        if (ans.type === 1 && ans.data) {
          return ans.data;
        }
      }
    }
  } catch (e) {
    // fallback or failure
  }
  // fallback: check if IPv6 literal
  if (/^([\da-fA-F:]+)$/.test(target)) {
    return target;
  }
  throw new Error("Unable to resolve target to an IP address");
}

// Internal: Perform traceroute using public API (ip-api.com traceroute endpoint) - no official free API, we simulate
// Given limitations, we simulate traceroute with ping to up to 5 ASNs
async function fetchTracerouteAsnHops(ip: string, signal: AbortSignal): Promise<ASNHop[]> {
  // Due to no available real traceroute API to public, we get the AS path via ip-api.com as path
  // ip-api.com offers as info but no route path, simulate with just single hop
  // Another option: use https://api.bgpview.io/ip/{ip} to get prefixes and peers

  try {
    // Use bgpview.io API to get prefix prefixes and AS path
    const resPrefix = await safeFetch(`https://api.bgpview.io/ip/${encodeURIComponent(ip)}`, {
      signal,
      timeoutMs: 10000,
    });
    if (!resPrefix.ok) return [];
    const data = await resPrefix.json();

    if (!data || !data.data) return [];

    // Extract AS_PATH from prefixes
    const prefixes = data.data.prefixes;
    if (!prefixes || prefixes.length === 0) return [];

    // Get AS path - bgpview returns list of ASNs (example: [15169, 3356])
    // Extract unique ASNs from routes
    const asnSet = new Set<number>();

    for (const prefix of prefixes) {
      if (prefix.as_path && Array.isArray(prefix.as_path)) {
        for (const asnStr of prefix.as_path) {
          const asnNum = parseInt(String(asnStr), 10);
          if (!isNaN(asnNum)) asnSet.add(asnNum);
        }
      }
    }

    const asns = Array.from(asnSet).slice(0, 7); // limit 7 hops

    // For each ASN get org and country info using BGPView AS API
    const hopPromises = asns.map(async (asn) => {
      try {
        const resAsn = await safeFetch(`https://api.bgpview.io/asn/${asn}`, {
          signal,
          timeoutMs: 10000,
        });
        if (!resAsn.ok) return null;
        const asnData = await resAsn.json();
        if (!asnData || !asnData.data) return null;
        const { asn: asnNumber, name, country_code } = asnData.data;
        return {
          asn: asnNumber,
          name: name || "Unknown",
          country: country_code || "",
          latencyMs: undefined,
          suspicious: false,
        };
      } catch {
        return null;
      }
    });

    const hops = await Promise.all(hopPromises);
    return hops.filter((h): h is ASNHop => h !== null);
  } catch {
    return [];
  }
}

// Internal: Analyze ASN hops to detect suspicious ASNs (example heuristics)
function analyzeSuspiciousAsns(hops: ASNHop[]): ASNHop[] {
  // Example heuristic: flag ASNs from countries considered risky or private ASNs

  // Private ASN ranges: 64512-65534
  const privateAsnRange = (asn: number) => asn >= 64512 && asn <= 65534;
  // Suspicious country codes
  const suspiciousCountries = new Set(["RU", "CN", "IR", "KP", "SY"]);

  return hops.map((hop) => {
    const suspicious = privateAsnRange(hop.asn) || suspiciousCountries.has(hop.country.toUpperCase());
    return {
      ...hop,
      suspicious,
    };
  });
}

// Internal: Calculate overall score and recommendations
function calculateScoreAndRecommendations(
  result: {
    asnHops: ASNHop[];
    geolocation: GeoLocation;
  }
): { score: number; recommendations: Recommendation[]; details: string } {
  let score = 100;
  const recs: Recommendation[] = [];

  // Deduct points for suspicious ASNs
  const suspiciousHops = result.asnHops.filter((h) => h.suspicious);
  if (suspiciousHops.length > 0) {
    score -= suspiciousHops.length * 25;
    recs.push({
      issue: `Detected ${suspiciousHops.length} suspicious ASN${suspiciousHops.length > 1 ? "s" : ""} in route`,
      severity: 80,
      suggestion:
        "Consider rerouting or investigating networks with suspicious ASNs to enhance security.",
    });
  }

  // Deduct points for private ASNs in path
  const privateHopCount = result.asnHops.filter((h) => h.asn >= 64512 && h.asn <= 65534).length;
  if (privateHopCount > 0) {
    score -= privateHopCount * 15;
    recs.push({
      issue: `Network includes ${privateHopCount} private ASN hop${privateHopCount > 1 ? "s" : ""}`,
      severity: 60,
      suggestion:
        "Private ASNs may indicate VPNs or tunnels; consider clarity on path for trusted networks.",
    });
  }

  // Score bias for geolocation (penalize if unknown)
  if (!result.geolocation.country) {
    score -= 20;
    recs.push({
      issue: "Geolocation unavailable",
      severity: 50,
      suggestion: "No geolocation data found; verify IP address and try again.",
    });
  }

  // Grade based threshold
  if (score < 0) score = 0;

  // Compose details text
  const detailsParts = [];
  if (suspiciousHops.length > 0) {
    detailsParts.push(
      `Suspicious ASNs detected (${suspiciousHops
        .map((h) => `AS${h.asn}`)
        .join(", ")}), potential security risk.`
    );
  }
  if (privateHopCount > 0) {
    detailsParts.push(`Private ASNs in network path may indicate VPN or tunnels.`);
  }
  detailsParts.push(`Geolocation: ${result.geolocation.country || "unknown"}`);
  if (score > 85) {
    detailsParts.push("Route considered stable and secure.");
  } else if (score > 60) {
    detailsParts.push("Route has minor warnings.");
  } else {
    detailsParts.push("Route has significant concerns.");
  }

  return {
    score,
    recommendations: recs,
    details: detailsParts.join(" "),
  };
}

// Public preview function
export async function previewNetworkRoute(
  target: string
): Promise<NetworkRoutePreviewResult> {
  const signal = AbortSignal.timeout(20000);
  let ip = "";
  try {
    ip = await resolveTargetToIp(target, signal);
  } catch (e) {
    throw new Error("Failed to resolve target IP: " + (e instanceof Error ? e.message : String(e)));
  }

  // Simple ASN info
  let asnHop: ASNHop | null = null;
  try {
    asnHop = await fetchAsnInfo(ip, signal);
  } catch {
    asnHop = null;
  }

  const asnHops = asnHop ? [asnHop] : [];

  // Simple geolocation
  let geolocation = { country: "", city: undefined };
  try {
    const geo = await fetchGeolocation(ip, signal);
    geolocation.country = geo.country;
    geolocation.city = geo.city;
  } catch {
    geolocation = { country: "" };
  }

  // Calculate basic score
  const score = asnHops.length > 0 && geolocation.country ? 80 : 50;

  const grade = scoreToGrade(score);

  const recommendations: Recommendation[] = [];
  if (score < 80) {
    recommendations.push({
      issue: "Limited route info",
      severity: 50,
      suggestion: "Use the paid endpoint for comprehensive route discovery and analysis.",
    });
  }

  return {
    target,
    detectedIp: ip,
    asnHops,
    geolocation,
    summaryScore: score,
    grade,
    details: "Preview provides limited ASN and geolocation info; upgrade for full audit.",
    recommendations,
  };
}

// Public paid route analysis function
export async function analyzeNetworkRoute(
  target: string
): Promise<NetworkRouteResult> {
  const signal = AbortSignal.timeout(10000);

  // Validate and resolve IP
  let ip: string;
  try {
    const val = validateExternalUrl(target);
    if ("error" in val) {
      throw new Error(`Invalid target: ${val.error}`);
    }
    ip = await resolveTargetToIp(target, signal);
  } catch (e) {
    throw new Error("Failed to resolve target IP: " + (e instanceof Error ? e.message : String(e)));
  }

  // Perform multiple requests in parallel (ASN hops, traceroute, geolocation)
  const [asnInfo, tracerouteHops, geoLoc] = await Promise.all([
    fetchAsnInfo(ip, signal),
    fetchTracerouteAsnHops(ip, signal),
    fetchGeolocation(ip, signal),
  ]);

  // Compose ASN hops list combining traceroute and direct ASN info
  let asnHops: ASNHop[] = [...tracerouteHops];

  if (asnInfo) {
    // Add as entry if not duplicated
    if (!asnHops.find((h) => h.asn === asnInfo.asn)) {
      asnHops.unshift(asnInfo);
    }
  }

  // Analyze suspicious hops
  asnHops = analyzeSuspiciousAsns(asnHops);

  // Score and recommendations
  const { score, recommendations, details } = calculateScoreAndRecommendations({
    asnHops,
    geolocation: geoLoc,
  });

  // Compose grade
  const grade = scoreToGrade(score);

  // Compose structured geolocation to include city, region if available
  const geolocation: GeoLocation = {
    country: geoLoc.country,
  };

  if (geoLoc.region) geolocation.region = geoLoc.region;
  if (geoLoc.city) geolocation.city = geoLoc.city;
  if (geoLoc.latitude) geolocation.latitude = geoLoc.latitude;
  if (geoLoc.longitude) geolocation.longitude = geoLoc.longitude;

  return {
    target,
    detectedIp: ip,
    asnHops,
    geolocation,
    summaryScore: score,
    grade,
    details,
    recommendations,
  };
}
