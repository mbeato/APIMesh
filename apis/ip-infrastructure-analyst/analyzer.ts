import { safeFetch } from "../../shared/ssrf";
import { IPInfrastructureAnalysis, ASNInfo, ISPInfo, GeoLocation, RoutingInfo, Recommendation } from "./types";
import { validateIp, gradeFromScore, createRecommendation, dedupeRecommendations, clampScore } from "./utils";

const TIMEOUT_MS = 10000;

/**
 * External API endpoints used:
 * - ipinfo.io (free tier allows caching but no API key needed) for ASN, ISP, and Geo
 * - ip-api.com for detailed API: as, isp, geo, proxy info
 * - bgpview.io API for routing info (prefixes, AS path etc)
 * 
 * We execute these in parallel and merge the results.
 */

interface IpApiResponse {
  status: string; // success or fail
  country?: string;
  regionName?: string;
  city?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
  isp?: string;
  org?: string;
  as?: string; // e.g. AS12345 Some ASN Name
  query?: string;
  message?: string;
}

interface IpInfoResponse {
  ip: string;
  hostname: string | null;
  city: string | null;
  region: string | null;
  country: string | null;
  loc: string | null; // lat,long
  org: string | null; // e.g. AS12345 name
  postal: string | null;
  timezone: string | null;
  readme: string;
}

interface BgpViewASNData {
  asn: number;
  name: string;
  description: string;
  country_code: string;
  prefix_count: number;
  peers: number;
  prefixes: string[];
  path: number[]; // AS path simplified
}

/**
 * Validate and parse ASN string from various sources
 * e.g. "AS12345 Some ASN Name"
 */
function parseAsnString(asnStr: string | undefined): number | null {
  if (!asnStr) return null;
  const match = asnStr.match(/AS(\d+)/i);
  if (match) return Number(match[1]);
  return null;
}

// Fetch from ip-api.com json endpoint
async function fetchFromIpApi(ip: string): Promise<IpApiResponse | null> {
  try {
    const res = await safeFetch(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city,lat,lon,timezone,isp,org,as,query,message`, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as IpApiResponse;
    if (data.status !== "success") return null;
    return data;
  } catch {
    return null;
  }
}

// Fetch from ipinfo.io (limited) free API
async function fetchFromIpInfo(ip: string): Promise<IpInfoResponse | null> {
  try {
    const res = await safeFetch(`https://ipinfo.io/${ip}/json`, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { "User-Agent": "ip-infrastructure-analyst/1.0 apimesh.xyz" },
    });
    if (!res.ok) return null;
    const data = (await res.json()) as IpInfoResponse;
    return data;
  } catch {
    return null;
  }
}

// Fetch routing info from bgpview.io API
async function fetchRoutingInfo(asn: number | null, ip: string): Promise<RoutingInfo> {
  if (!asn) {
    return {
      originAS: null,
      ASPath: [],
      prefixes: [],
    };
  }
  try {
    const res = await safeFetch(`https://api.bgpview.io/asn/${asn}`, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return { originAS: asn, ASPath: [], prefixes: [] };
    const data = await res.json();
    const body = data.data;
    if (!body) return { originAS: asn, ASPath: [], prefixes: [] };

    // Extract prefix list
    const prefixes = [] as string[];
    if (Array.isArray(body.prefixes_ipv4)) {
      for (const p of body.prefixes_ipv4) {
        if (typeof p.prefix === "string") {
          prefixes.push(p.prefix);
        }
      }
    }
    if (Array.isArray(body.prefixes_ipv6)) {
      for (const p of body.prefixes_ipv6) {
        if (typeof p.prefix === "string") {
          prefixes.push(p.prefix);
        }
      }
    }

    // AS Path is not directly provided by bgpview API,
    // simulate as just [asn]

    // Peers count
    const peersCount = typeof body.peers === "number" ? body.peers : undefined;

    return {
      originAS: asn,
      ASPath: [asn],
      prefixes,
      peersCount,
    };
  } catch {
    return { originAS: asn, ASPath: [], prefixes: [] };
  }
}

/**
 * Main analysis function. Combines multiple public APIs to produce enriched IP data.
 * Returns full analysis including scoring, grading, recommendations, explanation.
 */
export async function analyzeIpInfrastructure(ip: string): Promise<IPInfrastructureAnalysis> {
  const startTime = performance.now();

  const inputIpTrimmed = ip.trim();
  const isValidIp = validateIp(inputIpTrimmed);

  if (!isValidIp) {
    const duration = Math.round(performance.now() - startTime);
    return {
      inputIP: inputIpTrimmed,
      isValidIp: false,
      asnInfo: {
        asn: null,
        name: null,
        country: null,
        description: null,
      },
      ispInfo: {
        isp: null,
        organization: null,
        asn: null,
        queryIp: inputIpTrimmed,
      },
      geoLocation: {
        country: null,
        region: null,
        city: null,
        latitude: null,
        longitude: null,
        timezone: null,
        postalCode: null,
      },
      routingInfo: {
        originAS: null,
        ASPath: [],
        prefixes: [],
      },
      score: 0,
      grade: "F",
      recommendations: [createRecommendation(
        "Invalid IP format",
        10,
        "Verify the input IP address is correctly formatted IPv4 or IPv6."
      )],
      details: "The provided IP address is invalid and could not be analyzed.",
    };
  }

  // Fetch all data in parallel
  const [ipApiData, ipInfoData] = await Promise.all([
    fetchFromIpApi(inputIpTrimmed),
    fetchFromIpInfo(inputIpTrimmed),
  ]);

  // Extract ASN from ip-api first, fallback ipinfo.org
  let asn: number | null = null;
  let asnName: string | null = null;
  let asnCountry: string | null = null;
  let asnDescription: string | null = null;

  if (ipApiData && ipApiData.as) {
    asn = parseAsnString(ipApiData.as);
    if (ipApiData.as) {
      asnName = ipApiData.as.replace(/^AS\d+\s*/i, "");
    }
    asnCountry = ipApiData.country || null;
  } else if (ipInfoData && ipInfoData.org) {
    asn = parseAsnString(ipInfoData.org);
    if (ipInfoData.org) {
      asnName = ipInfoData.org.replace(/^AS\d+\s*/i, "");
    }
    asnCountry = ipInfoData.country || null;
  }

  // ISP and organization
  const isp = ipApiData?.isp ?? null;
  const org = ipApiData?.org ?? ipInfoData?.org ?? null;

  // Geo location
  const geo: GeoLocation = {
    country: ipApiData?.country ?? ipInfoData?.country ?? null,
    region: ipApiData?.regionName ?? ipInfoData?.region ?? null,
    city: ipApiData?.city ?? ipInfoData?.city ?? null,
    latitude: ipApiData?.lat ?? (ipInfoData?.loc ? Number(ipInfoData.loc.split(",")[0]) : null) ?? null,
    longitude: ipApiData?.lon ?? (ipInfoData?.loc ? Number(ipInfoData.loc.split(",")[1]) : null) ?? null,
    timezone: ipApiData?.timezone ?? ipInfoData?.timezone ?? null,
    postalCode: ipInfoData?.postal ?? null,
  };

  // Fetch routing info
  const routingInfo = await fetchRoutingInfo(asn, inputIpTrimmed);

  // Compose ASN info
  const asnInfo: ASNInfo = {
    asn: asn,
    name: asnName,
    country: asnCountry,
    description: asnDescription,
    routeCount: routingInfo.prefixes.length,
  };

  // Compose ISP info
  const ispInfo: ISPInfo = {
    isp: isp,
    organization: org,
    asn: asn,
    queryIp: inputIpTrimmed,
  };

  // -- Scoring & recommendations --

  // Score components (0-100 each)
  const scores: number[] = [];
  const recs: Recommendation[] = [];

  // IP validity already checked, skip

  // ASN presence and plausibility
  if (asn && asn > 0) {
    scores.push(90);
  } else {
    scores.push(20);
    recs.push(createRecommendation("Missing or unrecognized ASN", 7, "The IP could not be associated with a valid ASN. Verify the IP address or try again later."));
  }

  // ISP info presence
  if (isp || org) {
    scores.push(85);
  } else {
    scores.push(40);
    recs.push(createRecommendation("ISP or Organization info missing", 6, "ISP or organization data not found; consider using alternate IP data sources or checking for IP privacy features."));
  }

  // Geo completeness
  const geoScore = geo.country && geo.city ? 80 : 50;
  scores.push(geoScore);
  if (!geo.country) {
    recs.push(createRecommendation("Geolocation country missing", 6, "No country information found for this IP. Geolocation accuracy is limited or IP is unallocated."));
  }

  // Routing info
  if (routingInfo.originAS) {
    scores.push(85);
  } else {
    scores.push(30);
    recs.push(createRecommendation("Routing information incomplete", 6, "No routing or prefix details found for ASN. BGP data may be delayed or the IP is from a small/nonpublic network."));
  }

  // Count of prefixes affects score
  if (routingInfo.prefixes.length === 0) {
    recs.push(createRecommendation("No IP prefixes announced for ASN", 5, "ASN has no announced IP prefixes, which may indicate a reserved or private network."));
  }

  // Compose average score
  let finalScore = combineScores(scores);

  // Adjust score for suspicious cases
  if (asn && asn > 0 && geo.country === null) {
    finalScore = Math.min(finalScore, 70);
  }

  // Clamp final
  finalScore = clampScore(finalScore);

  // Assign grade
  const grade = gradeFromScore(finalScore);

  // Add explanation
  const details = [
    `IP: ${inputIpTrimmed} is ${isValidIp ? "valid" : "invalid"}.`,
    asn
      ? `ASN: AS${asn} (${asnName ?? "Unknown name"}) in ${asnCountry ?? "Unknown country"}.`
      : "ASN info unavailable.",
    ispInfo.isp ? `ISP: ${ispInfo.isp}` : "ISP info unavailable.",
    geo.country ? `Located in ${geo.city ?? "a city"}, ${geo.region ?? "a region"}, ${geo.country}.` : "Geolocation data not available.",
    routingInfo.originAS ? `Routing prefix count: ${routingInfo.prefixes.length}.` : "Routing info missing.",
    `Overall risk and confidence score is ${finalScore}, grade ${grade}.`,
  ].join(" ");

  // Final recommendations dedup
  const finalRecs = dedupeRecommendations(recs);

  const durationMs = Math.round(performance.now() - startTime);

  return {
    inputIP: inputIpTrimmed,
    isValidIp,
    asnInfo,
    ispInfo,
    geoLocation: geo,
    routingInfo,
    score: finalScore,
    grade,
    recommendations: finalRecs,
    details,
  };
}
