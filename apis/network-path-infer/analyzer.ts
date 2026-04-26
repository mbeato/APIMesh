import type { NetworkPathInferResult, AsnHop, GeoLocation, Recommendation } from "./types";
import { safeFetch } from "../../shared/ssrf";

const ABORT_TIMEOUT_MS = 10000;

// Fetch ASN info from public API for given IP
async function fetchAsnInfo(ip: string, signal: AbortSignal): Promise<{ asn: number | null; asnName: string | null }> {
  try {
    const url = `https://api.iptoasn.com/v1/as/ip/${encodeURIComponent(ip)}`;
    const res = await safeFetch(url, { signal });
    if (!res.ok) throw new Error(`IPtoASN API responded with status ${res.status}`);
    const data = await res.json();
    if (typeof data.asn === "number" && typeof data.asn_description === "string") {
      return { asn: data.asn, asnName: data.asn_description };
    }
    return { asn: null, asnName: null };
  } catch (e) {
    return { asn: null, asnName: null };
  }
}

// Fetch geolocation info from public API for given IP
async function fetchGeoLocation(ip: string, signal: AbortSignal): Promise<GeoLocation> {
  try {
    const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json`;
    const res = await safeFetch(url, { signal });
    if (!res.ok) throw new Error(`ipinfo.io responded with status ${res.status}`);
    const data = await res.json();
    const loc = typeof data.loc === "string" ? data.loc.split(",") : [];
    return {
      ip,
      country: typeof data.country === "string" ? data.country : null,
      region: typeof data.region === "string" ? data.region : null,
      city: typeof data.city === "string" ? data.city : null,
      latitude: loc.length === 2 ? parseFloat(loc[0]) : null,
      longitude: loc.length === 2 ? parseFloat(loc[1]) : null,
    };
  } catch (e) {
    return {
      ip,
      country: null,
      region: null,
      city: null,
      latitude: null,
      longitude: null,
    };
  }
}

// Perform trace route IP hops, returning array of IPs
// Since no DNS or perf imports allowed, we use 'mtr' API or similar
async function traceRoute(targetIp: string, signal: AbortSignal): Promise<string[]> {
  // Use public ICMP or traceroute API is not guaranteed, use ip-api for AS path approximation
  // Workaround: use 'https://api.hackertarget.com/mtr/?q=' but it is unstable / no CORS may block
  // Instead, we simulate by resolving AS path via IP-to-ASN data for now
  try {
    // Query ip-api.com path endpoint for AS path (basic)
    // Though no exact hop IPs, at minimum can get AS path
    // To comply, do multiple single hop analyses
    // Alternatively, query https://api.iptoasn.com/v1/as/ip/{ip} for ASN info
    // But for hops, we need traceroute IPs.

    // Because external traceroute APIs are limited, we do a fallback:
    // We run multiple reverse lookups for each hop IP from a public source.
    // Without 'dns' module we cannot resolve locally.

    // So, we use a third party public traceroute API that allows direct fetch.
    // Use https://api.hackertarget.com/mtr/?q=ip (Shows hop IPs in text)

    const url = `https://api.hackertarget.com/mtr/?q=${encodeURIComponent(targetIp)}`;
    const res = await safeFetch(url, { signal });
    if (!res.ok) {
      throw new Error(`Traceroute API returned status ${res.status}`);
    }
    const text = await res.text();

    // Parse MTR output lines to extract IPs for hops
    // Sample line format starting after header lines:
    //  1.|--  10.14.80.1         1.0%    1    0.3    0.3    0.3    0.3
    //  2.|--  192.168.1.1        0.0%    1    1.7    1.7    1.7    1.7

    const ips: string[] = [];
    const lines = text.split("\n");

    for (const line of lines) {
      // Match IP in line
      const ipMatch = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
      if (ipMatch) {
        const ip = ipMatch[0];
        if (ip !== "*" && !ips.includes(ip)) {
          ips.push(ip);
        }
      }
    }

    // Limit hops to max 30
    return ips.slice(0, 30);
  } catch (e) {
    // On any failure, return only target IP
    return [targetIp];
  }
}

// Determine score and grade for network path analysis based on data completeness, diversity, private addresses
function computeScoreAndGrade(hops: AsnHop[]): { score: number; grade: string; explanation: string } {
  if (hops.length === 0) {
    return { score: 0, grade: "F", explanation: "No hops discovered in trace route." };
  }

  let score = 100;
  const reasons: string[] = [];

  // Deduct for private IPs in path
  const privateIpRegex = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.|0\.)/;
  const privateHops = hops.filter(hop => hop.ip && privateIpRegex.test(hop.ip));
  if (privateHops.length > 0) {
    score -= privateHops.length * 5;
    reasons.push(`Found ${privateHops.length} private or reserved IPs in the route, which may indicate internal or tunneled hops.`);
  }

  // Deduct for hops missing ASN
  const missingAsn = hops.filter(hop => hop.asn === null);
  if (missingAsn.length > 0) {
    score -= missingAsn.length * 4;
    reasons.push(`Missing ASN information for ${missingAsn.length} hops.`);
  }

  // Deduct for hops missing Geo info
  const missingGeo = hops.filter(hop => !hop.country);
  if (missingGeo.length > 0) {
    score -= missingGeo.length * 3;
    reasons.push(`Missing geolocation data for ${missingGeo.length} hops.`);
  }

  // Deduct for short paths
  if (hops.length < 3) {
    score -= 15;
    reasons.push("Very short path often indicates incomplete trace or local network.");
  }

  if (score < 0) score = 0;

  let grade: string;
  if (score >= 90) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 50) grade = "C";
  else if (score >= 25) grade = "D";
  else grade = "F";

  return { score, grade, explanation: reasons.length > 0 ? reasons.join(" ") : "Network path analysis completed with good quality." };
}

// Generate actionable recommendations based on analysis
function generateRecommendations(hops: AsnHop[]): Recommendation[] {
  const recs: Recommendation[] = [];
  const privateIpRegex = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.|0\.)/;

  if (hops.length === 0) {
    recs.push({ issue: "No trace route results", severity: "critical", suggestion: "Verify target address and try again later." });
    return recs;
  }

  const privateHops = hops.filter(hop => hop.ip && privateIpRegex.test(hop.ip));
  if (privateHops.length > 0) {
    recs.push({
      issue: "Private or reserved IPs in route",
      severity: "medium",
      suggestion: "Private network blocks in path may indicate tunneling or VPN usage; verify network configuration.",
    });
  }

  const missingAsn = hops.filter(hop => hop.asn === null);
  if (missingAsn.length > 0) {
    recs.push({
      issue: "Missing ASN info",
      severity: "low",
      suggestion: "Some hops lack ASN data; cross-check with alternate ASN geolocation services for completeness.",
    });
  }

  const missingGeo = hops.filter(hop => !hop.country);
  if (missingGeo.length > 0) {
    recs.push({
      issue: "Missing geolocation info",
      severity: "low",
      suggestion: "Hops missing geolocation can reduce analysis quality; consider additional geolocation APIs.",
    });
  }

  if (hops.length < 3) {
    recs.push({
      issue: "Very short trace route",
      severity: "medium",
      suggestion: "Short network paths might indicate local network or limited path visibility; try advanced traceroute with ICMP and TCP modes.",
    });
  }

  return recs;
}

// Generate simple SVG path visualization of hops geo-locations
// For simplicity, just plot hops on a world map coordinate grid
function generateTopologySvg(geos: GeoLocation[]): string {
  const width = 600;
  const height = 300;
  const margin = 20;

  // Project lat/lon to x/y coords simple equirectangular projection
  function project(lat: number | null, lon: number | null): [number, number] {
    if (lat === null || lon === null) return [width / 2, height / 2];
    const x = ((lon + 180) / 360) * (width - margin * 2) + margin;
    const y = ((90 - lat) / 180) * (height - margin * 2) + margin;
    return [x, y];
  }

  const points = geos.map(g => project(g.latitude, g.longitude));

  // Build SVG path connecting hops
  let path = "";
  for (let i = 0; i < points.length; i++) {
    const [x, y] = points[i];
    if (i === 0) path += `M ${x.toFixed(1)} ${y.toFixed(1)}`;
    else path += ` L ${x.toFixed(1)} ${y.toFixed(1)}`;
  }

  // Circles for hops
  const circles = points.map(([x, y], i) =>
    `<circle cx='${x.toFixed(1)}' cy='${y.toFixed(1)}' r='5' fill='${i === points.length - 1 ? "#d33" : "#357"}'><title>Hop ${i + 1}</title></circle>`
  ).join("");

  const svg = `
<svg width='${width}' height='${height}' viewBox='0 0 ${width} ${height}' xmlns='http://www.w3.org/2000/svg' aria-label='Network path topology'>
  <rect width='100%' height='100%' fill='#eaeaea'/>
  <path d='${path}' stroke='#357' stroke-width='2' fill='none' stroke-linejoin='round' stroke-linecap='round' />
  ${circles}
  <text x='${margin}' y='${height - 5}' font-family='sans-serif' font-size='10' fill='#555'>Network Path Topology (Approximate)</text>
</svg>
`;
  return svg.trim();
}

// Main infer function, input is hostname or IP string
export async function analyzeNetworkPath(target: string): Promise<NetworkPathInferResult | { error: string }> {
  const startTime = performance.now();
  // Validate input: IP or hostname
  try {
    let targetIp = "";
    let targetHostname: string | undefined;

    try {
      // Validate as IP first
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(target.trim())) {
        targetIp = target.trim();
      } else {
        // Try DNS lookup using a public API, since builtin dns is not allowed
        // Use https://dns.google/resolve?name=domain&type=A endpoint
        const dnsUrl = `https://dns.google/resolve?name=${encodeURIComponent(target.trim())}&type=A`;
        const dnsRes = await safeFetch(dnsUrl, { timeoutMs: ABORT_TIMEOUT_MS });
        if (!dnsRes.ok) {
          return { error: `DNS lookup failed with status ${dnsRes.status}` };
        }
        const dnsJson = await dnsRes.json();
        if (dnsJson.Answer && Array.isArray(dnsJson.Answer)) {
          const answer = dnsJson.Answer.find((a: any) => a.type === 1);
          if (answer && typeof answer.data === "string") {
            targetIp = answer.data;
            targetHostname = target.trim();
          } else {
            return { error: "No A record found for hostname" };
          }
        } else {
          return { error: "Invalid DNS response format" };
        }
      }
    } catch (e) {
      return { error: `Failed to resolve target hostname or IP: ${(e instanceof Error ? e.message : String(e))}` };
    }

    // Trace route hops
    let hopsIps: string[] = [];
    try {
      hopsIps = await traceRoute(targetIp, AbortSignal.timeout(ABORT_TIMEOUT_MS));
      if (hopsIps.length === 0) {
        hopsIps = [targetIp];
      }
    } catch (e) {
      hopsIps = [targetIp];
    }

    // For each hop IP fetch ASN and Geo info concurrently
    const hopPromises: Promise<AsnHop>[] = hopsIps.map(async (ip, idx) => {
      const signal = AbortSignal.timeout(ABORT_TIMEOUT_MS);
      const [asnInfo, geoInfo] = await Promise.all([
        fetchAsnInfo(ip, signal),
        fetchGeoLocation(ip, signal),
      ]);
      return {
        hopIndex: idx + 1,
        ip,
        asn: asnInfo.asn,
        asnName: asnInfo.asnName,
        country: geoInfo.country,
        region: geoInfo.region,
        city: geoInfo.city,
        error: null,
      };
    });

    const asnHops = await Promise.all(hopPromises);

    // Gather all geo infos for topology visualization
    const geolocations: GeoLocation[] = asnHops.map(hop => ({
      ip: hop.ip,
      country: hop.country,
      region: hop.region,
      city: hop.city,
      latitude: null,
      longitude: null,
    }));

    // Enrich geo locations with lat/lon from ipinfo.io (parallel)
    const geoPromises = geolocations.map(async (geo) => {
      try {
        const signal = AbortSignal.timeout(ABORT_TIMEOUT_MS);
        const geoDetail = await fetchGeoLocation(geo.ip, signal);
        return geoDetail;
      } catch {
        return geo;
      }
    });

    const detailedGeos = await Promise.all(geoPromises);

    // Compute score and grade
    const { score: pathScore, grade: pathGrade, explanation } = computeScoreAndGrade(asnHops);

    // Generate recommendations
    const recommendations = generateRecommendations(asnHops);

    // Generate topology SVG visualization
    const topologyGraphSvg = generateTopologySvg(detailedGeos);

    const analyzedAt = new Date().toISOString();

    return {
      targetIp,
      targetHostname,
      asnHops,
      pathScore,
      pathGrade,
      geolocations: detailedGeos,
      topologyGraphSvg,
      explanation,
      recommendations,
      analyzedAt,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { error: `Unexpected error during network path analysis: ${msg}` };
  } finally {
    const duration = Math.round(performance.now() - startTime);
  }
}
