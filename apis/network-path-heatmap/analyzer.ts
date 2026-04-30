import { safeFetch } from "../../shared/ssrf";

// ── Types ──────────────────────────────────────────────────────────────────────

export interface NetworkPathHop {
  asn: number | null;
  asnName: string | null;
  ip: string;
  country: string | null;
  geo: { latitude: number; longitude: number } | null;
  rttMs: number | null;
}

export interface NetworkPathHeatmapResult {
  ip: string;
  asnPath: NetworkPathHop[]; // hops ASNs with geolocation
  geolocations: Array<{ ip: string; country: string | null; latitude: number; longitude: number }>;
  score: number; // 0-100
  grade: "A" | "B" | "C" | "D" | "F";
  recommendations: Array<{ issue: string; severity: number; suggestion: string }>;
  explanation: string;
  analyzedAt: string;
}

export interface NetworkPathHeatmapPreview {
  ip: string;
  asn: number | null;
  asnName: string | null;
  country: string | null;
  geo: { latitude: number; longitude: number } | null;
  note: string;
  preview: true;
  checkedAt: string;
}

// ── Constants ──────────────────────────────────────────────────────────────────

// Public free ASN and IP geolocation services URLs
const ASN_LOOKUP_APIS = [
  async (ip: string, signal: AbortSignal) => {
    // ip-api.com JSON ASN lookup
    const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=as,asname,country,lat,lon,status,message`;
    try {
      const res = await safeFetch(url, { signal, timeoutMs: 10000 });
      if (!res.ok) throw new Error(`ip-api.com status ${res.status}`);
      const json = await res.json();
      if (json.status !== "success") throw new Error(`ip-api.com error: ${json.message || "unknown"}`);
      return {
        asn: typeof json.as === "number" ? json.as : null,
        asnName: json.asname || null,
        country: json.country || null,
        latitude: typeof json.lat === "number" ? json.lat : null,
        longitude: typeof json.lon === "number" ? json.lon : null,
      };
    } catch (e) {
      // On error return null to omit
      return null;
    }
  },
  async (ip: string, signal: AbortSignal) => {
    // ipinfo.io free endpoint for ASN
    const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json`;
    try {
      const res = await safeFetch(url, { signal, timeoutMs: 10000 });
      if (!res.ok) throw new Error(`ipinfo.io status ${res.status}`);
      const json = await res.json();
      if (json.error) throw new Error(`ipinfo.io error: ${json.error.message}`);
      // ASN string: e.g., "AS15169 Google LLC"
      let asnNum: number | null = null;
      let asnName: string | null = null;
      if (typeof json.as === "string") {
        const asMatch = json.as.match(/^AS(\d+)\s*(.*)$/i);
        if (asMatch) {
          asnNum = parseInt(asMatch[1], 10);
          asnName = asMatch[2].trim() || null;
        }
      }
      return {
        asn: asnNum,
        asnName: asnName,
        country: json.country || null,
        latitude: null, // no lat/lon available here
        longitude: null,
      };
    } catch {
      return null;
    }
  },
];

// Public free IPv4 traceroute-like API (using https://api.hackertarget.com/mtr/)
async function fetchTracerouteHops(ip: string, signal: AbortSignal): Promise<string[]> {
  const url = `https://api.hackertarget.com/mtr/?q=${encodeURIComponent(ip)}`;
  try {
    const res = await safeFetch(url, { signal, timeoutMs: 15000 });
    if (!res.ok) throw new Error(`hackertarget mtr status ${res.status}`);
    const text = await res.text();
    // Parse hops from output
    const lines = text.split("\n");
    // skip header lines by searching
    const hops: string[] = [];
    for (const line of lines) {
      // Each hop line starts with a number and IP somewhere in it
      if (/^\s*\d+\s/.test(line)) {
        const ips = line.match(/(?:\d{1,3}\.){3}\d{1,3}/g);
        if (ips && ips.length > 0) {
          hops.push(ips[0]);
        }
      }
    }
    return hops;
  } catch {
    return [];
  }
}

// Helper to fetch ASN info for multiple IPs in parallel
async function fetchMultipleAsnInfo(
  ips: string[],
  signal: AbortSignal
): Promise<(null | {
  asn: number | null;
  asnName: string | null;
  country: string | null;
  latitude: number | null;
  longitude: number | null;
})[]> {
  // Use Promise.all with race of first successful API for each IP
  const results = await Promise.all(
    ips.map(async (ip) => {
      // Try parallel calls, take first non-null
      const calls = ASN_LOOKUP_APIS.map((api) => api(ip, signal));
      try {
        const settled = await Promise.allSettled(calls);
        for (const s of settled) {
          if (s.status === "fulfilled" && s.value !== null) {
            return s.value;
          }
        }
        return null;
      } catch {
        return null;
      }
    })
  );
  return results;
}

// Scoring and grading helper
function computeScoreAndGrade(hops: NetworkPathHop[]): { score: number; grade: NetworkPathHeatmapResult["grade"] } {
  // Score: count distinct ASNs, diversity in countries, RTT presence
  const asnSet = new Set<number>();
  const countries = new Set<string>();
  let rttCount = 0;

  for (const hop of hops) {
    if (hop.asn && hop.asn > 0) asnSet.add(hop.asn);
    if (hop.country) countries.add(hop.country);
    if (hop.rttMs !== null) rttCount++;
  }

  let score = 50;
  score += Math.min(asnSet.size, 5) * 7;  // up to +35
  score += Math.min(countries.size, 3) * 5; // up to +15
  score += rttCount > 2 ? 10 : 0; // +10 if RTT data for 3+ hops

  if (score > 100) score = 100;

  // Grade calculation
  if (score >= 90) return { score, grade: "A" };
  if (score >= 75) return { score, grade: "B" };
  if (score >= 55) return { score, grade: "C" };
  if (score >= 35) return { score, grade: "D" };
  return { score: 0, grade: "F" };
}

// Recommendations based on analysis
function generateRecommendations(hops: NetworkPathHop[], score: number): NetworkPathHeatmapResult["recommendations"] {
  const recs: NetworkPathHeatmapResult["recommendations"] = [];

  // Example issues
  if (score < 60) {
    recs.push({
      issue: "Low path diversity",
      severity: 75,
      suggestion: "Consider network path optimization to diversify ISP or transit providers for resilience.",
    });
  }

  if (hops.length === 0) {
    recs.push({
      issue: "No network path information",
      severity: 90,
      suggestion: "Unable to detect network path. Check if the target IP is reachable or restricts traceroute requests.",
    });
  }

  return recs;
}

// Full deep analysis function
export async function fullAnalysis(ip: string): Promise<NetworkPathHeatmapResult> {
  const signal = AbortSignal.timeout(10000);

  // Fetch traceroute hops (up to 20)
  const hopsIps = await fetchTracerouteHops(ip, signal);
  // Limit hops to 20 to avoid blowup
  const limitedHops = hopsIps.slice(0, 20);

  // Fetch ASN+geolocation data for hops in parallel
  const asnInfoList = await fetchMultipleAsnInfo(limitedHops, signal);

  // Compose hops data
  const hops: NetworkPathHop[] = limitedHops.map((hopIp, i) => {
    const info = asnInfoList[i];
    return {
      ip: hopIp,
      asn: info?.asn ?? null,
      asnName: info?.asnName ?? null,
      country: info?.country ?? null,
      geo: info?.latitude !== null && info?.longitude !== null ? { latitude: info.latitude, longitude: info.longitude } : null,
      rttMs: null, // RTT data unavailable due to lack of ping info
    };
  });

  // Collect geolocations
  const geolocations: { ip: string; country: string | null; latitude: number; longitude: number }[] = [];
  for (const hop of hops) {
    if (hop.geo) {
      geolocations.push({
        ip: hop.ip,
        country: hop.country,
        latitude: hop.geo.latitude,
        longitude: hop.geo.longitude,
      });
    }
  }

  // Scoring and grading
  const { score, grade } = computeScoreAndGrade(hops);

  // Explanation
  let explanation = `Network path length: ${hops.length} hop(s). `;
  explanation += `Unique ASNs: ${new Set(hops.filter(h => h.asn !== null).map(h => h.asn)).size}. `;
  explanation += `Unique countries where hops were geolocated: ${new Set(hops.filter(h => h.country !== null).map(h => h.country)).size}. `;
  explanation += `Overall path score is ${score} with grade ${grade}.`;

  // Recommendations
  const recommendations = generateRecommendations(hops, score);

  return {
    ip,
    asnPath: hops,
    geolocations,
    score,
    grade,
    recommendations,
    explanation,
    analyzedAt: new Date().toISOString(),
  };
}

// Preview analysis for free endpoint
export async function previewAnalysis(ip: string): Promise<NetworkPathHeatmapPreview> {
  // Use a single quick ASN+geo fetch with timeout 15s
  const signal = AbortSignal.timeout(20000);

  // Use first API only for preview
  try {
    const info = await ASN_LOOKUP_APIS[0](ip, signal);
    if (!info) {
      return {
        ip,
        asn: null,
        asnName: null,
        country: null,
        geo: null,
        note: "Preview: ASN and basic geolocation unavailable for this IP.",
        preview: true,
        checkedAt: new Date().toISOString(),
      };
    }
    return {
      ip,
      asn: info.asn,
      asnName: info.asnName,
      country: info.country,
      geo: info.latitude !== null && info.longitude !== null ? { latitude: info.latitude, longitude: info.longitude } : null,
      note: "Preview: Basic ASN and geolocation info. Pay via x402 for full network path heatmap and analysis.",
      preview: true,
      checkedAt: new Date().toISOString(),
    };
  } catch (e) {
    return {
      ip,
      asn: null,
      asnName: null,
      country: null,
      geo: null,
      note: `Preview: ASN and geolocation query failed: ${(e instanceof Error) ? e.message : String(e)}`,
      preview: true,
      checkedAt: new Date().toISOString(),
    };
  }
}
