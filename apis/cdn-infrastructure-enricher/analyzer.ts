import {
  safeFetch,
  validateExternalUrl,
} from "../../shared/ssrf";

// --- Types ---

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface FullAnalysisResult {
  url: string;
  detectedCdns: string[]; // CDN providers found
  detectedHosting: string; // Hosting provider
  ipRanges: string[]; // CIDRs
  regionalDistribution: string; // Description
  score: number; // 0-100
  grade: string; // A-F
  explanation: string; // Human explanation
  recommendations: Recommendation[];
  checkedAt: string;
  duration_ms?: number;
}

export interface PreviewResult {
  url: string;
  detectedCdns: string[];
  detectedHosting: string;
  ipRanges: string[];
  regionalDistribution: string;
  score: number;
  grade: string;
  explanation: string;
  recommendations: Recommendation[];
  checkedAt: string;
  duration_ms?: number;
}

export interface AnalyzeOptions {
  preview: boolean;
}

interface DnsAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

// --- Constants ---
const CDN_IDENTIFIERS: Record<string, RegExp> = {
  Cloudflare: /cloudflare/i,
  Akamai: /akamai/i,
  Fastly: /fastly/i,
  AmazonCloudFront: /cloudfront\.net/i,
  GoogleCloudCDN: /googleusercontent\.com|googlecdn\.com/i,
  AzureCDN: /azureedge\.net|azurefd\.net/i,
  Netlify: /netlify\.com/i,
  Vercel: /vercel\.com/i,
};

const HOSTING_PROVIDERS: Record<string, RegExp> = {
  AWS: /amazonaws\.com|compute\.amazonaws\.com/i,
  GoogleCloud: /googleusercontent\.com|google\.com/i,
  Azure: /cloudapp\.azure\.com|azureedge\.net/i,
  DigitalOcean: /digitaloceanspaces\.com/i,
  Linode: /linodeobjects\.com/i,
  OVH: /ovh\.net/i,
  Hetzner: /hetzner\.cloud/i,
};

// Grades thresholds
const GRADE_THRESHOLDS = [
  { threshold: 90, grade: "A" },
  { threshold: 75, grade: "B" },
  { threshold: 60, grade: "C" },
  { threshold: 45, grade: "D" },
  { threshold: 0, grade: "F" },
];

// Utility to grade by score
function gradeFromScore(score: number): string {
  for (const { threshold, grade } of GRADE_THRESHOLDS) {
    if (score >= threshold) return grade;
  }
  return "F";
}

// Validate URL and get hostname
function getHostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

// Fetch DNS records A, CNAME for domain from Google DNS over HTTPS
async function fetchDnsRecords(hostname: string): Promise<{ a: string[]; cnames: string[] }> {
  const aRecords: string[] = [];
  const cnameRecords: string[] = [];

  // DNS Google doH endpoint
  const dnsBase = `https://dns.google/resolve?name=${encodeURIComponent(hostname)}`;

  try {
    // Fetch A records
    const resA = await safeFetch(`${dnsBase}&type=A`, { timeoutMs: 10000 });
    if (resA.ok) {
      const dataA = await resA.json();
      if (Array.isArray(dataA.Answer)) {
        for (const ans of dataA.Answer) {
          if (ans.type === 1 && ans.data) {
            aRecords.push(ans.data);
          }
        }
      }
    }
  } catch (e) {
    // Ignore failures
  }

  try {
    // Fetch CNAME records
    const resCN = await safeFetch(`${dnsBase}&type=CNAME`, { timeoutMs: 10000 });
    if (resCN.ok) {
      const dataCN = await resCN.json();
      if (Array.isArray(dataCN.Answer)) {
        for (const ans of dataCN.Answer) {
          if (ans.type === 5 && ans.data) {
            cnameRecords.push(ans.data.toLowerCase().replace(/\.$/, ""));
          }
        }
      }
    }
  } catch (e) {
    // Ignore failures
  }

  return { a: aRecords, cnames: cnameRecords };
}

// Fetch HTTP headers from website
async function fetchHeaders(url: string): Promise<Headers> {
  // Use GET for preview, HEAD for paid (to save bandwidth)
  // But preview allows longer timeout
  const signal = AbortSignal.timeout(10000);
  const res = await safeFetch(url, {
    method: "GET",
    headers: { "User-Agent": "cdn-infrastructure-enricher/1.0 apimesh.xyz" },
    signal,
  });
  return res.headers;
}

// Identify CDNs based on CNAMEs and headers
function identifyCdns(cnames: string[], headers: Headers): string[] {
  const detected: Set<string> = new Set();

  // Check CNAMEs
  for (const cname of cnames) {
    for (const [cdn, pattern] of Object.entries(CDN_IDENTIFIERS)) {
      if (pattern.test(cname)) {
        detected.add(cdn);
      }
    }
  }

  // Check headers for CF-Ray (Cloudflare), X-Served-By (Fastly, Akamai)
  const cfRay = headers.get("CF-Ray");
  if (cfRay) detected.add("Cloudflare");
  const xServedBy = headers.get("X-Served-By");
  if (xServedBy) {
    for (const [cdn, pattern] of Object.entries(CDN_IDENTIFIERS)) {
      if (pattern.test(xServedBy)) {
        detected.add(cdn);
      }
    }
  }

  // Check Server header
  const server = headers.get("Server");
  if (server) {
    for (const [cdn, pattern] of Object.entries(CDN_IDENTIFIERS)) {
      if (pattern.test(server)) {
        detected.add(cdn);
      }
    }
  }

  // Other headers that could hint
  // For example, X-CDN: Cachefly
  const xCdn = headers.get("X-CDN");
  if (xCdn) {
    for (const [cdn, pattern] of Object.entries(CDN_IDENTIFIERS)) {
      if (pattern.test(xCdn)) {
        detected.add(cdn);
      }
    }
  }

  return Array.from(detected);
}

// Identify hosting provider by domains/IP info heuristics
function identifyHostingProvider(hostname: string, ips: string[]): string {
  // Check hostname patterns
  for (const [provider, pattern] of Object.entries(HOSTING_PROVIDERS)) {
    if (pattern.test(hostname)) {
      return provider;
    }
  }

  // TODO: IP ranges mapping
  // For demo, basic heuristics

  // Known IP CIDRs for AWS
  const awsCidrs = ["3.", "13.", "52.", "54.", "144."];
  for (const ip of ips) {
    if (awsCidrs.some((prefix) => ip.startsWith(prefix))) return "AWS";
  }

  return "Unknown";
}

// Fetch IP ranges for the domain and do simple regional classification
async function fetchIpRangesAndRegions(ips: string[], signal: AbortSignal): Promise<{ cidrs: string[]; regionDesc: string }> {
  // For demo: return given IPs as CIDRs;
  // For real usage, query RIPE/ARIN or use ipinfo.io / ip-api.com free APIs with timeouts.
  // Respect no API key usage: use ip-api.com JSON endpoint throttled.

  const cidrs = [] as string[];
  const regions = new Set<string>();

  // Use ip-api.com batch for up to 100 IPs
  // Chunk in 100
  const chunks: string[][] = [];
  for (let i = 0; i < ips.length; i += 100) {
    chunks.push(ips.slice(i, i + 100));
  }

  try {
    for (const chunk of chunks) {
      const reqBody = chunk.map((ip) => ({ query: ip }));

      const res = await safeFetch("http://ip-api.com/batch?fields=status,country,regionName,city,query", {
        method: "POST",
        signal,
        body: JSON.stringify(reqBody),
        headers: { "Content-Type": "application/json" },
      });

      if (!res.ok) continue;

      const data = await res.json();
      for (const r of data) {
        if (r.status === "success" && typeof r.query === "string") {
          cidrs.push(r.query);
          if (r.regionName) regions.add(r.regionName);
          else if (r.country) regions.add(r.country);
        }
      }
    }
  } catch (e) {
    // Ignore failures
  }

  const regionDesc = regions.size === 0 ? "Unknown" : Array.from(regions).join(", ");
  return { cidrs, regionDesc };
}

// Compute score from detected CDNs and regional distribution
function computeScore(detectedCdns: string[], regionalDistribution: string): number {
  // Simple scoring scheme:
  // +30 if multi-CDN
  // +20 if regionalDistribution includes "Global"
  // +10 per CDN (max 50)
  let score = 0;
  if (detectedCdns.length > 1) score += 30;
  else if (detectedCdns.length === 1) score += 15;

  if (/global/i.test(regionalDistribution)) score += 20;

  score += Math.min(50, detectedCdns.length * 10);

  if (score > 100) score = 100;
  if (score < 0) score = 0;
  return score;
}

// Compose detailed explanation
function composeExplanation(detectedCdns: string[], detectedHosting: string, regionalDistribution: string, ipRanges: string[]): string {
  let expl = "Detected CDN providers: ";
  if (detectedCdns.length === 0) expl += "None detected";
  else expl += detectedCdns.join(", ");
  expl += ". Hosting environment: " + detectedHosting + ".";
  expl += ` Regional presence: ${regionalDistribution}. `;
  if (ipRanges.length > 0) {
    expl += `IP ranges detected: ${ipRanges.slice(0, 5).join(", ")}`;
    if (ipRanges.length > 5) expl += ` (and ${ipRanges.length - 5} more)`;
    expl += ".";
  }
  return expl;
}

// Recommendations generation
function generateRecommendations(
  detectedCdns: string[],
  detHosting: string,
  score: number
): Recommendation[] {
  const recs: Recommendation[] = [];

  if (detectedCdns.length === 0) {
    recs.push({
      issue: "No CDN detected",
      severity: 80,
      suggestion: "Consider deploying a CDN for better performance and availability.",
    });
  }

  if (detectedCdns.length === 1 && score < 50) {
    recs.push({
      issue: "Single CDN with low score",
      severity: 60,
      suggestion: "Analyze your CDN configuration to improve caching or consider multi-CDN setup.",
    });
  }

  if (/unknown/i.test(detHosting)) {
    recs.push({
      issue: "Unknown hosting provider",
      severity: 30,
      suggestion: "Verify hosting environment; unknown providers may affect reliability.",
    });
  }

  if (score >= 80) {
    recs.push({
      issue: "Good CDN and hosting setup",
      severity: 10,
      suggestion: "Maintain current configurations; no immediate action needed.",
    });
  }

  return recs;
}

// Main exported function
export async function analyzeCdnInfrastructure(
  rawUrl: string,
  options: AnalyzeOptions
): Promise<FullAnalysisResult | PreviewResult> {
  const start = performance.now();

  const urlValidated = validateExternalUrl(rawUrl);
  if ("error" in urlValidated) {
    throw new Error(`Invalid URL: ${urlValidated.error}`);
  }
  const url = urlValidated.url.toString();
  const hostname = getHostname(url);
  if (!hostname) {
    throw new Error("Invalid hostname extracted from URL");
  }

  // Prepare AbortSignal with appropriate timeout
  const timeoutMs = options.preview ? 20000 : 15000;
  const signal = AbortSignal.timeout(timeoutMs);

  // Fetch DNS records and HTTP headers concurrently
  let dnsRecords: { a: string[]; cnames: string[] } = { a: [], cnames: [] };
  let headers: Headers | null = null;

  try {
    [dnsRecords, headers] = await Promise.all([
      fetchDnsRecords(hostname),
      fetchHeaders(url),
    ]);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`Data fetch error: ${msg}`);
  }

  const detectedCdns = identifyCdns(dnsRecords.cnames, headers);

  // Identify hosting using hostname + A records
  const detectedHosting = identifyHostingProvider(hostname, dnsRecords.a);

  // Fetch IP ranges and regional info
  const ipData = await fetchIpRangesAndRegions(dnsRecords.a, signal);

  // Compose regional label, enhance for preview with heuristic
  let regionalDistribution = ipData.regionDesc;
  if (regionalDistribution === "Unknown") {
    // Use presence of common CDN names for global guess
    if (detectedCdns.length > 1) {
      regionalDistribution = "Global multiple regions";
    } else if (detectedCdns.length === 1) {
      regionalDistribution = "Regional/Single region presence";
    } else {
      regionalDistribution = "Unknown or minimal regional presence";
    }
  }

  // Compute final score
  const score = computeScore(detectedCdns, regionalDistribution);

  // Map score to grade
  const grade = gradeFromScore(score);

  // Compose explanation
  const explanation = composeExplanation(detectedCdns, detectedHosting, regionalDistribution, ipData.cidrs);

  // Recommendations
  const recommendations = generateRecommendations(detectedCdns, detectedHosting, score);

  const duration_ms = Math.round(performance.now() - start);

  const checkedAt = new Date().toISOString();

  if (options.preview) {
    const previewResult: PreviewResult = {
      url,
      detectedCdns,
      detectedHosting,
      ipRanges: ipData.cidrs,
      regionalDistribution,
      score,
      grade,
      explanation,
      recommendations,
      checkedAt,
      duration_ms,
    };
    return previewResult;
  } else {
    const fullResult: FullAnalysisResult = {
      url,
      detectedCdns,
      detectedHosting,
      ipRanges: ipData.cidrs,
      regionalDistribution,
      score,
      grade,
      explanation,
      recommendations,
      checkedAt,
      duration_ms,
    };
    return fullResult;
  }
}
