import { safeFetch } from "../../shared/ssrf";

// Define TypeScript interfaces for structured response

export interface ResolverResponse {
  resolver: string;
  records: string[];    // records returned for query
  error?: string;       // error message if failed
  rttMs?: number;       // round-trip time in milliseconds
  lastUpdated?: Date;   // inferred last update time by resolver
}

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface PropagationSimulationResult {
  domain: string;
  recordType: string;
  resolvedRecords: string[]; // union set of all records observed
  resolverDetails: ResolverResponse[];
  propagationScore: number; // 0-100, based on convergence and latency
  grade: string; // A-F
  recommendations: Recommendation[];
  details: string; // human-readable analysis text
}

export interface SimulatorOptions {
  previewMode?: boolean; // if true, run quick light checks
}


// Static list of global DNS resolver IPs / names for query
// We will query their DNS over HTTPS JSON APIs (Google, Cloudflare, Quad9, OpenDNS, CleanBrowsing, etc.)
const DNS_RESOLVERS = [
  {
    name: "Google DNS",
    type: "doh-google",
    endpoint: "https://dns.google/resolve"
  },
  {
    name: "Cloudflare DNS",
    type: "doh-cloudflare",
    endpoint: "https://cloudflare-dns.com/dns-query"
  },
  {
    name: "Quad9 DNS",
    type: "doh-quad9",
    endpoint: "https://dns.quad9.net/dns-query"
  },
  {
    name: "OpenDNS",
    type: "doh-opendns",
    endpoint: "https://doh.opendns.com/dns-query"
  },
  {
    name: "CleanBrowsing",
    type: "doh-cleanbrowsing",
    endpoint: "https://doh.cleanbrowsing.org/doh/feed"
  },
];

// DOH fetch configuration
const FETCH_TIMEOUT_MS = 10000;

// Utility: convert DNS record type string to numeric code for DOH queries
// Per https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/
const DNS_RECORD_TYPES: Record<string, number> = {
  A: 1,
  AAAA: 28,
  CNAME: 5,
  TXT: 16,
  MX: 15,
  NS: 2,
  SOA: 6,
  PTR: 12,
  SRV: 33,
  SPF: 99,
  ANY: 255
};

function recordTypeToCode(rt: string): number {
  return DNS_RECORD_TYPES[rt.toUpperCase()] || 1; // default A record
}

// Known resolver response interfaces
interface DohGoogleResponse {
  Status: number;
  Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
  "AD"?: boolean;
  "CD"?: boolean;
  Comment?: string;
}

interface DohCloudflareAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DohCloudflareResponse {
  Status: number;
  Answer?: DohCloudflareAnswer[];
  Comment?: string;
}

// Fetch DNS records from a resolver using DOH JSON API
async function fetchDnsFromResolver(
  resolver: typeof DNS_RESOLVERS[0],
  domain: string,
  recordType: string
): Promise<ResolverResponse> {
  const qtype = recordTypeToCode(recordType);
  let url: string;
  let headers = {};
  try {
    switch (resolver.type) {
      case "doh-google":
        // GET?name=example.com&type=A
        url = `${resolver.endpoint}?name=${encodeURIComponent(domain)}&type=${qtype}`;
        break;
      case "doh-cloudflare":
        // GET?name=example.com&type=1 (also accepts Accept: application/dns-json)
        url = `${resolver.endpoint}?name=${encodeURIComponent(domain)}&type=${qtype}`;
        headers = { Accept: "application/dns-json" };
        break;
      case "doh-quad9":
        url = `${resolver.endpoint}?name=${encodeURIComponent(domain)}&type=${qtype}`;
        headers = { Accept: "application/dns-json" };
        break;
      case "doh-opendns":
        url = `${resolver.endpoint}?name=${encodeURIComponent(domain)}&type=${qtype}`;
        headers = { Accept: "application/dns-json" };
        break;
      case "doh-cleanbrowsing":
        url = `${resolver.endpoint}?name=${encodeURIComponent(domain)}&type=${qtype}`;
        headers = { Accept: "application/dns-json" };
        break;
      default:
        return { resolver: resolver.name, records: [], error: "Unsupported resolver type" };
    }

    const start = performance.now();
    const response = await safeFetch(url, {
      method: "GET",
      headers: {
        ...headers,
        "User-Agent": "dns-propagation-simulator/1.0 apimesh.xyz"
      },
      timeoutMs: FETCH_TIMEOUT_MS
    });
    const rttMs = Math.round(performance.now() - start);

    if (!response.ok) {
      return { resolver: resolver.name, records: [], error: `HTTP status ${response.status}`, rttMs };
    }

    const json = await response.json();

    // Parse answers according to resolver type
    let answers: string[] = [];
    switch (resolver.type) {
      case "doh-google": {
        const data = json as DohGoogleResponse;
        if (data.Status !== 0) {
          return { resolver: resolver.name, records: [], error: `DNS query status ${data.Status}`, rttMs };
        }
        if (!data.Answer) {
          return { resolver: resolver.name, records: [], rttMs };
        }
        answers = data.Answer.filter((a) => a.type === qtype).map((a) => a.data);
        break;
      }
      case "doh-cloudflare":
      case "doh-quad9":
      case "doh-opendns":
      case "doh-cleanbrowsing": {
        if (json.Status !== 0) {
          return { resolver: resolver.name, records: [], error: `DNS query status ${json.Status}`, rttMs };
        }
        if (!json.Answer) {
          return { resolver: resolver.name, records: [], rttMs };
        }
        answers = json.Answer.filter((a: DohCloudflareAnswer) => a.type === qtype).map((a: DohCloudflareAnswer) => a.data);
        break;
      }
    }

    return { resolver: resolver.name, records: answers, rttMs };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { resolver: resolver.name, records: [], error: msg };
  }
}

// Utilities to analyze results

function unionArrays(arrays: string[][]): string[] {
  const set = new Set<string>();
  for (const arr of arrays) {
    for (const item of arr) {
      set.add(item);
    }
  }
  return Array.from(set);
}

function computePropagationScore(resolvers: ResolverResponse[]): number {
  // Score is based on % of resolvers that agree on records, and delays
  const successes = resolvers.filter(r => r.records.length > 0);
  if (successes.length === 0) return 0;

  // Consolidate all results
  const allRecords = unionArrays(successes.map(r => r.records));

  // Compute agreement ratio
  let agreementCount = 0;
  for (const r of successes) {
    // We say it agrees if all resolver records are subset of allRecords
    // But for scoring, count how many resolvers have the full record
    agreementCount += 1 - (r.records.filter(rec => !allRecords.includes(rec)).length / allRecords.length);
  }

  const agreementRatio = agreementCount / successes.length; // 0-1

  // Compute average latency (exclude errored or not responded)
  const latencyArr = successes.map(r => r.rttMs ?? FETCH_TIMEOUT_MS);
  const avgLatency = latencyArr.reduce((a,b) => a+b, 0) / latencyArr.length;

  // Score from 0-100
  // We want high agreement ratio and low latency
  let score = agreementRatio * 100;

  // Deduct points for latency penalty beyond 200ms
  if (avgLatency > 200) {
    const penalty = Math.min((avgLatency - 200) / 10, 50); // max 50 points
    score -= penalty;
  }

  if (score < 0) score = 0;
  if (score > 100) score = 100;

  return Math.round(score);
}

function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  if (score >= 30) return "E";
  return "F";
}

function generateRecommendations(score: number, resolverDetails: ResolverResponse[]): Recommendation[] {
  const recs: Recommendation[] = [];

  if (score < 70) {
    recs.push({
      issue: "Propagation incomplete or delayed",
      severity: 60,
      suggestion: "Allow more time for DNS records to propagate, verify the TTL settings and DNS provider configurations."
    });
  }

  // Check for any resolvers reporting errors
  for (const r of resolverDetails) {
    if (r.error) {
      recs.push({
        issue: `Resolver ${r.resolver} returned error: ${r.error}`,
        severity: 80,
        suggestion: "Check DNS configuration and ensure the domain is correctly published and resolvable globally."
      });
    }
  }

  // Check for inconsistent responses
  const recordsSets = resolverDetails.filter(r => r.records.length > 0).map(r => JSON.stringify(r.records.sort()));
  const uniqueSets = new Set(recordsSets);
  if (uniqueSets.size > 1) {
    recs.push({
      issue: "Inconsistent DNS responses across resolvers detected",
      severity: 75,
      suggestion: "Investigate DNS server inconsistencies or caching issues; ensure all authoritative DNS servers serve the same data."
    });
  }

  if (recs.length === 0) {
    recs.push({
      issue: "No significant issues detected",
      severity: 10,
      suggestion: "DNS records are well propagated and consistent across global resolvers."
    });
  }

  return recs;
}

function humanReadableDetails(domain: string, recordType: string, score: number, grade: string, resolverDetails: ResolverResponse[]): string {
  const availability = resolverDetails.filter(r => r.records.length > 0).length;
  const total = resolverDetails.length;
  const details = `DNS propagation simulation for ${domain} (${recordType} record): ${availability} of ${total} resolvers returned records. Propagation score is ${score} (${grade}). Some delays or inconsistencies may cause non-instant global updates.`;
  return details;
}

export async function simulatePropagation(
  domain: string,
  recordType: string,
  options: SimulatorOptions = {}
): Promise<PropagationSimulationResult | { error: string }> {
  // Validate domain basic format (simple check)
  if (!/^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,}$/i.test(domain)) {
    return { error: "Invalid domain name format" };
  }

  const resolversToUse = options.previewMode ? DNS_RESOLVERS.slice(0, 3) : DNS_RESOLVERS;

  // Fire parallel queries
  const queries = resolversToUse.map(r => fetchDnsFromResolver(r, domain, recordType));

  let resolverResults: ResolverResponse[] = [];
  try {
    resolverResults = await Promise.all(queries);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Fetch error: ${msg}` };
  }

  // Union all returned records
  const allRecords = unionArrays(resolverResults.map(r => r.records));

  // Compute score and grade
  const propagationScore = computePropagationScore(resolverResults);
  const grade = scoreToGrade(propagationScore);

  // Recommendations
  const recommendations = generateRecommendations(propagationScore, resolverResults);

  // Compose human-readable details
  const details = humanReadableDetails(domain, recordType, propagationScore, grade, resolverResults);

  return {
    domain,
    recordType,
    resolvedRecords: allRecords,
    resolverDetails: resolverResults,
    propagationScore,
    grade,
    recommendations,
    details
  };
}
