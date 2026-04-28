import type { EndpointDiscoveryRequest, EndpointInfo, EndpointDiscoveryResult } from "./types";
import { safeFetch, validateExternalUrl, readBodyCapped } from "../../shared/ssrf";

// Allowed common API path tokens to test
// For analysis depth 2, we try root and 1-level tokens.
// For depth 3, 2-level tokens, etc.

const COMMON_PATHS = [
  "api",
  "v1",
  "v2",
  "users",
  "user",
  "auth",
  "login",
  "logout",
  "me",
  "status",
  "health",
  "items",
  "products",
  "data",
  "info",
  "search",
  "admin",
  "config",
  "settings",
  "posts",
  "comments",
  "tags",
  "metrics",
  "reports",
  "files",
  "upload",
  "download",
  "orders",
  "payments",
];

const HTTP_METHODS: string[] = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"];

const MAX_SAMPLE_BODIES = 3;
const MAX_BODY_SIZE = 4096; // bytes

function simpleLetterGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

function mergeCounts<T extends string | number>(counts: Record<T, number>[], maxItems = 100): Record<T, number> {
  const result: Record<T, number> = {} as Record<T, number>;
  for (const c of counts) {
    for (const k in c) {
      if (Object.prototype.hasOwnProperty.call(c, k)) {
        const key = k as unknown as T;
        result[key] = (result[key] || 0) + c[key];
      }
    }
  }
  // Optional: trim to max items sorted by count desc
  const entries = Object.entries(result) as [T, number][];
  entries.sort((a, b) => b[1] - a[1]);
  if (entries.length > maxItems) {
    entries.splice(maxItems);
  }
  const trimmed: Record<T, number> = {} as Record<T, number>;
  for (const [k,v] of entries) trimmed[k] = v;
  return trimmed;
}

function sampleBody(bodyText: string): string {
  const trimmed = bodyText.trim();
  if (trimmed.length > 256) return trimmed.slice(0, 256) + "...";
  return trimmed;
}

async function probeMethod(url: string, method: string): Promise<{ status: number; contentType: string | null; sampleBody: string | null }> {
  const opts: RequestInit = {
    method,
    signal: AbortSignal.timeout(10000),
    headers: { "User-Agent": "api-endpoint-discovery-graph/1.0 apimesh.xyz" },
  };

  // In general, avoid sending body or content-type for probes

  try {
    const resp = await safeFetch(url, opts);
    const status = resp.status;
    const ct = resp.headers.get("content-type");

    let sample: string | null = null;

    if (resp.body && resp.body instanceof ReadableStream && status === 200) {
      try {
        const limitedBody = await readBodyCapped(resp, MAX_BODY_SIZE);
        const decoded = new TextDecoder().decode(limitedBody);
        sample = sampleBody(decoded);
      } catch {
        sample = null;
      }
    }

    return { status, contentType: ct, sampleBody: sample };
  } catch (e) {
    return { status: 0, contentType: null, sampleBody: null };
  }
}

function uniqueAdd<T>(arr: T[], item: T, maxLen: number): void {
  if (arr.length >= maxLen) return;
  if (!arr.includes(item)) arr.push(item);
}

// Build test paths recursively
function buildTestPaths(baseUrl: string, maxDepth: number): string[] {
  const paths: string[] = ["/"];
  if (maxDepth < 2) return paths;

  // Generate simple 1-level paths
  const level1 = COMMON_PATHS.map((p) => `/${p}`);
  paths.push(...level1);

  if (maxDepth < 3) return paths;

  // Generate simple 2-level paths
  for (const p1 of COMMON_PATHS) {
    for (const p2 of COMMON_PATHS) {
      paths.push(`/${p1}/${p2}`);
    }
  }

  // Cap total paths
  if (paths.length > 200) {
    return paths.slice(0, 200);
  }

  return paths;
}

export async function performDiscovery(request: EndpointDiscoveryRequest): Promise<EndpointDiscoveryResult | { error: string }> {
  // Validate URL
  const val = validateExternalUrl(request.url);
  if ("error" in val) return { error: val.error };

  const baseUrl = val.url.origin;

  const maxDepth = request.maxDepth && request.maxDepth > 0 && request.maxDepth <= 3 ? request.maxDepth : 2;
  const maxEndpoints = request.maxEndpoints && request.maxEndpoints > 0 ? Math.min(request.maxEndpoints, 100) : 50;

  const pathsToTest = buildTestPaths(baseUrl, maxDepth);

  const discovered: EndpointInfo[] = [];

  // Limit paths to maxEndpoints roughly
  const pathsLimited = pathsToTest.slice(0, maxEndpoints * 2);

  for (const path of pathsLimited) {
    const fullUrl = `${baseUrl}${path}`;

    const endpointData: EndpointInfo = {
      path,
      methods: [],
      statusCodes: {},
      contentTypes: {},
      sampleResponses: [],
      lastChecked: new Date().toISOString(),
    };

    // Probe all methods in parallel
    const probes = HTTP_METHODS.map((method) => probeMethod(fullUrl, method));

    let results: Awaited<ReturnType<typeof probeMethod>[]>;
    try {
      results = await Promise.all(probes);
    } catch (e) {
      // Defensive: on failure skip this path
      continue;
    }

    // Analyze results
    for (let i = 0; i < results.length; i++) {
      const res = results[i];
      if (res.status >= 200 && res.status < 600) {
        endpointData.methods.push(HTTP_METHODS[i]);
        endpointData.statusCodes[res.status] = (endpointData.statusCodes[res.status] || 0) + 1;
        if (res.contentType) {
          const ct = res.contentType.split(";")[0].trim().toLowerCase();
          endpointData.contentTypes[ct] = (endpointData.contentTypes[ct] || 0) + 1;
        }
        if (res.sampleBody) {
          uniqueAdd(endpointData.sampleResponses, res.sampleBody, MAX_SAMPLE_BODIES);
        }
      }
    }

    // Only include endpoints with >0 methods responding
    if (endpointData.methods.length > 0) {
      discovered.push(endpointData);
      if (discovered.length >= maxEndpoints) break;
    }

  }

  // Calculate score based on coverage and data richness
  // Coverage: % of tested paths with responses
  const coverage = discovered.length / pathsLimited.length;

  // Data richness: average number of methods, distinct status codes, distinct content types, presence of body samples
  let richnessScore = 0;
  if (discovered.length > 0) {
    let totMethods = 0;
    let totStatusCodes = 0;
    let totContentTypes = 0;
    let totSamples = 0;

    for (const ep of discovered) {
      totMethods += ep.methods.length;
      totStatusCodes += Object.keys(ep.statusCodes).length;
      totContentTypes += Object.keys(ep.contentTypes).length;
      totSamples += ep.sampleResponses.length;
    }
    richnessScore = (
      totMethods / discovered.length * 10 +
      totStatusCodes / discovered.length * 15 +
      totContentTypes / discovered.length * 15 +
      totSamples / discovered.length * 20
    );
    if (richnessScore > 50) richnessScore = 50;
  }

  // Combine for total score out of 100
  const totalScore = Math.round(coverage * 50 + richnessScore);
  const grade = simpleLetterGrade(totalScore);

  // Recommendations based on score and coverage
  const recommendations = [];
  if (coverage < 0.1) {
    recommendations.push({ issue: "Low endpoint coverage", severity: 80, suggestion: "Increase maxDepth or maxEndpoints, or provide manual endpoint list for better discovery." });
  }
  if (richnessScore < 20) {
    recommendations.push({ issue: "Low response data richness", severity: 60, suggestion: "Ensure target API responds to varied HTTP methods and returns meaningful content types and bodies." });
  }
  if (totalScore < 50) {
    recommendations.push({ issue: "Low overall discovery score", severity: 90, suggestion: "Review crawl parameters and improve endpoint responsiveness to enhance discovery quality." });
  }

  const explanation = `Discovery tested ${pathsLimited.length} paths, found ${discovered.length} responsive endpoints. Coverage: ${(coverage*100).toFixed(1)}%. Data richness score: ${richnessScore.toFixed(1)}. Combined score: ${totalScore}. Grade: ${grade}.`;

  return {
    baseUrl,
    crawledPaths: pathsLimited.length,
    discoveredEndpoints: discovered,
    score: totalScore,
    grade,
    recommendations,
    explanation,
    completedAt: new Date().toISOString(),
  };
}

export async function discoveryPreview(rawUrl: string): Promise<{ preview: true; baseUrl: string; samplePaths: string[]; note: string; timestamp: string } | { error: string }> {
  const val = validateExternalUrl(rawUrl);
  if ("error" in val) return { error: val.error };
  const baseUrl = val.url.origin;

  // Return up to 10 sample constructed paths
  const samplePaths = buildTestPaths(baseUrl, 1).slice(0, 10);
  return {
    preview: true,
    baseUrl,
    samplePaths,
    note: "Preview provides sample common API paths without live crawling or payment. For full discovery and analysis, use the paid /check endpoint.",
    timestamp: new Date().toISOString(),
  };
}
