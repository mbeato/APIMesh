import { safeFetch, validateExternalUrl } from "../../shared/ssrf";

// Types for heuristic results
export interface Recommendation {
  issue: string;
  severity: number; // 0-100 severity where higher is more severe
  suggestion: string;
}

export interface EndpointHeuristicsResult {
  isLikelyApi: boolean; // probability the endpoint is an API
  isRestResource: boolean; // probability the endpoint is typical REST resource
  isStaticPage: boolean; // probability the endpoint serves a mostly static page
  apiConfidence: number; // 0-100 confidence score
  restConfidence: number; // 0-100 confidence score
  staticConfidence: number; // 0-100 confidence score
  patternScore: number; // score reflecting route pattern complexity and API-like layout
  recommendations: Recommendation[];
  explanation: string; // human readable explanation
}

// Helper to score letter grade from score 0..100
export function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 45) return "D";
  return "F";
}

// Check if path segments look like placeholders, param ids, or resource ids
function looksLikeIdSegment(segment: string): boolean {
  if (!segment) return false;
  // UUID v4, simplified
  if (/^[a-f0-9]{8}-[a-f0-9]{4}-[1345][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(segment)) return true;
  // Numeric ids
  if (/^\d+$/.test(segment)) return true;
  // Hex short id
  if (/^[a-f0-9]{4,}$/.test(segment)) return true;
  // Common param names
  if (segment.toLowerCase().startsWith("id")) return true;
  return false;
}

// Check if path looks like common API prefixes
const commonApiPrefixes = ["api", "v1", "v2", "rest", "services", "svc", "graphql", "json"];

// Count number of query parameters
function countQueryParams(url: URL): number {
  return [...url.searchParams.keys()].length;
}

// Check if query parameters look like typical API parameters (filter, sort, limit, offset, etc)
const commonApiParams = new Set(["filter", "sort", "limit", "offset", "page", "per_page", "fields", "expand"]);

function countApiLikeQueryParams(url: URL): number {
  let count = 0;
  for (const key of url.searchParams.keys()) {
    if (commonApiParams.has(key.toLowerCase())) count++;
  }
  return count;
}

// Check if path segments have typical API naming patterns
function analyzePathSegments(pathname: string): {
  totalSegments: number;
  idSegments: number;
  camelCaseSegments: number;
  snakeCaseSegments: number;
  kebabCaseSegments: number;
  allLowercase: boolean;
  containsCommonApiPrefix: boolean;
} {
  const segments = pathname.split("/").filter(Boolean);
  let idSegments = 0;
  let camelCaseSegments = 0;
  let snakeCaseSegments = 0;
  let kebabCaseSegments = 0;
  let allLowercase = true;
  let containsCommonApiPrefix = false;

  for (const seg of segments) {
    if (looksLikeIdSegment(seg)) idSegments++;

    // camelCase check (not all lowercase and has uppercase letter)
    if (/[A-Z]/.test(seg)) {
      camelCaseSegments++;
      allLowercase = false;
    } else if (seg.includes("_")) {
      snakeCaseSegments++;
    } else if (seg.includes("-")) {
      kebabCaseSegments++;
    } else {
      // segment with no uppercase and no _ or -
      if (seg.toLowerCase() !== seg) allLowercase = false;
    }

    if (commonApiPrefixes.includes(seg.toLowerCase())) containsCommonApiPrefix = true;
  }

  return {
    totalSegments: segments.length,
    idSegments,
    camelCaseSegments,
    snakeCaseSegments,
    kebabCaseSegments,
    allLowercase,
    containsCommonApiPrefix,
  };
}

// Main analyze function
export async function analyzeEndpoint(rawUrl: string): Promise<EndpointHeuristicsResult | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) {
    return { error: check.error };
  }

  try {
    const url = check.url;

    // Run concurrent tasks to fetch headers and attempt GET with partial body
    // to look for content-type, example responses, or hints

    // Timeout controller for fetch
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    // Fetch HEAD for headers
    const headP = safeFetch(url.toString(), {
      method: "HEAD",
      headers: { "User-Agent": "api-endpoint-heuristics/1.0 apimesh.xyz" },
      signal: controller.signal,
      timeoutMs: 8000,
    }).catch(() => null);

    // Fetch GET for small sample body
    const getP = safeFetch(url.toString(), {
      method: "GET",
      headers: { "User-Agent": "api-endpoint-heuristics/1.0 apimesh.xyz" },
      signal: controller.signal,
      timeoutMs: 10000,
    }).catch(() => null);

    const [headRes, getRes] = await Promise.all([headP, getP]);
    clearTimeout(timeoutId);

    // Analysis variables
    const pathAnalysis = analyzePathSegments(url.pathname);
    const queryParamCount = countQueryParams(url);
    const apiLikeQueryParamCount = countApiLikeQueryParams(url);

    // Heuristic scoring variables
    let apiScore = 0;
    let restScore = 0;
    let staticPageScore = 0;
    const recs: Recommendation[] = [];

    // Heuristic 1: Path prefix
    if (pathAnalysis.containsCommonApiPrefix) {
      apiScore += 20;
      recs.push({
        issue: "Common API prefix detected in path",
        severity: 20,
        suggestion: "Standard API prefixes like /api, /v1 help identify API endpoints.",
      });
    }

    // Heuristic 2: Path complexity
    if (pathAnalysis.totalSegments >= 3) {
      apiScore += 15;
      restScore += 10;
    } else if (pathAnalysis.totalSegments === 2) {
      apiScore += 10;
      restScore += 5;
    } else {
      staticPageScore += 10;
      recs.push({
        issue: "Shallow URL path segments",
        severity: 15,
        suggestion: "Deep nested paths often indicate APIs or apps rather than static pages.",
      });
    }

    // Heuristic 3: ID placeholders in path
    if (pathAnalysis.idSegments > 0) {
      restScore += 20;
      apiScore += 10;
    } else {
      staticPageScore += 5;
      recs.push({
        issue: "No ID-like segments detected",
        severity: 10,
        suggestion: "REST resources usually have identifiers in path segments.",
      });
    }

    // Heuristic 4: Parameter usage
    if (apiLikeQueryParamCount > 0) {
      apiScore += 15;
      restScore += 10;
    }
    if (queryParamCount > 5) {
      apiScore += 10;
      recs.push({
        issue: "High number of query parameters",
        severity: 15,
        suggestion: "APIs often utilize query params for filters, pagination, and sorting.",
      });
    } else if (queryParamCount === 0) {
      staticPageScore += 10;
    }

    // Heuristic 5: Path naming style
    if (pathAnalysis.camelCaseSegments > 0) {
      apiScore += 10;
      recs.push({
        issue: "CamelCase in path segments",
        severity: 25,
        suggestion: "Avoid camelCase in path segments; kebab-case or snake_case preferred for REST APIs.",
      });
    }
    if (pathAnalysis.kebabCaseSegments > 0 || pathAnalysis.snakeCaseSegments > 0) {
      restScore += 10;
    }

    // Heuristic 6: Attempt to detect static page by file extension
    const lowerPath = url.pathname.toLowerCase();
    if (lowerPath.match(/\.(html|htm|php|asp|aspx|jsp|jspx|json|xml|txt|md)$/)) {
      staticPageScore += 15;
      recs.push({
        issue: "URI contains file extension typical of pages or documents",
        severity: 20,
        suggestion: "File extensions usually indicate static or dynamic pages rather than API endpoints.",
      });
    }

    // Heuristic 7: Check content-type headers from HEAD or GET
    let contentType = "";
    if (headRes && headRes.ok) {
      contentType = headRes.headers.get("content-type") || "";
    }
    if (!contentType && getRes && getRes.ok) {
      contentType = getRes.headers.get("content-type") || "";
    }

    // Check if content type indicates JSON data
    if (contentType.includes("application/json") || contentType.includes("application/vnd.api+json")) {
      apiScore += 25;
      restScore += 15;
      recs.push({
        issue: "Response content-type is JSON",
        severity: 30,
        suggestion: "JSON content-type strongly indicates an API or REST resource.",
      });
    } else if (contentType.includes("text/html")) {
      staticPageScore += 20;
      recs.push({
        issue: "Response content-type is HTML",
        severity: 10,
        suggestion: "HTML content-type is typical for static or dynamic pages, less so for APIs.",
      });
    } else if (contentType.includes("text/plain")) {
      staticPageScore += 5;
    } else if (contentType.includes("application/xml") || contentType.includes("text/xml")) {
      apiScore += 15;
      recs.push({
        issue: "Response content-type is XML",
        severity: 15,
        suggestion: "Some older APIs use XML response format.",
      });
    }

    // Heuristic 8: Try to parse small JSON from GET body if possible
    let sampleJson: any = null;
    if (getRes && getRes.ok && contentType.includes("application/json")) {
      try {
        const text = await getRes.text();
        if (text.length > 0 && text.length < 32_768) {
          sampleJson = JSON.parse(text);
        }
      } catch {
        sampleJson = null;
      }
    }

    // If sampleJson is an object and has common API response keys
    if (sampleJson && typeof sampleJson === "object") {
      const keys = new Set(Object.keys(sampleJson));
      if (keys.has("data") || keys.has("results") || keys.has("items")) {
        apiScore += 30;
        restScore += 25;
        recs.push({
          issue: "Response JSON contains common API keys like 'data', 'results'.",
          severity: 40,
          suggestion: "This strongly indicates a RESTful or API endpoint.",
        });
      }

      if (keys.has("html") || keys.has("content") || keys.has("page")) {
        staticPageScore += 10;
        recs.push({
          issue: "Response JSON contains keys typical for page content.",
          severity: 20,
          suggestion: "Might be a static/dynamic page embed or CMS data.",
        });
      }
    }

    // Normalize scores to 0-100 range and clamp
    apiScore = Math.min(Math.max(apiScore, 0), 100);
    restScore = Math.min(Math.max(restScore, 0), 100);
    staticPageScore = Math.min(Math.max(staticPageScore, 0), 100);

    // Final decisions
    const isLikelyApi = apiScore > 65;
    const isRestResource = restScore > 65;
    const isStaticPage = staticPageScore > 50;

    // Compose explanation text
    let explanation = `Analysis based on URL structure, headers, and content type. `;
    explanation += `API confidence: ${apiScore}%. REST resource confidence: ${restScore}%. Static page confidence: ${staticPageScore}%. `;
    explanation += `Recommendations provided to improve heuristics or naming style.`;

    return {
      isLikelyApi,
      isRestResource,
      isStaticPage,
      apiConfidence: apiScore,
      restConfidence: restScore,
      staticConfidence: staticPageScore,
      patternScore: restScore, // reusing restScore as pattern complexity
      recommendations: recs,
      explanation,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Internal error during analysis: ${msg}` };
  }
}
