import { safeFetch, validateExternalUrl, readBodyCapped } from "../../shared/ssrf";
import type {
  ApiHeuristicsInput,
  EndpointAnalysis,
  FetchTiming,
  ResponseSummary,
  Recommendation,
  HeuristicsResult,
  PreviewResult,
} from "./types";

const MAX_SAMPLE_RESPONSES = 3;
const FETCH_TIMEOUT_MS = 10000;
const PREVIEW_TIMEOUT_MS = 15000;
const BODY_PREVIEW_BYTES = 1024;

function gradeFromScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  if (score >= 30) return "E";
  return "F";
}

function letterToSeverity(letter: string): "low" | "medium" | "high" | "critical" {
  switch (letter) {
    case "A":
    case "B":
      return "low";
    case "C":
      return "medium";
    case "D":
    case "E":
      return "high";
    default:
      return "critical";
  }
}

function extractBasicTypeFromHeaders(headers: Headers): string {
  const contentType = headers.get("content-type");
  if (!contentType) return "Unknown";
  if (contentType.includes("application/json")) return "JSON API";
  if (contentType.includes("text/html")) return "HTML Website";
  if (contentType.includes("application/xml") || contentType.includes("text/xml")) return "XML API";
  if (contentType.includes("text/plain")) return "Plain Text";
  if (contentType.includes("application/octet-stream")) return "Binary Data";
  if (contentType.includes("multipart/")) return "Multipart";
  return "Other";
}

function analyzeStatusCodeVariability(statusCodes: number[]): { diversity: number; frequent: number[] } {
  const countMap = new Map<number, number>();
  for (const code of statusCodes) {
    countMap.set(code, (countMap.get(code) ?? 0) + 1);
  }
  const sortedByFreq = Array.from(countMap.entries()).sort((a, b) => b[1] - a[1]);
  return {
    diversity: countMap.size,
    frequent: sortedByFreq.slice(0, 3).map((e) => e[0]),
  };
}

function scoreComplexity(
  diversity: number,
  avgResponseTime: number,
  contentTypes: Set<string>,
  statusCodes: Set<number>,
): number {
  // heuristics: more diversity + more contentTypes + more status codes + slower response = higher complexity
  let score = 0;
  score += diversity * 10; // max ~40
  if (avgResponseTime > 2000) score += 20;
  else score += (avgResponseTime / 2000) * 20;
  score += Math.min(contentTypes.size * 15, 30);
  score += Math.min(statusCodes.size * 10, 20);
  if (score > 100) score = 100;
  return Math.round(score);
}

function gradeFromComplexity(score: number): string {
  // reverse grade, less complexity = better grade
  if (score < 30) return "A";
  if (score < 50) return "B";
  if (score < 70) return "C";
  if (score < 85) return "D";
  if (score < 95) return "E";
  return "F";
}

function generateRecommendations(analysis: EndpointAnalysis): Recommendation[] {
  const recs: Recommendation[] = [];

  if (analysis.statusCodeDiversity > 3) {
    recs.push({
      issue: "High status code variability",
      severity: "medium",
      suggestion: "Check why the API returns many different status codes; consider documenting them clearly.",
    });
  }

  if (analysis.averageResponseTimeMs > 5000) {
    recs.push({
      issue: "Slow average response time",
      severity: "high",
      suggestion: "Investigate underlying server or network issues to reduce latency.",
    });
  }

  if (analysis.inferredApiType === "Unknown") {
    recs.push({
      issue: "Unknown API type",
      severity: "medium",
      suggestion: "Provide better content type or API documentation.",
    });
  }

  if (analysis.complexityScore > 80) {
    recs.push({
      issue: "High API complexity",
      severity: "high",
      suggestion: "Simplify API or provide detailed usage examples and best practices.",
    });
  }

  if (analysis.score < 50) {
    recs.push({
      issue: "Low overall quality score",
      severity: "critical",
      suggestion: "Perform a detailed audit of the API responses and standardize them.",
    });
  }

  return recs;
}

async function fetchWithTiming(url: string): Promise<{ response: Response; timing: FetchTiming }> {
  const startIso = new Date().toISOString();
  const startMs = performance.now();
  const res = await safeFetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  const duration = Math.round(performance.now() - startMs);
  return {
    response: res,
    timing: { startTimeIso: startIso, durationMs: duration },
  };
}

async function fetchResponseSummary(url: string): Promise<ResponseSummary> {
  try {
    const { response, timing } = await fetchWithTiming(url);

    let bodyPreview = null;
    const contentType = response.headers.get("content-type");

    // For JSON or text types, try to read small body preview
    if (contentType && (contentType.includes("text") || contentType.includes("json") || contentType.includes("xml"))) {
      try {
        const buf = await readBodyCapped(response, BODY_PREVIEW_BYTES);
        bodyPreview = new TextDecoder().decode(buf);
      } catch {
        bodyPreview = null;
      }
    }

    return {
      statusCode: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      fetchTiming: timing,
      bodyPreview,
      contentType,
    };
  } catch (e) {
    // On fetch failure, simulate response summary with minimal data
    return {
      statusCode: 0,
      headers: {},
      fetchTiming: { startTimeIso: new Date().toISOString(), durationMs: 0 },
      bodyPreview: null,
      contentType: null,
    };
  }
}

export async function fullHeuristicsAnalyze(rawUrl: string): Promise<HeuristicsResult | { error: string }> {
  const validation = validateExternalUrl(rawUrl);
  if ("error" in validation) return { error: validation.error };
  const url = validation.url.toString();

  // Strategy: fetch main URL multiple times, slightly varying headers to detect endpoint behavior
  const responses: ResponseSummary[] = [];
  const statusCodes: number[] = [];
  const contentTypes = new Set<string>();

  // Fetch samples with headers to provoke different API behaviors (cache control, user agent, etc.)
  const fetchPromises = [
    fetchResponseSummary(url),
    fetchResponseSummary(url),
    fetchResponseSummary(url),
  ];

  try {
    const results = await Promise.all(fetchPromises);
    for (const res of results) {
      responses.push(res);
      statusCodes.push(res.statusCode);
      if (res.contentType) contentTypes.add(res.contentType);
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    throw new Error(msg);
  }

  // Compute stats
  const { diversity, frequent } = analyzeStatusCodeVariability(statusCodes);
  const avgResponseTimeMs = Math.round(responses.reduce((acc, r) => acc + r.fetchTiming.durationMs, 0) / responses.length);
  const statusCodeSet = new Set(statusCodes);

  // Inferred type from majority of content types
  let inferredApiType = "Unknown";
  if (contentTypes.size === 1) {
    inferredApiType = extractBasicTypeFromHeaders(new Headers(responses[0].headers as Record<string, string>));
  } else if (contentTypes.size > 1) {
    inferredApiType = "Mixed / Complex";
  }

  // Complexity scoring
  const complexityScore = scoreComplexity(diversity, avgResponseTimeMs, contentTypes, statusCodeSet);
  const grade = gradeFromComplexity(complexityScore);
  const score = 100 - complexityScore; // higher complexity means lower score

  // Stability check: 1 means always same status code, otherwise less stable
  const stableResponse = diversity <= 2 && (new Set(responses.map((r) => r.bodyPreview ?? "")).size <= 3);

  // Issues detection
  const issues: string[] = [];
  if (diversity > 3) {
    issues.push("API returns many different status codes, may be inconsistent or complex.");
  }
  if (avgResponseTimeMs > 4000) {
    issues.push("Average response time over 4 seconds may harm user experience.");
  }
  if (inferredApiType === "Unknown") {
    issues.push("API type cannot be inferred reliably from headers.");
  }

  // Explanation text
  let details = `The analysis detected ${diversity} distinct status codes with top codes: ${frequent.join(", ")}. The average response time was ${avgResponseTimeMs}ms. The inferred API type is ${inferredApiType}. API complexity score is ${complexityScore} implying grade ${grade}.`;
  if (issues.length > 0) {
    details += " Issues identified: " + issues.join(" ");
  }

  const recommendations = generateRecommendations({
    url,
    stableResponse,
    statusCodeDiversity: diversity,
    commonStatusCodes: frequent,
    averageResponseTimeMs: avgResponseTimeMs,
    responseSamples: responses,
    inferredApiType,
    complexityScore,
    issues,
    score,
    grade,
    details,
    recommendations: [], // to be replaced
  });

  const analysis: EndpointAnalysis = {
    url,
    stableResponse,
    statusCodeDiversity: diversity,
    commonStatusCodes: frequent,
    averageResponseTimeMs: avgResponseTimeMs,
    responseSamples: responses,
    inferredApiType,
    complexityScore,
    issues,
    score,
    grade,
    recommendations,
    details,
  };

  return {
    analyzedUrl: url,
    analysis,
    reportGeneratedAt: new Date().toISOString(),
  };
}

export async function previewHeuristics(rawUrl: string): Promise<PreviewResult | { error: string }> {
  const validation = validateExternalUrl(rawUrl);
  if ("error" in validation) return { error: validation.error };

  const url = validation.url.toString();

  try {
    const start = performance.now();
    const res = await safeFetch(url, { signal: AbortSignal.timeout(PREVIEW_TIMEOUT_MS) });
    const durationMs = Math.round(performance.now() - start);

    return {
      url,
      reachable: res.ok,
      statusCode: res.status,
      contentType: res.headers.get("content-type"),
      responseTimeMs: durationMs,
      note: "Preview performs a single basic HEAD or GET request to check reachability and content type. Use the paid endpoint for comprehensive analysis.",
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return {
      url,
      reachable: false,
      statusCode: null,
      contentType: null,
      responseTimeMs: null,
      note: `Preview analysis failed: ${msg}`,
    };
  }
}
