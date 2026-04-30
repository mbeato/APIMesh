import { safeFetch } from "../../shared/ssrf";

// --- Types ---
export interface CorsPolicyAnalysisResult {
  url: string;
  corsHeaders: Record<string, string | null>;
  preflightResult: PreflightCheckResult | null;
  reflectedOriginDetected: boolean;
  score: number; // 0-100
  grade: string; // A-F
  recommendations: Recommendation[];
  explanation: string;
}

export interface PreflightCheckResult {
  status: number;
  allowedMethods: string[];
  allowedHeaders: string[];
  maxAgeSeconds: number | null;
}

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface CorsPreviewResult {
  url: string;
  corsHeadersPresent: boolean;
  credentialsAllowed: boolean;
  explanation: string;
  error?: string;
}

// Constants
const CORS_HEADER_KEYS = [
  "access-control-allow-origin",
  "access-control-allow-methods",
  "access-control-allow-headers",
  "access-control-allow-credentials",
  "access-control-expose-headers",
  "access-control-max-age",
];

// Helper to parse comma separated header into normalized array
function parseCsvHeader(header: string | null): string[] {
  if (!header) return [];
  return header
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
}

// Helper to compute letter grade from score
function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 45) return "D";
  if (score >= 30) return "E";
  return "F";
}

// --- Core Analysis Functions ---

// Validate origin reflection by sending a fake Origin header and detecting if it's reflected verbatim
async function checkReflectedOrigin(
  url: URL,
  signal: AbortSignal
): Promise<boolean> {
  const testOrigin = "https://evil.example.com";
  try {
    const res = await safeFetch(url.toString(), {
      method: "OPTIONS",
      headers: { Origin: testOrigin },
      signal,
      timeoutMs: 10000,
    });
    const acoHeader = res.headers.get("access-control-allow-origin") || "";
    // Detect exact match reflecting test origin (dangerous)
    return acoHeader === testOrigin;
  } catch {
    return false; // On error, assume no reflection detected
  }
}

// Perform preflight OPTIONS request with max timeout 10s
async function performPreflightCheck(
  url: URL,
  signal: AbortSignal
): Promise<PreflightCheckResult | null> {
  try {
    // Common preflight custom header & method
    const reqHeaders = {
      Origin: url.origin,
      "Access-Control-Request-Method": "PUT",
      "Access-Control-Request-Headers": "X-Custom-Header,Content-Type",
    };
    const res = await safeFetch(url.toString(), {
      method: "OPTIONS",
      headers: reqHeaders,
      signal,
      timeoutMs: 10000,
    });
    const status = res.status;

    const allowedMethods = parseCsvHeader(res.headers.get("access-control-allow-methods"));
    const allowedHeaders = parseCsvHeader(res.headers.get("access-control-allow-headers"));

    const maxAgeRaw = res.headers.get("access-control-max-age");
    let maxAgeSeconds: number | null = null;
    if (maxAgeRaw) {
      const num = Number(maxAgeRaw);
      if (!isNaN(num) && num >= 0) maxAgeSeconds = Math.floor(num);
    }

    return { status, allowedMethods, allowedHeaders, maxAgeSeconds };
  } catch {
    return null;
  }
}

// Extract relevant CORS headers from response headers
function extractCorsHeaders(headers: Headers): Record<string, string | null> {
  const result: Record<string, string | null> = {};
  for (const key of CORS_HEADER_KEYS) {
    result[key] = headers.get(key);
  }
  return result;
}

// Compute detailed score with weighting
function computeScore(
  corsHeaders: Record<string, string | null>,
  preflight: PreflightCheckResult | null,
  originReflected: boolean
): { score: number; grade: string; recommendations: Recommendation[]; explanation: string } {
  // Start 100
  let score = 100;
  const recs: Recommendation[] = [];
  const explanations: string[] = [];

  // Check allow-origin header
  const aco = corsHeaders["access-control-allow-origin"];
  if (!aco) {
    score -= 40;
    recs.push({
      issue: "Missing Access-Control-Allow-Origin header.",
      severity: 90,
      suggestion: "Add a restrictive Access-Control-Allow-Origin header to allow only specific origins.",
    });
    explanations.push("No Access-Control-Allow-Origin header is present, so CORS is not enabled.");
  } else if (aco === "*") {
    score -= 40;
    recs.push({
      issue: "Access-Control-Allow-Origin is '*', allowing any origin.",
      severity: 80,
      suggestion: "Specify allowed origins explicitly instead of '*'.",
    });
    explanations.push("The wildcard '*' allows any origin, increasing risk if credentials are allowed.");
  } else if (originReflected) {
    score -= 35;
    recs.push({
      issue: "Access-Control-Allow-Origin reflects the Origin header dynamically.",
      severity: 85,
      suggestion: "Avoid reflecting dynamic Origin values. Use a whitelist of trusted origins.",
    });
    explanations.push("The server reflects back the Origin header dynamically, which can expose credentials to arbitrary origins.");
  } else {
    explanations.push("Access-Control-Allow-Origin header is set specifically and does not reflect origin.");
  }

  // Check Allow-Credentials
  const acc = corsHeaders["access-control-allow-credentials"];
  if (acc && acc.toLowerCase() === "true") {
    // Allow credentials enabled
    if (!aco || aco === "*") {
      score -= 50;
      recs.push({
        issue: "Access-Control-Allow-Credentials enabled but origin is '*' or missing.",
        severity: 90,
        suggestion: "Do not allow credentials with wildcard origin. Specify allowed origins explicitly.",
      });
      explanations.push("Credentials allowed but origin is too permissive.");
    } else {
      score -= 10;
      recs.push({
        issue: "Access-Control-Allow-Credentials is true.",
        severity: 60,
        suggestion: "Ensure allowed origins are strictly controlled when credentials are allowed.",
      });
      explanations.push("Credentials are allowed; ensure origins are restricted.");
    }
  } else {
    explanations.push("Credentials are not allowed to be sent.");
  }

  // Check Access-Control-Allow-Methods
  if (corsHeaders["access-control-allow-methods"] == null) {
    score -= 10;
    recs.push({
      issue: "Missing Access-Control-Allow-Methods header.",
      severity: 50,
      suggestion: "Explicitly specify allowed HTTP methods in Access-Control-Allow-Methods header.",
    });
    explanations.push("Missing Access-Control-Allow-Methods reduces control over allowed HTTP methods.");
  }

  // Preflight specific checks
  if (preflight) {
    // Status must be 204 or no content
    if (preflight.status !== 204) {
      score -= 10;
      recs.push({
        issue: `Preflight OPTIONS request returned status code ${preflight.status} (expected 204).`,
        severity: 55,
        suggestion: "Respond to preflight OPTIONS requests with 204 No Content status.",
      });
      explanations.push("Preflight response status code is not 204.");
    }
    if (preflight.allowedMethods.length === 0) {
      score -= 15;
      recs.push({
        issue: "Preflight Access-Control-Allow-Methods header is empty.",
        severity: 55,
        suggestion: "Specify allowed HTTP methods explicitly in preflight response.",
      });
      explanations.push("No allowed methods reported in preflight.");
    }
    if (preflight.allowedHeaders.length === 0) {
      score -= 10;
      recs.push({
        issue: "Preflight Access-Control-Allow-Headers header is empty.",
        severity: 55,
        suggestion: "Specify allowed headers explicitly in preflight response.",
      });
      explanations.push("No allowed headers reported in preflight.");
    }
    if (preflight.maxAgeSeconds !== null) {
      if (preflight.maxAgeSeconds > 86400) {
        score -= 5;
        recs.push({
          issue: `Preflight Access-Control-Max-Age is very long (${preflight.maxAgeSeconds} seconds).`,
          severity: 40,
          suggestion: "Reduce max-age to mitigate impact of potential misconfigurations or attacks.",
        });
        explanations.push("A long preflight max-age increases exposure duration.");
      } else {
        explanations.push(`Preflight Access-Control-Max-Age is ${preflight.maxAgeSeconds} seconds.`);
      }
    } else {
      explanations.push("No Access-Control-Max-Age header in preflight response.");
    }
  } else {
    score -= 15;
    recs.push({
      issue: "No successful preflight response discovered.",
      severity: 75,
      suggestion: "Handle OPTIONS preflight requests correctly to allow complex CORS requests.",
    });
    explanations.push("Preflight OPTIONS request failed or not handled properly.");
  }

  // Clamp score
  if (score < 0) score = 0;
  if (score > 100) score = 100;

  const grade = scoreToGrade(score);
  const explanation = explanations.join(" ");

  return { score, grade, recommendations: recs, explanation };
}


// --- Public APIs ---

// Perform comprehensive analysis including multi-step fetches and tests
export async function performFullAnalysis(
  url: URL
): Promise<CorsPolicyAnalysisResult | { error: string }> {
  // Timeout signal with 10s for fetches
  const signal = AbortSignal.timeout(10000);

  try {
    // 1) Fetch main page GET
    const fetchMainP = safeFetch(url.toString(), {
      method: "GET",
      signal,
      timeoutMs: 10000,
      headers: { "User-Agent": "cors-policy-check/1.0 apimesh.xyz" },
    });

    // 2) Check origin reflection with OPTIONS
    const originReflectP = checkReflectedOrigin(url, signal);

    // 3) Preflight OPTIONS fetch
    const preflightP = performPreflightCheck(url, signal);

    // Await in parallel
    const [mainRes, originReflected, preflight] = await Promise.all([
      fetchMainP,
      originReflectP,
      preflightP,
    ]);

    // Extract CORS headers
    const corsHeaders = extractCorsHeaders(mainRes.headers);

    // Analyze scoring and recommendations
    const { score, grade, recommendations, explanation } = computeScore(
      corsHeaders,
      preflight,
      originReflected
    );

    return {
      url: url.toString(),
      corsHeaders,
      preflightResult: preflight,
      reflectedOriginDetected: originReflected,
      score,
      grade,
      recommendations,
      explanation,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Failed to analyze CORS policies: ${msg}` };
  }
}

// Perform lightweight preview analysis
export async function performPreviewAnalysis(
  url: URL
): Promise<CorsPreviewResult | { error: string }> {
  const signal = AbortSignal.timeout(20000); // generous timeout
  try {
    const res = await safeFetch(url.toString(), {
      method: "GET",
      signal,
      timeoutMs: 20000,
      headers: { "User-Agent": "cors-policy-check-preview/1.0 apimesh.xyz" },
    });
    const corsHeadersPresent =
      CORS_HEADER_KEYS.some((key) => res.headers.has(key));

    const accRaw = res.headers.get("access-control-allow-credentials");
    const credentialsAllowed = accRaw !== null && accRaw.toLowerCase() === "true";

    const explanation = corsHeadersPresent
      ? credentialsAllowed
        ? "CORS headers detected with credentials allowed."
        : "CORS headers detected but credentials are not allowed."
      : "No CORS headers detected.";

    return {
      url: url.toString(),
      corsHeadersPresent,
      credentialsAllowed,
      explanation,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Preview analysis failed: ${msg}`, url: url.toString(), corsHeadersPresent: false, credentialsAllowed: false, explanation: "" };
  }
}
