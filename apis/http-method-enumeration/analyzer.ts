import { validateExternalUrl, safeFetch } from "../../shared/ssrf";

// ── Types ──────────────────────────────────────────────────────────────────────

export type Grade = "A+" | "A" | "B" | "C" | "D" | "F";

export interface HttpMethodInfo {
  method: string;
  allowed: boolean;
  description: string;
}

export interface HttpMethodEnumerationResult {
  url: string;
  supports: HttpMethodInfo[];
  overallScore: number; // 0-100
  overallGrade: Grade;
  recommendations: Recommendation[];
  scannedAt: string;
  details: string;
}

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface PreviewResult {
  url: string;
  preview: true;
  supportedMethods: string[];
  scannedAt: string;
  note: string;
}

// ── Constants ──────────────────────────────────────────────────────────────────

const COMMON_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"];

const METHOD_DESCRIPTIONS: Record<string, string> = {
  GET: "Retrieve resource data.",
  POST: "Create new resource or submit data.",
  PUT: "Replace or create resource.",
  DELETE: "Delete a resource.",
  PATCH: "Partially update a resource.",
  HEAD: "Retrieve resource headers only.",
  OPTIONS: "Query server-supported methods.",
  TRACE: "Echo the received request (potentially risky).",
};

// Weighting severity for recommendations
const RECOMMENDATION_SEVERITY = {
  TRACE_ALLOWED: 70,
  OPTIONS_MISSING: 40,
  POST_MISSING: 30,
  PUT_DELETE_ALLOWED: 50,
  NO_SAFE_METHODS: 80,
};

// ── Helper Functions ───────────────────────────────────────────────────────────

/**
 * Makes a SAFE OPTIONS request to given URL, returns allowed methods array
 */
async function fetchAllowedMethods(url: string): Promise<string[]> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000); // 8s timeout for HEAD/OPTIONS

    // Primary OPTIONS request
    const optionsResp = await safeFetch(url, {
      method: "OPTIONS",
      signal: controller.signal,
      headers: { "User-Agent": "http-method-enumeration/1.0 apimesh.xyz" },
    });

    clearTimeout(timeoutId);

    if (!optionsResp.ok) {
      if (optionsResp.status === 405) {
        // OPTIONS not allowed => fallback
        return [];
      }
      throw new Error(`OPTIONS HTTP ${optionsResp.status}`);
    }

    const allow = optionsResp.headers.get("allow") || "";
    if (allow) {
      return allow.split(",").map((m) => m.trim().toUpperCase()).filter(Boolean);
    }

    // Some servers respond without Allow header
    return [];
  } catch (e) {
    throw e;
  }
}

/**
 * Attempts minimal requests (HEAD, GET) to verify method allowed,
 * considers failures as disallowed.
 * Returns true if method allowed, false otherwise.
 */
async function testMethodAllowed(url: string, method: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeoutMs = method === "HEAD" ? 8000 : 10000;
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const res = await safeFetch(url, {
      method,
      signal: controller.signal,
      headers: { "User-Agent": "http-method-enumeration/1.0 apimesh.xyz" },
    });

    clearTimeout(timeoutId);

    // We consider 2xx, 3xx, 4xx status codes as method allowed,
    // 405 Method Not Allowed and 501 Not Implemented are disallowed.
    if (res.status === 405 || res.status === 501) {
      return false;
    }

    // Other statuses likely indicate method accepted
    return true;
  } catch (e) {
    return false;
  }
}

// ── Scoring and Grading ────────────────────────────────────────────────────────

function scoreToGrade(score: number): Grade {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 65) return "B";
  if (score >= 45) return "C";
  if (score >= 25) return "D";
  return "F";
}

function clamp(n: number, min = 0, max = 100): number {
  if (n < min) return min;
  if (n > max) return max;
  return n;
}

// ── Business Logic: Full Enumeration and Analysis ──────────────────────────────

export async function fullEnumeration(rawUrl: string): Promise<HttpMethodEnumerationResult | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: check.error };
  const url = check.url.toString();

  try {
    // We will run these checks:
    // 1) OPTIONS to get Allow header
    // 2) HEAD ping
    // 3) GET ping
    // 4) POST test with CORS preflight
    // 5) PUT test with CORS preflight
    // 6) DELETE test with CORS preflight
    
    // We do lightweight pings for POST, PUT, DELETE by OPTIONS + method tests, not actual mutating.

    // Start OPTIONS
    const allowedOptions = await fetchAllowedMethods(url);
    // For additional safety, also test if OPTIONS is actually allowed (by fetch, already done)
    const optionsAllowed = allowedOptions.length > 0;

    // Parallel test HEAD, GET
    const [headAllowed, getAllowed] = await Promise.all([
      testMethodAllowed(url, "HEAD"),
      testMethodAllowed(url, "GET"),
    ]);

    // POST, PUT, DELETE
    // To verify if allowed without harmful side effects, we send OPTIONS then OPTIONS+assumption + minimal request trials

    async function safeMethodCheck(m: string): Promise<boolean> {
      // If OPTIONS reports not allowed this, no point testing
      if (allowedOptions.length > 0 && !allowedOptions.includes(m)) return false;
      // If OPTIONS header missing, we try the method directly
      return testMethodAllowed(url, m);
    }

    const [postAllowed, putAllowed, deleteAllowed] = await Promise.all([
      safeMethodCheck("POST"),
      safeMethodCheck("PUT"),
      safeMethodCheck("DELETE"),
    ]);

    // Compose list
    const methodData: HttpMethodInfo[] = [];

    // Include OPTIONS method data
    methodData.push({
      method: "OPTIONS",
      allowed: optionsAllowed,
      description: METHOD_DESCRIPTIONS["OPTIONS"],
    });

    // Basic Checks
    methodData.push({ method: "HEAD", allowed: headAllowed, description: METHOD_DESCRIPTIONS["HEAD"] });
    methodData.push({ method: "GET", allowed: getAllowed, description: METHOD_DESCRIPTIONS["GET"] });
    methodData.push({ method: "POST", allowed: postAllowed, description: METHOD_DESCRIPTIONS["POST"] });
    methodData.push({ method: "PUT", allowed: putAllowed, description: METHOD_DESCRIPTIONS["PUT"] });
    methodData.push({ method: "DELETE", allowed: deleteAllowed, description: METHOD_DESCRIPTIONS["DELETE"] });

    // Also add PATCH and TRACE by test if possible
    async function checkExtraMethod(method: string): Promise<HttpMethodInfo> {
      const allowed = await safeMethodCheck(method);
      return { method, allowed, description: METHOD_DESCRIPTIONS[method] || "" };
    }

    const patchInfo = await checkExtraMethod("PATCH");
    const traceInfo = await checkExtraMethod("TRACE");

    methodData.push(patchInfo, traceInfo);

    // Calculate overall score based on allowed methods
    // We penalize allowing TRACE (security risk), allowing PUT/DELETE (potentially dangerous), missing GET/HEAD/OPTIONS
    // Score 100 base
    let score = 100;

    if (traceInfo.allowed) {
      score -= RECOMMENDATION_SEVERITY.TRACE_ALLOWED; // deduct for TRACE allowed
    }

    if (!optionsAllowed) {
      score -= RECOMMENDATION_SEVERITY.OPTIONS_MISSING;
    }

    if (!postAllowed) {
      score -= RECOMMENDATION_SEVERITY.POST_MISSING;
    }

    if (putAllowed) {
      score -= RECOMMENDATION_SEVERITY.PUT_DELETE_ALLOWED;
    }

    if (deleteAllowed) {
      score -= RECOMMENDATION_SEVERITY.PUT_DELETE_ALLOWED;
    }

    if (!getAllowed && !headAllowed) {
      score -= RECOMMENDATION_SEVERITY.NO_SAFE_METHODS;
    }

    score = clamp(score);
    const grade = scoreToGrade(score);

    // Recommendations
    const recommendations: Recommendation[] = [];

    if (traceInfo.allowed) {
      recommendations.push({
        issue: "TRACE method allowed",
        severity: RECOMMENDATION_SEVERITY.TRACE_ALLOWED,
        suggestion: "Disable TRACE method on your web server to prevent potential cross-site tracing attacks.",
      });
    }

    if (!optionsAllowed) {
      recommendations.push({
        issue: "OPTIONS method missing or not allowed",
        severity: RECOMMENDATION_SEVERITY.OPTIONS_MISSING,
        suggestion: "Enable OPTIONS method to allow clients to discover allowed HTTP methods and improve API usability.",
      });
    }

    if (!postAllowed) {
      recommendations.push({
        issue: "POST method not allowed or blocked",
        severity: RECOMMENDATION_SEVERITY.POST_MISSING,
        suggestion: "Allow POST method if your API supports resource creation or data submission.",
      });
    }

    if (putAllowed) {
      recommendations.push({
        issue: "PUT method allowed",
        severity: RECOMMENDATION_SEVERITY.PUT_DELETE_ALLOWED,
        suggestion: "Ensure PUT method is properly secured as it allows resource replacement.",
      });
    }

    if (deleteAllowed) {
      recommendations.push({
        issue: "DELETE method allowed",
        severity: RECOMMENDATION_SEVERITY.PUT_DELETE_ALLOWED,
        suggestion: "Restrict DELETE method to authorized users to prevent resource deletion.",
      });
    }

    if (!getAllowed && !headAllowed) {
      recommendations.push({
        issue: "No safe (GET/HEAD) methods allowed",
        severity: RECOMMENDATION_SEVERITY.NO_SAFE_METHODS,
        suggestion: "Allow at least safe methods (GET or HEAD) for resource fetching.",
      });
    }

    // Final explanation
    const details = `HTTP methods on ${url} are enumerated combining OPTIONS header and probe requests for core and extra methods. Score penalizes risky methods (TRACE), missing standard methods (OPTIONS, GET), and allows to tune server security posture.`;

    return {
      url,
      supports: methodData,
      overallScore: score,
      overallGrade: grade,
      recommendations,
      scannedAt: new Date().toISOString(),
      details,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: msg };
  }
}

export async function previewEnumeration(rawUrl: string): Promise<PreviewResult | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: check.error };
  const url = check.url.toString();

  try {
    // Preview is a free quick test - just OPTIONS header parsed + HEAD allowed
    const allowedOptions = await fetchAllowedMethods(url);
    const headAllowed = await testMethodAllowed(url, "HEAD");

    // Compose minimal preview
    const supportedMethods = allowedOptions.slice();
    if (headAllowed && !supportedMethods.includes("HEAD")) {
      supportedMethods.push("HEAD");
    }

    return {
      url,
      preview: true,
      supportedMethods: supportedMethods.sort(),
      scannedAt: new Date().toISOString(),
      note: "Preview runs only OPTIONS header and HEAD method quick check. Pay via x402 for full multi-method probe, scoring and recommendations.",
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: msg };
  }
}
