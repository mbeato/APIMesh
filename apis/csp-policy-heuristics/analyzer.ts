import { validateExternalUrl, safeFetch } from "../../shared/ssrf";

// -- Type definitions --

export interface Recommendation {
  issue: string;
  severity: "low" | "medium" | "high";
  suggestion: string;
}

export interface CspPolicyAnalysisResult {
  url: string;
  cspScore: number; // 0-100
  cspGrade: "A" | "B" | "C" | "D" | "F";
  insecureResourcesCount: number;
  activeMixedContent: boolean;
  evaluations: {
    inlineScripts: number;
    unsafeEvalUsage: boolean;
    wildcardSources: boolean;
    legacyDirectives: boolean;
  };
  recommendations: Recommendation[];
  details: string;
}

// -- Utility functions --
function gradeFromScore(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

function commonUserAgentHeader() {
  return { "User-Agent": "csp-policy-heuristics/1.0 apimesh.xyz" };
}

// Helper to parse CSP header string into directive map
function parseCspHeader(csp: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  const parts = csp.split(/;/g).map((p) => p.trim()).filter(Boolean);
  for (const p of parts) {
    const [directiveName, ...values] = p.split(/\s+/);
    directives.set(directiveName.toLowerCase(), values);
  }
  return directives;
}

// Validate if URL is https, return boolean
function isHttps(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === "https:";
  } catch {
    return false;
  }
}

// Extract script-src, style-src, img-src URLs from CSP directives
function extractCspUrls(directives: Map<string, string[]>): string[] {
  const urls: string[] = [];
  for (const [dir, values] of directives.entries()) {
    if (["script-src", "style-src", "img-src", "default-src"].includes(dir)) {
      for (const v of values) {
        if (!v.startsWith("'") && !v.includes("nonce-") && !v.includes("sha256-") && !v.includes("sha384-") && !v.includes("sha512-")) {
          urls.push(v);
        }
      }
    }
  }
  return urls;
}

// Main preview audit: limited CSP heuristic checks
export async function runPreviewAudit(rawUrl: string): Promise<CspPolicyAnalysisResult | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: check.error };
  const url = check.url.toString();

  // AbortSignal generous timeout for preview (20s)
  const signal = AbortSignal.timeout(20_000);

  let res: Response;
  try {
    res = await safeFetch(url, {
      method: "GET",
      headers: commonUserAgentHeader(),
      signal,
      redirect: "follow",
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Failed to fetch page: ${msg}` };
  }

  // Extract CSP header
  const cspRaw = res.headers.get("content-security-policy") || "";
  let cspScore = 60; // Default middle value for preview
  let recommendations: Recommendation[] = [];
  let details = "Preview analysis focused on CSP header and mixed content detection.";

  const directives = parseCspHeader(cspRaw);
  
  // Basic checks
  const scriptSrc = directives.get("script-src") || directives.get("default-src") || [];

  let scoreAdjust = 0;
  // Check unsafe-inline and unsafe-eval
  if (scriptSrc.includes("'unsafe-inline'")) {
    recommendations.push({
      issue: "Use of 'unsafe-inline' in script-src",
      severity: "high",
      suggestion: "Remove 'unsafe-inline' from script-src to enhance XSS protection.",
    });
    scoreAdjust -= 25;
  }
  if (scriptSrc.includes("'unsafe-eval'")) {
    recommendations.push({
      issue: "Use of 'unsafe-eval' in script-src",
      severity: "medium",
      suggestion: "Avoid 'unsafe-eval' to prevent dynamic code execution risks.",
    });
    scoreAdjust -= 15;
  }

  // Count number of insecure (http:) resource URLs
  const resourceUrls = extractCspUrls(directives);
  let insecureResourcesCount = 0;
  for (const rUrl of resourceUrls) {
    if (rUrl === "*") {
      recommendations.push({
        issue: "Wildcard '*' source in CSP",
        severity: "medium",
        suggestion: "Restrict sources to trusted domains instead of '*'.",
      });
      scoreAdjust -= 20;
    } else if (!isHttps(rUrl) && !['data:', 'blob:', 'self', 'none'].includes(rUrl)) {
      insecureResourcesCount++;
      recommendations.push({
        issue: `Insecure resource source: ${rUrl}`,
        severity: "high",
        suggestion: "Change resource URLs to HTTPS to avoid mixed content issues.",
      });
      scoreAdjust -= 30;
    }
  }

  // Cap score between 0 and 100
  cspScore = Math.max(0, Math.min(100, cspScore + scoreAdjust));

  // Grade assignment
  const cspGrade = gradeFromScore(cspScore);

  return {
    url,
    cspScore,
    cspGrade,
    insecureResourcesCount,
    activeMixedContent: insecureResourcesCount > 0,
    evaluations: {
      inlineScripts: scriptSrc.includes("'unsafe-inline'") ? 1 : 0,
      unsafeEvalUsage: scriptSrc.includes("'unsafe-eval'"),
      wildcardSources: scriptSrc.includes("*") || directives.get("default-src")?.includes("*") || false,
      legacyDirectives: false,
    },
    recommendations,
    details,
  };
}

// Core helper: get all resource URLs of given types by fetching resources and parsing types
async function fetchResourceUrls(baseUrl: string, resourceUrls: string[], signal: AbortSignal): Promise<string[]> {
  const urls: string[] = [];
  for (const rUrl of resourceUrls) {
    try {
      const resolvedUrl = new URL(rUrl, baseUrl).toString();
      urls.push(resolvedUrl);
    } catch {
      // ignore invalid URLs
    }
  }
  return urls;
}

// Comprehensive audit function
export async function runComprehensiveAudit(rawUrl: string): Promise<CspPolicyAnalysisResult | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: check.error };
  const baseUrl = check.url.toString();

  // AbortSignal 10 second timeout for external fetches
  const signalTimeout = 10_000;

  try {
    // Fetch main page CSP header and HTML
    const pageFetch = safeFetch(baseUrl, {
      method: "GET",
      headers: commonUserAgentHeader(),
      signal: AbortSignal.timeout(signalTimeout),
      redirect: "follow",
    });

    // Fetch main page resource list: also HEAD request for headers as fallback
    const headFetch = safeFetch(baseUrl, {
      method: "HEAD",
      headers: commonUserAgentHeader(),
      signal: AbortSignal.timeout(8000),
      redirect: "follow",
    });

    // Await in parallel
    const [pageResponse, headResponse] = await Promise.all([pageFetch, headFetch]);

    if (!pageResponse.ok && !headResponse.ok) {
      return { error: `Failed to fetch target page: status ${pageResponse.status} and status ${headResponse.status}` };
    }

    const html = await pageResponse.text();
    const cspRaw = pageResponse.headers.get("content-security-policy") || "";

    // Parse CSP
    const directives = parseCspHeader(cspRaw);

    // Collect resource URLs from CSP for further checking
    const cspResourceUrls = extractCspUrls(directives);

    // Analyze CSP directives in detail
    let cspScore = 85; // base high score for comprehensive
    const recommendations: Recommendation[] = [];
    
    // Check inline and eval usage
    const scriptSrc = directives.get("script-src") || directives.get("default-src") || [];
    if (scriptSrc.includes("'unsafe-inline'")) {
      cspScore -= 30;
      recommendations.push({
        issue: "Use of 'unsafe-inline' in script-src",
        severity: "high",
        suggestion: "Remove 'unsafe-inline' to prevent injection attacks.",
      });
    }
    if (scriptSrc.includes("'unsafe-eval'")) {
      cspScore -= 25;
      recommendations.push({
        issue: "Use of 'unsafe-eval' in script-src",
        severity: "medium",
        suggestion: "Avoid 'unsafe-eval' to reduce code injection risks.",
      });
    }

    if (scriptSrc.includes("*")) {
      cspScore -= 20;
      recommendations.push({
        issue: "Wildcard '*' in script-src source",
        severity: "medium",
        suggestion: "Explicitly list trusted domains instead of '*'.",
      });
    }

    // Check for legacy directives
    if (directives.has("allow") || directives.has("allow-from")) {
      cspScore -= 10;
      recommendations.push({
        issue: "Legacy or deprecated CSP directives detected.",
        severity: "low",
        suggestion: "Update CSP to latest standards.",
      });
    }

    // Detect mixed content by fetching resource URLs (check http vs https)
    const insecureResourcesSet = new Set<string>();

    // Rewrite URLs to absolute and filter http URLs
    const resourceUrlsToTest = await fetchResourceUrls(baseUrl, cspResourceUrls, AbortSignal.timeout(signalTimeout));

    // Check resource URLs in parallel with timeout
    const resourceChecks = resourceUrlsToTest.map(async (resUrl) => {
      if (resUrl.startsWith("http://")) {
        insecureResourcesSet.add(resUrl);
      }

      // Check quick fetch HEAD to detect resource redirects or errors
      try {
        const res = await safeFetch(resUrl, {
          method: "HEAD",
          signal: AbortSignal.timeout(8000),
          headers: commonUserAgentHeader(),
          redirect: "manual",
        });
        if (res.status >= 300 && res.status < 400) {
          const loc = res.headers.get("location");
          if (loc && loc.startsWith("http://")) {
            insecureResourcesSet.add(loc);
          }
        }
      } catch {
        // ignore errors in checking resources
      }
    });

    await Promise.all(resourceChecks);

    const insecureResourcesCount = insecureResourcesSet.size;

    if (insecureResourcesCount > 0) {
      cspScore -= Math.min(30, insecureResourcesCount * 5);
      recommendations.push({
        issue: `Detected ${insecureResourcesCount} insecure HTTP resource(s)`,
        severity: "high",
        suggestion: "Upgrade all resource links to HTTPS to prevent mixed content issues.",
      });
    }

    // Assemble evaluations object
    const evaluations = {
      inlineScripts: scriptSrc.includes("'unsafe-inline'") ? 1 : 0,
      unsafeEvalUsage: scriptSrc.includes("'unsafe-eval'"),
      wildcardSources: scriptSrc.includes("*") || directives.get("default-src")?.includes("*") || false,
      legacyDirectives: directives.has("allow") || directives.has("allow-from"),
    };

    const activeMixedContent = insecureResourcesCount > 0;

    // Clamp score between 0 and 100
    cspScore = Math.max(0, Math.min(100, cspScore));
    const cspGrade = gradeFromScore(cspScore);

    const details =
      "Comprehensive audit including CSP header analysis, resource load protocol inspection, and heuristic checks for unsafe directives.";

    return {
      url: baseUrl,
      cspScore,
      cspGrade,
      insecureResourcesCount,
      activeMixedContent,
      evaluations,
      recommendations,
      details,
    };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Audit failed: ${msg}` };
  }
}
