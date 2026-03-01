// Security header analyzer — pure header analysis, no external dependencies

import { validateExternalUrl, safeFetch } from "../../shared/ssrf";

// ── Types ──────────────────────────────────────────────────────────────────────

export type Grade = "A+" | "A" | "B" | "C" | "D" | "F";

export interface HeaderAnalysis {
  header: string;
  present: boolean;
  value: string | null;
  rating: Grade;
  issues: string[];
}

export interface CspDirectives {
  [directive: string]: string[];
}

export interface FullAuditResult {
  url: string;
  headers: HeaderAnalysis[];
  cspParsed: CspDirectives | null;
  overallGrade: Grade;
  remediation: string[];
  checkedAt: string;
}

export interface PreviewResult {
  url: string;
  preview: true;
  headers: HeaderAnalysis[];
  overallGrade: Grade;
  checkedAt: string;
  note: string;
}

// ── Constants ──────────────────────────────────────────────────────────────────

const SECURITY_HEADERS = [
  "Strict-Transport-Security",
  "Content-Security-Policy",
  "X-Frame-Options",
  "X-Content-Type-Options",
  "Referrer-Policy",
  "Permissions-Policy",
  "X-XSS-Protection",
  "Cross-Origin-Embedder-Policy",
  "Cross-Origin-Opener-Policy",
  "Cross-Origin-Resource-Policy",
] as const;

type SecurityHeader = (typeof SECURITY_HEADERS)[number];

const PREVIEW_HEADERS: SecurityHeader[] = [
  "Strict-Transport-Security",
  "X-Frame-Options",
  "X-Content-Type-Options",
];

// Weights for grading
const HEADER_WEIGHT: Record<SecurityHeader, number> = {
  "Strict-Transport-Security": 2,      // critical
  "Content-Security-Policy": 2,         // critical
  "X-Frame-Options": 1.5,              // important
  "X-Content-Type-Options": 1.5,       // important
  "Referrer-Policy": 1.5,              // important
  "Permissions-Policy": 1.5,           // important
  "X-XSS-Protection": 1,              // standard
  "Cross-Origin-Embedder-Policy": 1,   // standard
  "Cross-Origin-Opener-Policy": 1,     // standard
  "Cross-Origin-Resource-Policy": 1,   // standard
};

// Numeric values for grade math
const GRADE_SCORE: Record<Grade, number> = {
  "A+": 100,
  "A": 90,
  "B": 75,
  "C": 55,
  "D": 35,
  "F": 0,
};

// ── Error Sanitization ─────────────────────────────────────────────────────────

function sanitizeFetchError(err: unknown): string {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  if (msg.includes("private") || msg.includes("internal")) return "URL not allowed";
  if (msg.includes("timeout")) return "Request timed out";
  if (msg.includes("dns") || msg.includes("notfound")) return "DNS lookup failed";
  if (msg.includes("redirect")) return "Too many redirects";
  if (msg.includes("invalid url")) return "Invalid URL";
  return "Unable to reach the target URL";
}

// ── CSP Parsing ────────────────────────────────────────────────────────────────

export function parseCsp(value: string): CspDirectives {
  const directives: CspDirectives = {};
  const truncated = value.slice(0, 8192);
  const parts = truncated.split(";").map((s) => s.trim()).filter(Boolean).slice(0, 64);

  for (const part of parts) {
    const tokens = part.split(/\s+/).slice(0, 64);
    const name = tokens[0].toLowerCase();
    directives[name] = tokens.slice(1);
  }

  return directives;
}

// ── Individual Header Analyzers ────────────────────────────────────────────────

function analyzeHsts(value: string | null): HeaderAnalysis {
  const issues: string[] = [];

  if (!value) {
    return { header: "Strict-Transport-Security", present: false, value: null, rating: "F", issues: ["HSTS header is missing. Site is vulnerable to protocol downgrade and cookie hijacking attacks."] };
  }

  const lower = value.toLowerCase();
  const maxAgeMatch = lower.match(/max-age=(\d+)/);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  const hasSubDomains = lower.includes("includesubdomains");
  const hasPreload = lower.includes("preload");

  if (!maxAgeMatch) {
    issues.push("max-age directive is missing.");
    return { header: "Strict-Transport-Security", present: true, value, rating: "F", issues };
  }

  if (maxAge < 15768000) {
    issues.push(`max-age is ${maxAge}s (${Math.floor(maxAge / 86400)} days), should be at least 6 months (15768000s).`);
  }

  if (!hasSubDomains) {
    issues.push("Missing includeSubDomains directive.");
  }

  if (!hasPreload) {
    issues.push("Missing preload directive; consider adding for HSTS preload list eligibility.");
  }

  let rating: Grade;
  if (maxAge >= 31536000 && hasSubDomains) {
    rating = "A";
  } else if (maxAge >= 15768000) {
    rating = "B";
  } else {
    rating = "C";
  }

  return { header: "Strict-Transport-Security", present: true, value, rating, issues };
}

function analyzeCsp(value: string | null): { analysis: HeaderAnalysis; directives: CspDirectives | null } {
  const issues: string[] = [];

  if (!value) {
    return {
      analysis: { header: "Content-Security-Policy", present: false, value: null, rating: "F", issues: ["Content-Security-Policy header is missing. No protection against XSS and data injection attacks."] },
      directives: null,
    };
  }

  const directives = parseCsp(value);
  const hasDefaultSrc = "default-src" in directives;
  const scriptSrc = directives["script-src"] || directives["default-src"] || [];
  const hasUnsafeInline = scriptSrc.includes("'unsafe-inline'");
  const hasUnsafeEval = scriptSrc.includes("'unsafe-eval'");
  const isReportOnly = false; // We check the actual header name in fetchHeaders

  if (!hasDefaultSrc) {
    issues.push("Missing default-src directive; browsers fall back to no restriction for unlisted resource types.");
  }

  if (hasUnsafeInline) {
    issues.push("script-src allows 'unsafe-inline', which negates much of CSP's XSS protection.");
  }

  if (hasUnsafeEval) {
    issues.push("script-src allows 'unsafe-eval', which permits dynamic code execution.");
  }

  const styleSrc = directives["style-src"] || directives["default-src"] || [];
  if (styleSrc.includes("'unsafe-inline'")) {
    issues.push("style-src allows 'unsafe-inline'.");
  }

  if (scriptSrc.includes("*") || (directives["default-src"] || []).includes("*")) {
    issues.push("Wildcard (*) source is overly permissive.");
  }

  let rating: Grade;
  if (hasDefaultSrc && !hasUnsafeInline && !hasUnsafeEval) {
    rating = "A";
  } else if (hasDefaultSrc) {
    rating = "B";
  } else {
    rating = "C";
  }

  return { analysis: { header: "Content-Security-Policy", present: true, value, rating, issues }, directives };
}

function analyzeXFrameOptions(value: string | null): HeaderAnalysis {
  const issues: string[] = [];

  if (!value) {
    return { header: "X-Frame-Options", present: false, value: null, rating: "F", issues: ["X-Frame-Options is missing. Site may be vulnerable to clickjacking attacks."] };
  }

  const upper = value.toUpperCase().trim();
  if (upper === "DENY" || upper === "SAMEORIGIN") {
    return { header: "X-Frame-Options", present: true, value, rating: "A", issues };
  }

  if (upper.startsWith("ALLOW-FROM")) {
    issues.push("ALLOW-FROM is deprecated and not supported in modern browsers. Use CSP frame-ancestors instead.");
    return { header: "X-Frame-Options", present: true, value, rating: "C", issues };
  }

  issues.push(`Unrecognized value "${value}". Expected DENY or SAMEORIGIN.`);
  return { header: "X-Frame-Options", present: true, value, rating: "D", issues };
}

function analyzeXContentTypeOptions(value: string | null): HeaderAnalysis {
  if (!value) {
    return { header: "X-Content-Type-Options", present: false, value: null, rating: "F", issues: ["X-Content-Type-Options is missing. Browsers may MIME-sniff responses, enabling content-type confusion attacks."] };
  }

  if (value.trim().toLowerCase() === "nosniff") {
    return { header: "X-Content-Type-Options", present: true, value, rating: "A", issues: [] };
  }

  return { header: "X-Content-Type-Options", present: true, value, rating: "D", issues: [`Expected "nosniff" but got "${value}".`] };
}

function analyzeReferrerPolicy(value: string | null): HeaderAnalysis {
  if (!value) {
    return { header: "Referrer-Policy", present: false, value: null, rating: "F", issues: ["Referrer-Policy is missing. The browser default may leak referrer information across origins."] };
  }

  const secure = new Set([
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "no-referrer-when-downgrade",
  ]);

  const policies = value.split(",").map((s) => s.trim().toLowerCase());
  const lastPolicy = policies[policies.length - 1];

  if (secure.has(lastPolicy)) {
    return { header: "Referrer-Policy", present: true, value, rating: "A", issues: [] };
  }

  if (lastPolicy === "origin" || lastPolicy === "origin-when-cross-origin") {
    return { header: "Referrer-Policy", present: true, value, rating: "B", issues: [`"${lastPolicy}" leaks the origin. Consider strict-origin-when-cross-origin.`] };
  }

  if (lastPolicy === "unsafe-url") {
    return { header: "Referrer-Policy", present: true, value, rating: "D", issues: [`"unsafe-url" leaks full URL including path and query string to all origins.`] };
  }

  return { header: "Referrer-Policy", present: true, value, rating: "C", issues: [`Unrecognized policy "${lastPolicy}".`] };
}

function analyzePermissionsPolicy(value: string | null): HeaderAnalysis {
  if (!value) {
    return { header: "Permissions-Policy", present: false, value: null, rating: "F", issues: ["Permissions-Policy is missing. Browser features like camera, microphone, and geolocation are unrestricted."] };
  }

  const directives = value.split(",").map((s) => s.trim()).filter(Boolean);

  if (directives.length === 0) {
    return { header: "Permissions-Policy", present: true, value, rating: "C", issues: ["Permissions-Policy is empty."] };
  }

  // Count how many features are restricted
  const restricted = directives.filter((d) => d.includes("=()") || d.includes("=(self)"));
  const issues: string[] = [];

  if (restricted.length >= 5) {
    return { header: "Permissions-Policy", present: true, value, rating: "A", issues };
  }

  if (restricted.length >= 2) {
    issues.push("Only a few features are restricted. Consider restricting camera, microphone, geolocation, etc.");
    return { header: "Permissions-Policy", present: true, value, rating: "B", issues };
  }

  issues.push("Very few features are restricted by Permissions-Policy.");
  return { header: "Permissions-Policy", present: true, value, rating: "C", issues };
}

function analyzeXXssProtection(value: string | null): HeaderAnalysis {
  if (!value) {
    return { header: "X-XSS-Protection", present: false, value: null, rating: "F", issues: ["X-XSS-Protection is missing. While deprecated in modern browsers, it provides defense-in-depth for older clients."] };
  }

  const trimmed = value.trim();
  if (trimmed === "0") {
    // Explicitly disabled — this is valid for sites that rely on CSP
    return { header: "X-XSS-Protection", present: true, value, rating: "B", issues: ["Set to 0 (disabled). This is acceptable if CSP is configured, but provides no fallback for older browsers."] };
  }

  if (trimmed.startsWith("1") && trimmed.includes("mode=block")) {
    return { header: "X-XSS-Protection", present: true, value, rating: "A", issues: [] };
  }

  if (trimmed.startsWith("1")) {
    return { header: "X-XSS-Protection", present: true, value, rating: "B", issues: ["Enabled but missing mode=block. The browser may attempt to sanitize the page instead of blocking."] };
  }

  return { header: "X-XSS-Protection", present: true, value, rating: "C", issues: [`Unrecognized value "${value}".`] };
}

function analyzeCrossOriginEmbedderPolicy(value: string | null): HeaderAnalysis {
  if (!value) {
    return { header: "Cross-Origin-Embedder-Policy", present: false, value: null, rating: "F", issues: ["Cross-Origin-Embedder-Policy is missing. Cannot enable cross-origin isolation (SharedArrayBuffer, high-res timers)."] };
  }

  const trimmed = value.trim().toLowerCase();
  if (trimmed === "require-corp") {
    return { header: "Cross-Origin-Embedder-Policy", present: true, value, rating: "A", issues: [] };
  }

  if (trimmed === "credentialless") {
    return { header: "Cross-Origin-Embedder-Policy", present: true, value, rating: "A", issues: [] };
  }

  if (trimmed === "unsafe-none") {
    return { header: "Cross-Origin-Embedder-Policy", present: true, value, rating: "C", issues: ["Set to unsafe-none, which does not provide cross-origin isolation."] };
  }

  return { header: "Cross-Origin-Embedder-Policy", present: true, value, rating: "C", issues: [`Unrecognized value "${value}".`] };
}

function analyzeCrossOriginOpenerPolicy(value: string | null): HeaderAnalysis {
  if (!value) {
    return { header: "Cross-Origin-Opener-Policy", present: false, value: null, rating: "F", issues: ["Cross-Origin-Opener-Policy is missing. Window references may leak across origins."] };
  }

  const trimmed = value.trim().toLowerCase();
  if (trimmed === "same-origin") {
    return { header: "Cross-Origin-Opener-Policy", present: true, value, rating: "A", issues: [] };
  }

  if (trimmed === "same-origin-allow-popups") {
    return { header: "Cross-Origin-Opener-Policy", present: true, value, rating: "B", issues: ["same-origin-allow-popups still allows opened windows to retain references."] };
  }

  if (trimmed === "unsafe-none") {
    return { header: "Cross-Origin-Opener-Policy", present: true, value, rating: "C", issues: ["Set to unsafe-none, no isolation provided."] };
  }

  return { header: "Cross-Origin-Opener-Policy", present: true, value, rating: "C", issues: [`Unrecognized value "${value}".`] };
}

function analyzeCrossOriginResourcePolicy(value: string | null): HeaderAnalysis {
  if (!value) {
    return { header: "Cross-Origin-Resource-Policy", present: false, value: null, rating: "F", issues: ["Cross-Origin-Resource-Policy is missing. Resources may be embedded by any origin."] };
  }

  const trimmed = value.trim().toLowerCase();
  if (trimmed === "same-origin") {
    return { header: "Cross-Origin-Resource-Policy", present: true, value, rating: "A", issues: [] };
  }

  if (trimmed === "same-site") {
    return { header: "Cross-Origin-Resource-Policy", present: true, value, rating: "A", issues: [] };
  }

  if (trimmed === "cross-origin") {
    return { header: "Cross-Origin-Resource-Policy", present: true, value, rating: "B", issues: ["Set to cross-origin, which allows any site to embed this resource."] };
  }

  return { header: "Cross-Origin-Resource-Policy", present: true, value, rating: "C", issues: [`Unrecognized value "${value}".`] };
}

// ── Analyzer Dispatch ──────────────────────────────────────────────────────────

const ANALYZERS: Record<SecurityHeader, (value: string | null) => HeaderAnalysis> = {
  "Strict-Transport-Security": analyzeHsts,
  "Content-Security-Policy": (v) => analyzeCsp(v).analysis,
  "X-Frame-Options": analyzeXFrameOptions,
  "X-Content-Type-Options": analyzeXContentTypeOptions,
  "Referrer-Policy": analyzeReferrerPolicy,
  "Permissions-Policy": analyzePermissionsPolicy,
  "X-XSS-Protection": analyzeXXssProtection,
  "Cross-Origin-Embedder-Policy": analyzeCrossOriginEmbedderPolicy,
  "Cross-Origin-Opener-Policy": analyzeCrossOriginOpenerPolicy,
  "Cross-Origin-Resource-Policy": analyzeCrossOriginResourcePolicy,
};

// ── Overall Grade Computation ──────────────────────────────────────────────────

function computeOverallGrade(analyses: HeaderAnalysis[]): Grade {
  let totalWeight = 0;
  let weightedScore = 0;

  for (const a of analyses) {
    const weight = HEADER_WEIGHT[a.header as SecurityHeader] || 1;
    totalWeight += weight;
    weightedScore += GRADE_SCORE[a.rating] * weight;
  }

  const avg = totalWeight > 0 ? weightedScore / totalWeight : 0;

  // Count present headers for the threshold-based grading
  const presentCount = analyses.filter((a) => a.present).length;
  const totalHeaders = analyses.length;

  // Use both weighted score and presence count
  if (avg >= 90 && presentCount === totalHeaders) return "A+";
  if (avg >= 80 && presentCount >= totalHeaders - 1) return "A";
  if (avg >= 65 && presentCount >= 7) return "B";
  if (avg >= 45 && presentCount >= 5) return "C";
  if (presentCount >= 3) return "D";
  return "F";
}

// ── Remediation ────────────────────────────────────────────────────────────────

function generateRemediation(analyses: HeaderAnalysis[]): string[] {
  const suggestions: string[] = [];

  for (const a of analyses) {
    if (!a.present) {
      suggestions.push(...getMissingHeaderSuggestion(a.header as SecurityHeader));
    } else if (a.rating === "C" || a.rating === "D" || a.rating === "F") {
      suggestions.push(...getWeakHeaderSuggestion(a.header as SecurityHeader, a.issues));
    }
  }

  return suggestions;
}

function getMissingHeaderSuggestion(header: SecurityHeader): string[] {
  const suggestions: Record<SecurityHeader, string[]> = {
    "Strict-Transport-Security": [
      "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ],
    "Content-Security-Policy": [
      "Add a Content-Security-Policy header. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'",
      "Use CSP evaluator tools to iteratively tighten the policy for your site.",
    ],
    "X-Frame-Options": [
      "Add: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed).",
      "Also consider CSP frame-ancestors for more granular control.",
    ],
    "X-Content-Type-Options": [
      "Add: X-Content-Type-Options: nosniff",
    ],
    "Referrer-Policy": [
      "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ],
    "Permissions-Policy": [
      "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
      "Restrict any browser features your site does not use.",
    ],
    "X-XSS-Protection": [
      "Add: X-XSS-Protection: 1; mode=block (for legacy browser support).",
      "Note: Modern browsers rely on CSP instead.",
    ],
    "Cross-Origin-Embedder-Policy": [
      "Add: Cross-Origin-Embedder-Policy: require-corp",
      "Required for cross-origin isolation (SharedArrayBuffer, high-resolution timers).",
    ],
    "Cross-Origin-Opener-Policy": [
      "Add: Cross-Origin-Opener-Policy: same-origin",
    ],
    "Cross-Origin-Resource-Policy": [
      "Add: Cross-Origin-Resource-Policy: same-origin (or same-site if cross-subdomain access is needed).",
    ],
  };

  return suggestions[header] || [`Add the ${header} header.`];
}

function getWeakHeaderSuggestion(header: SecurityHeader, issues: string[]): string[] {
  const prefix = `${header}: `;
  return issues.map((issue) => `${prefix}${issue}`);
}

// ── Fetch & Analyze ────────────────────────────────────────────────────────────

async function fetchHeaders(url: string): Promise<Headers> {
  const res = await safeFetch(url, {
    timeoutMs: 10000,
    headers: { "User-Agent": "security-headers/1.0 apimesh.xyz" },
  });

  return res.headers;
}

// ── Public API ─────────────────────────────────────────────────────────────────

export async function fullAudit(rawUrl: string): Promise<FullAuditResult | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: check.error };

  let headers: Headers;
  try {
    headers = await fetchHeaders(check.url.toString());
  } catch (err: any) {
    console.error(`[fullAudit] fetch error for ${check.url}:`, err);
    return { error: sanitizeFetchError(err) };
  }

  // Check for Content-Security-Policy-Report-Only as fallback
  const cspValue = headers.get("Content-Security-Policy") || null;
  const cspReportOnly = headers.get("Content-Security-Policy-Report-Only") || null;

  const analyses: HeaderAnalysis[] = [];
  let cspParsed: CspDirectives | null = null;

  for (const headerName of SECURITY_HEADERS) {
    if (headerName === "Content-Security-Policy") {
      // Special handling: parse CSP and detect report-only
      const effectiveCsp = cspValue || cspReportOnly;
      const result = analyzeCsp(effectiveCsp);

      if (!cspValue && cspReportOnly) {
        // Downgrade: report-only is not enforcing
        result.analysis.rating = "C";
        result.analysis.issues.push("Content-Security-Policy-Report-Only is set but the enforcing header is missing. Policy is not enforced.");
      }

      analyses.push(result.analysis);
      cspParsed = result.directives;
    } else {
      const value = headers.get(headerName);
      analyses.push(ANALYZERS[headerName](value));
    }
  }

  const overallGrade = computeOverallGrade(analyses);
  const remediation = generateRemediation(analyses);

  return {
    url: check.url.toString(),
    headers: analyses,
    cspParsed,
    overallGrade,
    remediation,
    checkedAt: new Date().toISOString(),
  };
}

export async function previewAudit(rawUrl: string): Promise<PreviewResult | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: check.error };

  let headers: Headers;
  try {
    headers = await fetchHeaders(check.url.toString());
  } catch (err: any) {
    console.error(`[previewAudit] fetch error for ${check.url}:`, err);
    return { error: sanitizeFetchError(err) };
  }

  const analyses: HeaderAnalysis[] = [];

  for (const headerName of PREVIEW_HEADERS) {
    const value = headers.get(headerName);
    analyses.push(ANALYZERS[headerName](value));
  }

  const overallGrade = computeOverallGrade(analyses);

  return {
    url: check.url.toString(),
    preview: true,
    headers: analyses,
    overallGrade,
    checkedAt: new Date().toISOString(),
    note: "Preview checks 3 headers only (HSTS, X-Frame-Options, X-Content-Type-Options). Pay via x402 for full 10-header audit with CSP parsing, grading, and remediation.",
  };
}
