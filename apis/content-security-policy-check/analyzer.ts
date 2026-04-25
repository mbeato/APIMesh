import { safeFetch } from "../../shared/ssrf";

// --------------------------
// Types
// --------------------------

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface HeaderAnalysis {
  header: string;
  present: boolean;
  value: string | null;
  rating: Grade;
  issues: string[];
}

export interface ContentSecurityAnalysisResult {
  cspPresent: boolean;
  directives: Record<string, string[]>;
  strengthScore: number;
  error?: string;
}

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface DetailedAnalysisResult {
  url: string;
  overallScore: number; // 0-100
  overallGrade: Grade;
  headers: HeaderAnalysis[];
  cspDirectives: Record<string, string[]>;
  htmlCspDirectives: Record<string, string[]>;
  recommendations: Recommendation[];
  analysisDetails: string;
  scannedAt: string; // ISO
}

export interface PreviewAnalysisResult {
  url: string;
  preview: true;
  overallScore: number;
  overallGrade: Grade;
  headers: HeaderAnalysis[];
  recommendations: Recommendation[];
  note: string;
}

// --------------------------
// Constants and Utilities
// --------------------------

const HEADERS_TO_CHECK = [
  "content-security-policy",
  "x-frame-options",
  "strict-transport-security",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "x-xss-protection",
  "cross-origin-embedder-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
];

// Utility to parse CSP header string into directives
export function parseCsp(value: string): Record<string, string[]> {
  const directives: Record<string, string[]> = {};
  if (!value) return directives;

  const parts = value.split(";").map((p) => p.trim()).filter((p) => p.length > 0);

  for (const part of parts) {
    const [dir, ...vals] = part.split(/\s+/);
    if (dir) {
      directives[dir.toLowerCase()] = vals.map(v => v.trim()).filter(v => v.length > 0);
    }
  }

  return directives;
}

// Utility to make grade from numeric score
function gradeFromScore(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 45) return "D";
  return "F";
}

// -----------
// Analyze Headers
// -----------

export async function analyzeHeaders(url: string): Promise<PreviewAnalysisResult> {
  // Mainly fetch HEAD request for preview
  try {
    const response = await safeFetch(url, { method: "HEAD", timeoutMs: 15_000 });
    const headers = response.headers;

    const analyses: HeaderAnalysis[] = [];

    for (const header of HEADERS_TO_CHECK) {
      const val = headers.get(header);
      const analysis = analyzeSingleHeader(header, val);
      analyses.push(analysis);
    }

    // Compute overall score and grade
    const score = calculateScore(analyses);
    const grade = gradeFromScore(score);

    const recs = generateRecommendationsFromHeaderAnalysis(analyses);

    return {
      url,
      preview: true,
      overallScore: score,
      overallGrade: grade,
      headers: analyses,
      recommendations: recs,
      note: "Preview checks critical security headers only, pay for full CSP analysis and content parsing.",
    };
  } catch (e) {
    throw e;
  }
}

// Analyzes a single header for presence, value, rating, and issues
export function analyzeSingleHeader(header: string, value: string | null): HeaderAnalysis {
  const headerLower = header.toLowerCase();
  const present = value !== null && value.length > 0;
  let rating: Grade = "F";
  const issues: string[] = [];

  if (!present) {
    issues.push(`${header} header is missing.`);
    return { header, present: false, value, rating, issues };
  }

  // Simplified individual header ratings
  switch (headerLower) {
    case "content-security-policy": {
      const directives = parseCsp(value!);
      // Check presence of default-src directive
      if (!directives["default-src"]) {
        issues.push(`Missing 'default-src' directive.`);
        rating = "C";
      } else {
        // Check for unsafe-inline and unsafe-eval
        const scriptSrc = directives["script-src"] || directives["default-src"];
        if (scriptSrc.includes("'unsafe-inline'") || scriptSrc.includes("'unsafe-eval'")) {
          issues.push(`'script-src' contains unsafe-inline or unsafe-eval.`);
          rating = "D";
        } else {
          rating = "A";
        }
      }
      break;
    }
    case "x-frame-options": {
      const v = value!.toUpperCase().trim();
      if (v === "DENY" || v === "SAMEORIGIN") rating = "A";
      else {
        issues.push(`Unrecognized X-Frame-Options value '${value}'.`);
        rating = "C";
      }
      break;
    }
    case "strict-transport-security": {
      const v = value!.toLowerCase();
      if (v.includes("max-age") && v.includes("includesubdomains")) rating = "A";
      else {
        issues.push(`HSTS missing max-age or includeSubDomains.`);
        rating = "C";
      }
      break;
    }
    case "x-content-type-options": {
      if (value!.toLowerCase() === "nosniff") rating = "A";
      else {
        issues.push(`Expected 'nosniff' value.`);
        rating = "D";
      }
      break;
    }
    case "referrer-policy": {
      const securePolicies = [
        "no-referrer",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "same-origin",
      ];
      if (securePolicies.includes(value!.toLowerCase())) rating = "A";
      else {
        issues.push(`Referrer-Policy value '${value}' is not recommended for privacy.`);
        rating = "C";
      }
      break;
    }
    case "permissions-policy": {
      // if empty or missing always low
      rating = value!.length > 0 ? "B" : "C";
      break;
    }
    case "x-xss-protection": {
      if (value === "1; mode=block") rating = "A";
      else if (value === "0") {
        rating = "B";
        issues.push("X-XSS-Protection disabled but relying on CSP.");
      } else rating = "C";
      break;
    }
    case "cross-origin-embedder-policy":
    case "cross-origin-opener-policy":
    case "cross-origin-resource-policy": {
      if (value!.toLowerCase().includes("same-origin") || value!.toLowerCase().includes("require-corp")) {
        rating = "A";
      } else {
        issues.push(`${header} has weak or missing value.`);
        rating = "C";
      }
      break;
    }
    default: {
      rating = "C";
      issues.push(`No analysis rule for ${header}`);
    }
  }

  return {
    header,
    present,
    value,
    rating,
    issues,
  };
}

// Score calculation for preview analysis
function calculateScore(analyses: HeaderAnalysis[]): number {
  let total = 0;
  let count = 0;

  for (const a of analyses) {
    if (!a.present) {
      total += 0;
      count++;
      continue;
    }

    total +=
      a.rating === "A"
        ? 100
        : a.rating === "B"
        ? 80
        : a.rating === "C"
        ? 60
        : a.rating === "D"
        ? 40
        : 0;
    count++;
  }

  return count > 0 ? Math.round(total / count) : 0;
}

// Generate recommendations based on header analysis (for preview)
function generateRecommendationsFromHeaderAnalysis(
  analyses: HeaderAnalysis[],
): Recommendation[] {
  const recs: Recommendation[] = [];
  for (const a of analyses) {
    if (!a.present) {
      recs.push({
        issue: `${a.header} header missing`,
        severity: 80,
        suggestion: `Add strong ${a.header} header according to security best practices.`,
      });
    } else if (a.issues.length > 0) {
      for (const issue of a.issues) {
        recs.push({
          issue,
          severity: 60,
          suggestion: `Review and fix problems in header: ${a.header}.`,
        });
      }
    }
  }
  return recs;
}

// --------------------------
// CSP Header Analysis
// --------------------------

export function analyzeCspHeader(
cspHeader: string,
): ContentSecurityAnalysisResult {
  const result: ContentSecurityAnalysisResult = {
    cspPresent: false,
    directives: {},
    strengthScore: 0,
  };
  if (!cspHeader || cspHeader.trim().length === 0) {
    return result;
  }

  result.cspPresent = true;
  let directives: Record<string, string[]> = {};
  try {
    directives = parseCsp(cspHeader);
  } catch (e) {
    result.error = "Failed to parse CSP header.";
    return result;
  }

  result.directives = directives;

  // Basic scoring
  let score = 50;
  if (directives["default-src"] &&
      !directives["default-src"].includes("'unsafe-inline'") &&
      !directives["default-src"].includes("*") &&
      directives["default-src"].length > 0) {
    score += 30;
  } else {
    score -= 20;
  }

  if (directives["script-src"] &&
      !directives["script-src"].includes("'unsafe-inline'") &&
      directives["script-src"].length > 0) {
    score += 20;
  } else {
    score -= 20;
  }

  if (score < 0) score = 0;
  if (score > 100) score = 100;

  result.strengthScore = score;

  return result;
}

// --------------------------
// CSP Directives inside HTML <meta> tag analysis
// --------------------------

export function analyzeHtmlContent(
  html: string
): ContentSecurityAnalysisResult {
  // Look for <meta http-equiv="Content-Security-Policy" content="..." />
  // Extract and parse its content attribute

  if (!html) {
    return {
      cspPresent: false,
      directives: {},
      strengthScore: 0,
    };
  }

  const metaCspMatch = html.match(
    /<meta[^>]*http-equiv=["']content-security-policy["'][^>]*content=["']([^"']+)["'][^>]*>/i
  );

  if (!metaCspMatch) {
    return {
      cspPresent: false,
      directives: {},
      strengthScore: 0,
    };
  }

  const contentValue = metaCspMatch[1];
  return analyzeCspHeader(contentValue);
}

// --------------------------
// Comprehensive overall score calculation
// --------------------------

export function computeOverallScore(
  headerAnalyses: HeaderAnalysis[],
  cspAnalysis: ContentSecurityAnalysisResult,
  htmlCspAnalysis: ContentSecurityAnalysisResult,
): number {
  let score = 0;
  
  // Header analysis contributes 50%
  score += calculateScore(headerAnalyses) * 0.5;

  // CSP header analysis weighting 35%
  score += cspAnalysis.strengthScore ? cspAnalysis.strengthScore * 0.35 : 0;

  // HTML CSP directives analysis weighting 15%
  score += htmlCspAnalysis.strengthScore ? htmlCspAnalysis.strengthScore * 0.15 : 0;

  if (score > 100) score = 100;
  if (score < 0) score = 0;

  return Math.round(score);
}

// --------------------------
// Generate Recommendations for detailed analysis
// --------------------------

export function generateRecommendations(
  headerAnalyses: HeaderAnalysis[],
  cspAnalysis: ContentSecurityAnalysisResult,
  htmlCspAnalysis: ContentSecurityAnalysisResult
): Recommendation[] {
  const recs: Recommendation[] = [];

  for (const ha of headerAnalyses) {
    if (!ha.present) {
      recs.push({
        issue: `${ha.header} is missing`,
        severity: 80,
        suggestion: `Add a strong ${ha.header} header with recommended defaults to improve security.`,
      });
    } else if (ha.issues.length > 0) {
      ha.issues.forEach((issue) => {
        recs.push({
          issue,
          severity: 60,
          suggestion: `Fix issue in ${ha.header}: ${issue}`,
        });
      });
    }
  }

  if (!cspAnalysis.cspPresent) {
    recs.push({
      issue: "Content-Security-Policy header missing",
      severity: 90,
      suggestion:
        "Add a Content-Security-Policy HTTP header to mitigate cross-site scripting and other attacks.",
    });
  } else if (cspAnalysis.strengthScore < 75) {
    recs.push({
      issue: "Weak Content-Security-Policy header detected",
      severity: 75,
      suggestion:
        "Tighten the CSP by removing unsafe-inline and restricting script-src and default-src to trusted sources only.",
    });
  }

  if (!htmlCspAnalysis.cspPresent) {
    recs.push({
      issue: "No CSP meta tag found in HTML content",
      severity: 35,
      suggestion:
        "Consider adding a CSP <meta> tag for browsers or scenarios that miss HTTP header, but header is preferred.",
    });
  } else if (htmlCspAnalysis.strengthScore < 50) {
    recs.push({
      issue: "Weak CSP directives detected in HTML meta tag",
      severity: 40,
      suggestion: "Improve CSP meta tag directives for better security.",
    });
  }

  // Remove duplicates based on issue text
  const seen = new Set<string>();
  const uniqueRecs: Recommendation[] = [];
  for (const r of recs) {
    if (!seen.has(r.issue)) {
      seen.add(r.issue);
      uniqueRecs.push(r);
    }
  }

  return uniqueRecs;
}
