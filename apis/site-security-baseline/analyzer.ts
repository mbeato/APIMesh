import {
  validateExternalUrl,
  safeFetch,
} from "../../shared/ssrf";

export type Grade = "A+" | "A" | "B" | "C" | "D" | "F";

export interface HeaderAnalysis {
  header: string;
  present: boolean;
  value: string | null;
  score: number; // 0-100 numeric
  grade: Grade;
  issues: string[];
  recommendations: Recommendation[];
}

export interface Recommendation {
  issue: string;
  severity: number; // 1-5 (5 highest)
  suggestion: string;
}

export interface SslAnalysis {
  valid: boolean | null;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  expiryDays: number | null;
  strengthScore: number; // 0-100
  recommendations: Recommendation[];
  error?: string;
}

export interface SiteSecurityBaselineResult {
  url: string;
  headerAnalyses: HeaderAnalysis[];
  sslAnalysis: SslAnalysis;
  overallScore: number; // 0-100
  overallGrade: Grade;
  recommendations: Recommendation[];
  explanation: string;
  scannedAt: string;
}

export interface SiteSecurityBaselinePreviewResult {
  url: string;
  preview: true;
  summary: {
    securityHeadersScore: number;
    sslGrade: Grade | null;
    recommendationsCount: number;
  };
  explanation: string;
}

// --- Constants ---

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

// Grade thresholds
function scoreToGrade(score: number): Grade {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 65) return "B";
  if (score >= 45) return "C";
  if (score >= 25) return "D";
  return "F";
}

// Simple scoring helpers
function clampScore(score: number): number {
  if (score > 100) return 100;
  if (score < 0) return 0;
  return Math.round(score);
}

// Helper function to parse directives from CSP header string
function parseCspDirectives(csp: string): Record<string, string[]> {
  const directives: Record<string, string[]> = {};
  const parts = csp.split(";").map((s) => s.trim()).filter(Boolean);
  for (const part of parts) {
    const tokens = part.split(/\s+/);
    if (tokens.length === 0) continue;
    const dirName = tokens[0].toLowerCase();
    directives[dirName] = tokens.slice(1);
  }
  return directives;
}

// --- Analysis functions for individual headers ---

function analyzeHsts(value: string | null): HeaderAnalysis {
  const header = "Strict-Transport-Security";
  const issues: string[] = [];
  const recommendations: Recommendation[] = [];
  if (!value) {
    issues.push("HSTS header is missing.");
    recommendations.push({
      issue: "Missing HSTS header",
      severity: 5,
      suggestion: "Add Strict-Transport-Security header with at least max-age=31536000; includeSubDomains; preload",
    });
    return {
      header,
      present: false,
      value: null,
      score: 0,
      grade: "F",
      issues,
      recommendations,
    };
  }

  const v = value.toLowerCase();
  const maxAgeMatch = v.match(/max-age=(\d+)/);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  const hasIncludeSubDomains = v.includes("includesubdomains");
  const hasPreload = v.includes("preload");

  let score = 100;

  if (!maxAgeMatch) {
    issues.push("HSTS max-age directive is missing.");
    recommendations.push({
      issue: "No max-age in HSTS",
      severity: 5,
      suggestion: "Add max-age directive in Strict-Transport-Security header with at least 15768000 (6 months)",
    });
    score -= 70;
  } else if (maxAge < 15768000) {
    issues.push(`HSTS max-age too short: ${maxAge}s (<6 months).`);
    recommendations.push({
      issue: "Short HSTS max-age",
      severity: 4,
      suggestion: "Increase max-age to at least 15768000 (6 months)",
    });
    score -= 40;
  }

  if (!hasIncludeSubDomains) {
    issues.push("HSTS missing includeSubDomains directive.");
    recommendations.push({
      issue: "Missing includeSubDomains",
      severity: 4,
      suggestion: "Add 'includeSubDomains' directive to Strict-Transport-Security header",
    });
    score -= 20;
  }

  if (!hasPreload) {
    issues.push("HSTS missing preload directive.");
    recommendations.push({
      issue: "Missing preload directive",
      severity: 3,
      suggestion: "Add 'preload' directive and submit site to HSTS preload list",
    });
    score -= 10;
  }

  const grade = scoreToGrade(clampScore(score));

  return {
    header,
    present: true,
    value,
    score: clampScore(score),
    grade,
    issues,
    recommendations,
  };
}

function analyzeCsp(value: string | null): HeaderAnalysis {
  const header = "Content-Security-Policy";
  const issues: string[] = [];
  const recommendations: Recommendation[] = [];

  if (!value) {
    issues.push("Content-Security-Policy header is missing.");
    recommendations.push({
      issue: "Missing CSP header",
      severity: 5,
      suggestion: "Add a Content-Security-Policy header starting with default-src 'self'",
    });
    return {
      header,
      present: false,
      value: null,
      score: 0,
      grade: "F",
      issues,
      recommendations,
    };
  }

  const directives = parseCspDirectives(value);
  let score = 100;

  if (!directives["default-src"]) {
    issues.push("Missing default-src directive in CSP.");
    recommendations.push({
      issue: "No default-src directive",
      severity: 5,
      suggestion: "Add a 'default-src' directive restricting sources, e.g., 'default-src 'self''",
    });
    score -= 50;
  } else {
    const defaultSrc = directives["default-src"];
    if (defaultSrc.includes("'unsafe-inline'") || defaultSrc.includes("*")) {
      issues.push("default-src directive is too permissive or unsafe.");
      recommendations.push({
        issue: "Unsafe default-src directive",
        severity: 4,
        suggestion: "Avoid 'unsafe-inline' and wildcard "*" in default-src directive",
      });
      score -= 40;
    }
  }

  const scriptSrc = directives["script-src"] || directives["default-src"] || [];
  if (scriptSrc.includes("'unsafe-inline'") || scriptSrc.includes("'unsafe-eval'")) {
    issues.push("script-src directive allows unsafe-inline or unsafe-eval.");
    recommendations.push({
      issue: "Unsafe script-src directive",
      severity: 5,
      suggestion: "Remove 'unsafe-inline' and 'unsafe-eval' from script-src directive",
    });
    score -= 50;
  }

  if (directives["style-src"] && directives["style-src"].includes("'unsafe-inline'")) {
    issues.push("style-src directive allows unsafe-inline.");
    recommendations.push({
      issue: "Unsafe style-src directive",
      severity: 3,
      suggestion: "Avoid 'unsafe-inline' in style-src directive",
    });
    score -= 20;
  }

  if ((directives["default-src"] || []).includes("*")) {
    issues.push("Wildcard '*' source in default-src is overly permissive.");
    recommendations.push({
      issue: "Overly permissive wildcard in default-src",
      severity: 4,
      suggestion: "Narrow down allowed sources in default-src directive",
    });
    score -= 40;
  }

  const grade = scoreToGrade(clampScore(score));

  return {
    header,
    present: true,
    value,
    score: clampScore(score),
    grade,
    issues,
    recommendations,
  };
}

function analyzeXFrameOptions(value: string | null): HeaderAnalysis {
  const header = "X-Frame-Options";
  const issues: string[] = [];
  const recommendations: Recommendation[] = [];

  if (!value) {
    issues.push("X-Frame-Options header is missing.");
    recommendations.push({
      issue: "Missing X-Frame-Options",
      severity: 5,
      suggestion: "Add X-Frame-Options header with DENY or SAMEORIGIN",
    });
    return {
      header,
      present: false,
      value: null,
      score: 0,
      grade: "F",
      issues,
      recommendations,
    };
  }

  const val = value.trim().toUpperCase();

  if (val === "DENY" || val === "SAMEORIGIN") {
    return {
      header,
      present: true,
      value,
      score: 100,
      grade: "A+",
      issues,
      recommendations,
    };
  }

  if (val.startsWith("ALLOW-FROM")) {
    issues.push("ALLOW-FROM is deprecated and not supported in many browsers.");
    recommendations.push({
      issue: "Deprecated ALLOW-FROM value",
      severity: 4,
      suggestion: "Use CSP frame-ancestors directive instead of ALLOW-FROM",
    });
    return {
      header,
      present: true,
      value,
      score: 50,
      grade: "C",
      issues,
      recommendations,
    };
  }

  issues.push(`Unrecognized X-Frame-Options value: ${val}`);
  recommendations.push({
    issue: "Unrecognized X-Frame-Options value",
    severity: 4,
    suggestion: "Use DENY or SAMEORIGIN values",
  });
  return {
    header,
    present: true,
    value,
    score: 30,
    grade: "D",
    issues,
    recommendations,
  };
}

function analyzeXContentTypeOptions(value: string | null): HeaderAnalysis {
  const header = "X-Content-Type-Options";
  const issues: string[] = [];
  const recommendations: Recommendation[] = [];

  if (!value) {
    issues.push("X-Content-Type-Options header is missing.");
    recommendations.push({
      issue: "Missing X-Content-Type-Options",
      severity: 5,
      suggestion: "Add X-Content-Type-Options: nosniff header",
    });
    return {
      header,
      present: false,
      value: null,
      score: 0,
      grade: "F",
      issues,
      recommendations,
    };
  }

  if (value.trim().toLowerCase() === "nosniff") {
    return {
      header,
      present: true,
      value,
      score: 100,
      grade: "A+",
      issues,
      recommendations,
    };
  }

  issues.push(`Unexpected X-Content-Type-Options value: ${value}`);
  recommendations.push({
    issue: "Unexpected X-Content-Type-Options value",
    severity: 4,
    suggestion: "Set value to 'nosniff'",
  });
  return {
    header,
    present: true,
    value,
    score: 40,
    grade: "D",
    issues,
    recommendations,
  };
}

function analyzeReferrerPolicy(value: string | null): HeaderAnalysis {
  const header = "Referrer-Policy";
  const issues: string[] = [];
  const recommendations: Recommendation[] = [];

  if (!value) {
    issues.push("Referrer-Policy header is missing.");
    recommendations.push({
      issue: "Missing Referrer-Policy",
      severity: 4,
      suggestion: "Add Referrer-Policy: strict-origin-when-cross-origin or stricter",
    });
    return {
      header,
      present: false,
      value: null,
      score: 0,
      grade: "F",
      issues,
      recommendations,
    };
  }
  
  const valueNorm = value.toLowerCase();
  const safeValues = new Set([
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "no-referrer-when-downgrade",
  ]);
  
  if (safeValues.has(valueNorm)) return {
    header,
    present: true,
    value,
    score: 100,
    grade: "A+",
    issues,
    recommendations,
  };

  if (valueNorm === "origin" || valueNorm === "origin-when-cross-origin") {
    issues.push(`Referrer-Policy value '${value}' leaks origin.`);
    recommendations.push({
      issue: "Referrer-Policy leaks origin",
      severity: 3,
      suggestion: "Use 'strict-origin-when-cross-origin' or stricter policies",
    });
    return {
      header,
      present: true,
      value,
      score: 75,
      grade: "B",
      issues,
      recommendations,
    };
  }

  if (valueNorm === "unsafe-url") {
    issues.push("Referrer-Policy 'unsafe-url' leaks full URL including path and query.");
    recommendations.push({
      issue: "Unsafe Referrer-Policy value",
      severity: 5,
      suggestion: "Avoid 'unsafe-url' as it leaks sensitive information",
    });
    return {
      header,
      present: true,
      value,
      score: 25,
      grade: "D",
      issues,
      recommendations,
    };
  }

  issues.push(`Unrecognized Referrer-Policy value '${value}'.`);
  recommendations.push({
    issue: "Unrecognized Referrer-Policy",
    severity: 3,
    suggestion: "Use recognized, secure policies like 'no-referrer' or 'strict-origin-when-cross-origin'",
  });
  return {
    header,
    present: true,
    value,
    score: 50,
    grade: "C",
    issues,
    recommendations,
  };
}

function analyzePermissionsPolicy(value: string | null): HeaderAnalysis {
  const header = "Permissions-Policy";
  const issues: string[] = [];
  const recommendations: Recommendation[] = [];

  if (!value) {
    issues.push("Permissions-Policy header is missing.");
    recommendations.push({
      issue: "Missing Permissions-Policy",
      severity: 4,
      suggestion: "Add a Permissions-Policy to restrict use of sensitive features (camera, microphone, geolocation, etc.)",
    });
    return {
      header,
      present: false,
      value: null,
      score: 0,
      grade: "F",
      issues,
      recommendations,
    };
  }

  // Simple heuristic: count number of restricted features
  // Policies are comma separated - like "geolocation=(), camera=()"

  const directives = value.split(",").map((d) => d.trim()).filter(Boolean);
  let restrictedFeaturesCount = 0;

  for (const d of directives) {
    if (d.endsWith("=()") || d.includes("=(self)")) {
      restrictedFeaturesCount++;
    }
  }

  let score = 100;

  if (restrictedFeaturesCount >= 5) {
    score = 100;
  } else if (restrictedFeaturesCount >= 2) {
    score = 70;
    issues.push("Only a few sensitive features are restricted.");
    recommendations.push({
      issue: "Few feature restrictions",
      severity: 3,
      suggestion: "Consider restricting more features like camera, microphone, geolocation",
    });
  } else {
    score = 40;
    issues.push("Very few features are restricted in Permissions-Policy.");
    recommendations.push({
      issue: "Minimal feature restrictions",
      severity: 4,
      suggestion: "Restrict sensitive features in Permissions-Policy to improve security",
    });
  }

  const grade = scoreToGrade(clampScore(score));

  return {
    header,
    present: true,
    value,
    score: clampScore(score),
    grade,
    issues,
    recommendations,
  };
}

function analyzeXXssProtection(value: string | null): HeaderAnalysis {
  const header = "X-XSS-Protection";
  const issues: string[] = [];
  const recommendations: Recommendation[] = [];

  if (!value) {
    issues.push("X-XSS-Protection header is missing.");
    recommendations.push({
      issue: "Missing X-XSS-Protection",
      severity: 3,
      suggestion: "Add X-XSS-Protection: 1; mode=block (deprecated but fallback for older browsers)",
    });
    return {
      header,
      present: false,
      value: null,
      score: 30,
      grade: "D",
      issues,
      recommendations,
    };
  }

  const v = value.trim();
  if (v === "0") {
    issues.push("X-XSS-Protection is disabled (value 0).");
    recommendations.push({
      issue: "X-XSS-Protection disabled",
      severity: 2,
      suggestion: "Enable X-XSS-Protection unless relying wholly on CSP",
    });
    return {
      header,
      present: true,
      value,
      score: 50,
      grade: "C",
      issues,
      recommendations,
    };
  }

  if (v.startsWith("1") && v.includes("mode=block")) {
    return {
      header,
      present: true,
      value,
      score: 100,
      grade: "A+",
      issues,
      recommendations,
    };
  }

  if (v.startsWith("1")) {
    issues.push("X-XSS-Protection enabled but mode=block missing.");
    recommendations.push({
      issue: "Enable mode=block",
      severity: 3,
      suggestion: "Use '1; mode=block' to block detected XSS attacks",
    });
    return {
      header,
      present: true,
      value,
      score: 70,
      grade: "B",
      issues,
      recommendations,
    };
  }

  issues.push(`Unrecognized X-XSS-Protection value: ${v}`);
  recommendations.push({
    issue: "Unrecognized value",
    severity: 3,
    suggestion: "Set X-XSS-Protection to '1; mode=block' or '0' if CSP in place",
  });
  return {
    header,
    present: true,
    value,
    score: 40,
    grade: "D",
    issues,
    recommendations,
  };
}

function analyzeCrossOriginEmbedderPolicy(value: string | null): HeaderAnalysis {
  const header = "Cross-Origin-Embedder-Policy";
  const issues: string[] = [];
  const recommendations: Recommendation[] = [];

  if (!value) {
    issues.push("Cross-Origin-Embedder-Policy header is missing.");
    recommendations.push({
      issue: "Missing Cross-Origin-Embedder-Policy",
      severity: 4,
      suggestion: "Add Cross-Origin-Embedder-Policy: require-corp or credentialless for cross-origin isolation",
    });
    return {
      header,
      present: false,
      value: null,
      score: 0,
      grade: "F",
      issues,
      recommendations,
    };
  }
  
  const v = value.trim().toLowerCase();
  if (v === "require-corp" || v === "credentialless") {
    return {
      header,
      present: true,
      value,
      score: 100,
      grade: "A+",
      issues,
      recommendations,
    };
  }
  if (v === "unsafe-none") {
    issues.push("COEP set to unsafe-none disables cross-origin isolation.");
    recommendations.push({
      issue: "Unsafe COEP value",
      severity: 5,
      suggestion: "Set Cross-Origin-Embedder-Policy to 'require-corp' or 'credentialless'",
    });
    return {
      header,
      present: true,
      value,
      score: 30,
      grade: "D",
      issues,
      recommendations,
    };
  }
  issues.push(`Unrecognized COEP value: ${v}`);
  recommendations.push({
    issue: "Unrecognized COEP value",
    severity: 3,
    suggestion: "Use recognized COEP values: require-corp or credentialless",
  });
  return {
    header,
    present: true,
    value,
    score: 50,
    grade: "C",
    issues,
    recommendations,
  };
}

function analyzeCrossOriginOpenerPolicy(value: string | null): HeaderAnalysis {
  const header = "Cross-Origin-Opener-Policy";
  const issues: string[] = [];
  const recommendations: Recommendation[] = [];

  if (!value) {
    issues.push("Cross-Origin-Opener-Policy header is missing.");
    recommendations.push({
      issue: "Missing COOP",
      severity: 4,
      suggestion: "Add Cross-Origin-Opener-Policy: same-origin header for window isolation",
    });
    return {
      header,
      present: false,
      value: null,
      score: 0,
      grade: "F",
      issues,
      recommendations,
    };
  }

  const v = value.trim().toLowerCase();
  if (v === "same-origin") {
    return {
      header,
      present: true,
      value,
      score: 100,
      grade: "A+",
      issues,
      recommendations,
    };
  }
  if (v === "same-origin-allow-popups") {
    issues.push("COOP is set to same-origin-allow-popups which allows opened windows to retain references.");
    recommendations.push({
      issue: "Less strict COOP value",
      severity: 3,
      suggestion: "Use COOP 'same-origin' for better isolation if possible",
    });
    return {
      header,
      present: true,
      value,
      score: 70,
      grade: "B",
      issues,
      recommendations,
    };
  }
  if (v === "unsafe-none") {
    issues.push("COOP set to unsafe-none disables isolation.");
    recommendations.push({
      issue: "Unsafe COOP value",
      severity: 5,
      suggestion: "Use Cross-Origin-Opener-Policy: same-origin",
    });
    return {
      header,
      present: true,
      value,
      score: 30,
      grade: "D",
      issues,
      recommendations,
    };
  }
  issues.push(`Unrecognized COOP value: ${v}`);
  recommendations.push({
    issue: "Unrecognized COOP value",
    severity: 3,
    suggestion: "Use 'same-origin' or 'same-origin-allow-popups'",
  });
  return {
    header,
    present: true,
    value,
    score: 50,
    grade: "C",
    issues,
    recommendations,
  };
}

function analyzeCrossOriginResourcePolicy(value: string | null): HeaderAnalysis {
  const header = "Cross-Origin-Resource-Policy";
  const issues: string[] = [];
  const recommendations: Recommendation[] = [];

  if (!value) {
    issues.push("Cross-Origin-Resource-Policy header is missing.");
    recommendations.push({
      issue: "Missing CORP",
      severity: 4,
      suggestion: "Add Cross-Origin-Resource-Policy: same-origin or same-site",
    });
    return {
      header,
      present: false,
      value: null,
      score: 0,
      grade: "F",
      issues,
      recommendations,
    };
  }

  const v = value.trim().toLowerCase();
  switch (v) {
    case "same-origin":
    case "same-site":
      return {
        header,
        present: true,
        value,
        score: 100,
        grade: "A+",
        issues,
        recommendations,
      };
    case "cross-origin":
      issues.push("CORP set to cross-origin allows embedding by any origin.");
      recommendations.push({
        issue: "Overly permissive CORP",
        severity: 3,
        suggestion: "Set Cross-Origin-Resource-Policy to 'same-origin' or 'same-site' for better security",
      });
      return {
        header,
        present: true,
        value,
        score: 50,
        grade: "C",
        issues,
        recommendations,
      };
    default:
      issues.push(`Unrecognized CORP value: ${v}`);
      recommendations.push({
        issue: "Unrecognized CORP value",
        severity: 3,
        suggestion: "Use 'same-origin', 'same-site', or 'cross-origin'",
      });
      return {
        header,
        present: true,
        value,
        score: 40,
        grade: "D",
        issues,
        recommendations,
      };
  }
}

// Main helper: fetch headers with safeFetch and timeout
async function fetchHeaders(url: string): Promise<Headers> {
  const res = await safeFetch(url, {
    timeoutMs: 10000,
    headers: { "User-Agent": "site-security-baseline/1.0 apimesh.xyz" },
  });
  return res.headers;
}

// SSL analysis helper
async function fetchSslAnalysis(url: URL): Promise<SslAnalysis> {
  try {
    const hostname = url.hostname;
    // We'll fetch head, then get crt.sh data
    const headRes = await safeFetch(url.toString(), {
      method: "HEAD",
      signal: AbortSignal.timeout(10000),
      redirect: "manual",
    });
    if (!headRes.ok && !(headRes.status === 301 || headRes.status === 302)) {
      return {
        valid: false,
        issuer: null,
        validFrom: null,
        validTo: null,
        expiryDays: null,
        strengthScore: 0,
        recommendations: [
          { issue: `HTTP status ${headRes.status} returned from server.`, severity: 5, suggestion: "Ensure site is reachable via HTTPS." },
        ],
      };
    }

    const crtUrl = `https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`;
    const res = await fetch(crtUrl, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) {
      return {
        valid: false,
        issuer: null,
        validFrom: null,
        validTo: null,
        expiryDays: null,
        strengthScore: 0,
        recommendations: [
          { issue: `crt.sh returned HTTP ${res.status}`, severity: 4, suggestion: "Try again later." },
        ],
      };
    }

    const text = await res.text();
    if (!text || text === "[]") {
      return {
        valid: false,
        issuer: null,
        validFrom: null,
        validTo: null,
        expiryDays: null,
        strengthScore: 0,
        recommendations: [
          { issue: "No certificate data found on crt.sh.", severity: 4, suggestion: "Verify SSL certificate is installed." },
        ],
      };
    }

    const certs = JSON.parse(text);
    if (!Array.isArray(certs) || certs.length === 0) {
      return {
        valid: false,
        issuer: null,
        validFrom: null,
        validTo: null,
        expiryDays: null,
        strengthScore: 0,
        recommendations: [
          { issue: "No certificate data found on crt.sh.", severity: 4, suggestion: "Verify SSL certificate is installed." },
        ],
      };
    }

    const cert = certs[certs.length - 1];
    const validFrom = new Date(cert.not_before);
    const validTo = new Date(cert.not_after);
    const now = new Date();
    const expiryDays = validTo > now ? Math.round((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)) : 0;

    let strengthScore = 70;

    if (expiryDays > 60) strengthScore += 20;
    else if (expiryDays <= 30) strengthScore -= 30;

    const sigAlgo = cert.sig_alg || cert.signature_algorithm_name || "";

    if (sigAlgo.toLowerCase().includes("md5") || sigAlgo.toLowerCase().includes("sha1")) {
      strengthScore -= 50;
    } else {
      strengthScore += 10;
    }

    if (strengthScore > 100) strengthScore = 100;
    if (strengthScore < 0) strengthScore = 0;

    const valid = now >= validFrom && now <= validTo;

    const recommendations: Recommendation[] = [];
    if (!valid) {
      recommendations.push({
        issue: "SSL certificate is expired or not yet valid",
        severity: 5,
        suggestion: "Renew or fix SSL certificate validity period",
      });
    }
    if (expiryDays < 30) {
      recommendations.push({
        issue: `SSL cert expires soon in ${expiryDays} days`,
        severity: 4,
        suggestion: "Renew SSL certificate soon to avoid interruptions",
      });
    }
    if (strengthScore < 50) {
      recommendations.push({
        issue: "Weak SSL certificate signature algorithm",
        severity: 4,
        suggestion: "Use stronger signature algorithms like SHA-256",
      });
    }

    return {
      valid,
      issuer: cert.issuer_name || null,
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      expiryDays,
      strengthScore: clampScore(strengthScore),
      recommendations,
    };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      valid: null,
      issuer: null,
      validFrom: null,
      validTo: null,
      expiryDays: null,
      strengthScore: 0,
      recommendations: [{ issue: `Error fetching SSL info: ${msg}`, severity: 5, suggestion: "Try again later." }],
      error: msg,
    };
  }
}

// Aggregate overall score and grade
function computeOverallScore(
  headers: HeaderAnalysis[],
  ssl: SslAnalysis
): { score: number; grade: Grade } {
  let totalScore = 0;
  let totalWeight = 0;

  // Weight headers equally
  for (const h of headers) {
    totalScore += h.score;
    totalWeight += 100;
  }

  // SSL weight around 200 (double headers)
  if (ssl.strengthScore !== null && ssl.strengthScore !== undefined) {
    totalScore += ssl.strengthScore * 2;
    totalWeight += 200;
  }

  const avgScore = totalWeight > 0 ? totalScore / totalWeight : 0;
  return { score: clampScore(avgScore), grade: scoreToGrade(avgScore) };
}

// Aggregate recommendations
function aggregateRecommendations(
  headers: HeaderAnalysis[],
  ssl: SslAnalysis
): Recommendation[] {
  const recs: Recommendation[] = [];
  for (const h of headers) {
    recs.push(...h.recommendations);
  }
  if (ssl.recommendations) recs.push(...ssl.recommendations);

  // Sort by severity descending
  recs.sort((a, b) => b.severity - a.severity);

  return recs;
}

// Validate and analyze all headers
async function analyzeAllHeaders(url: string): Promise<HeaderAnalysis[]> {
  const hdrs = await fetchHeaders(url);
  const results: HeaderAnalysis[] = [];

  // Map header -> analyzer
  const analyzers: Record<string, (val: string | null) => HeaderAnalysis> = {
    "Strict-Transport-Security": analyzeHsts,
    "Content-Security-Policy": analyzeCsp,
    "X-Frame-Options": analyzeXFrameOptions,
    "X-Content-Type-Options": analyzeXContentTypeOptions,
    "Referrer-Policy": analyzeReferrerPolicy,
    "Permissions-Policy": analyzePermissionsPolicy,
    "X-XSS-Protection": analyzeXXssProtection,
    "Cross-Origin-Embedder-Policy": analyzeCrossOriginEmbedderPolicy,
    "Cross-Origin-Opener-Policy": analyzeCrossOriginOpenerPolicy,
    "Cross-Origin-Resource-Policy": analyzeCrossOriginResourcePolicy,
  };

  for (const header of SECURITY_HEADERS) {
    const val = hdrs.get(header);
    const anal = analyzers[header];
    try {
      if (anal) {
        results.push(anal(val));
      } else {
        // Unknown, present or not
        results.push({
          header,
          present: val !== null,
          value: val,
          score: val !== null ? 80 : 0,
          grade: val !== null ? "B" : "F",
          issues: [],
          recommendations: [],
        });
      }
    } catch (e) {
      results.push({
        header,
        present: val !== null,
        value: val,
        score: 0,
        grade: "F",
        issues: ["Error analyzing header."],
        recommendations: [{ issue: "Error analyzing header", severity: 5, suggestion: "Check header format and retry." }],
      });
    }
  }

  return results;
}

// Public full audit
export async function fullSecurityBaselineAudit(
  rawUrl: string
): Promise<SiteSecurityBaselineResult | { error: string }> {
  const validation = validateExternalUrl(rawUrl);
  if ("error" in validation) return { error: validation.error };

  const url = validation.url.toString();
  const parsedUrl = validation.url;

  try {
    // Run header and SSL fetches in parallel
    const [headerAnalyses, sslAnalysis] = await Promise.all([
      analyzeAllHeaders(url),
      fetchSslAnalysis(parsedUrl),
    ]);

    const overall = computeOverallScore(headerAnalyses, sslAnalysis);
    const recommendations = aggregateRecommendations(headerAnalyses, sslAnalysis);

    return {
      url,
      headerAnalyses,
      sslAnalysis,
      overallScore: overall.score,
      overallGrade: overall.grade,
      recommendations,
      explanation: "Comprehensive security baseline assessment combining multiple header and SSL checks with actionable recommendations.",
      scannedAt: new Date().toISOString(),
    };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Unexpected error during analysis: ${msg}` };
  }
}

// Preview audit does minimal fetch and returns limited summary
export async function previewSecurityBaselineAudit(
  rawUrl: string
): Promise<SiteSecurityBaselinePreviewResult | { error: string }> {
  const validation = validateExternalUrl(rawUrl);
  if ("error" in validation) return { error: validation.error };

  const url = validation.url.toString();
  const parsedUrl = validation.url;

  try {
    // Fetch only HEAD with 15s timeout
    const res = await safeFetch(url, {
      method: "HEAD",
      timeoutMs: 15000,
      headers: { "User-Agent": "site-security-baseline-preview/1.0 apimesh.xyz" },
    });

    const headers = res.headers;

    let securityHeadersScore = 0;
    let countHeaders = 0;

    for (const header of ["Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]) {
      if (headers.has(header)) {
        securityHeadersScore += 33;
      }
      countHeaders++;
    }

    const sslValid = parsedUrl.protocol === "https:" && res.ok;
    const sslGrade: Grade | null = sslValid ? "B" : "F";
    const recommendationsCount = 0;

    return {
      url,
      preview: true,
      summary: {
        securityHeadersScore: Math.min(securityHeadersScore, 100),
        sslGrade,
        recommendationsCount,
      },
      explanation:
        "Preview performs lightweight checks for HTTPS availability and key security headers. Full detailed audit is available via the paid /check endpoint.",
    };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return {
      url,
      preview: true,
      summary: { securityHeadersScore: 0, sslGrade: null, recommendationsCount: 0 },
      explanation: `Preview analysis failed: ${msg}`,
    };
  }
}
