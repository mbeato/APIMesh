import { validateExternalUrl, safeFetch } from "../../shared/ssrf";

// -----------------------------------
// Types
// -----------------------------------

export interface ScanResult {
  url: string;
  riskScore: number; // 0-100
  grade: string; // A-F uppercase
  checks: CheckResult[];
  recommendations: Recommendation[];
  scannedAt: string;
}

export interface CheckResult {
  name: string;
  score: number; // 0-100
  severity: Severity;
  details: string;
}

export interface Recommendation {
  issue: string;
  severity: Severity;
  suggestion: string;
}

export type Severity = "Low" | "Medium" | "High";

export interface PreviewResult {
  url: string;
  headerChecks: HeaderCheck[];
  riskScore: number;
  grade: string;
  scannedAt: string;
  note: string;
}

export interface HeaderCheck {
  name: string;
  present: boolean;
  value: string | null;
  rating: string; // A-F
  issues: string[];
}

// --- Utility grading helpers ---

function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  if (score >= 40) return "E";
  return "F";
}

function severityFromScore(score: number): Severity {
  if (score >= 80) return "Low";
  if (score >= 60) return "Medium";
  return "High";
}

// --- Helper functions ---

async function fetchHeaders(url: string): Promise<Headers> {
  // AbortSignal timeout 10000 as required
  return await safeFetch(url, {
    method: "HEAD",
    timeoutMs: 10000,
    headers: { "User-Agent": "web-misconfiguration-scan/1.0 apimesh.xyz" },
  }).then((res) => res.headers);
}

async function fetchGetText(url: string): Promise<string> {
  const res = await safeFetch(url, {
    method: "GET",
    timeoutMs: 10000,
    headers: { "User-Agent": "web-misconfiguration-scan/1.0 apimesh.xyz" },
  });
  return await res.text();
}

// --- Individual checks implementations ---

async function checkSecurityHeaders(url: string): Promise<CheckResult> {
  // Check presence and quality of common security headers
  // Fetch headers
  let headers: Headers;
  try {
    headers = await fetchHeaders(url);
  } catch (e) {
    throw new Error(`Failed to fetch headers: ${e instanceof Error ? e.message : String(e)}`);
  }

  // Important security headers to check (subset)
  const headersToCheck = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
  ];

  const missing: string[] = [];
  let score = 100;
  const issues: string[] = [];

  for (const h of headersToCheck) {
    if (!headers.has(h)) {
      missing.push(h);
      score -= 12; // missing one header reduces score by 12 approx
      issues.push(`${h} header is missing.`);
    } else {
      // For some headers we do quick validation here
      const val = headers.get(h) ?? "";
      if (h === "strict-transport-security") {
        if (!val.match(/max-age=\d+/i)) {
          score -= 8;
          issues.push("HSTS header does not have a valid max-age.");
        }
      } else if (h === "content-security-policy") {
        if (val.trim() === "") {
          score -= 10;
          issues.push("CSP header is empty.");
        } else if (val.includes("unsafe-inline") || val.includes("unsafe-eval")) {
          score -= 10;
          issues.push("CSP header allows unsafe-inline or unsafe-eval, which weakens protection.");
        }
      }
      // Other headers could be checked similarly
    }
  }

  if (score < 0) score = 0;

  return {
    name: "Security Headers",
    score,
    severity: severityFromScore(score),
    details: issues.length > 0 ? issues.join(" ") : "Security headers are properly configured.",
  };
}

async function checkEnvironmentDisclosure(url: string): Promise<CheckResult> {
  // Check if certain headers or response data reveal environment info
  let headers: Headers;
  try {
    headers = await fetchHeaders(url);
  } catch (e) {
    throw new Error(`Failed to fetch headers: ${e instanceof Error ? e.message : String(e)}`);
  }

  const serverHeader = headers.get("server");
  // We check for typical version disclosures or internal technology leaking
  const issues: string[] = [];
  let score = 100;

  if (serverHeader) {
    // If contains version numbers or common keywords
    if (serverHeader.match(/apache\/\d|nginx\/\d|iis\/\d/i)) {
      issues.push(`Server header reveals backend version: ${serverHeader}`);
      score -= 40;
    } else {
      score -= 5; // minor info leak
    }
  } else {
    score -= 0; // no info leak
  }

  // Check X-Powered-By header for versions
  const xPoweredBy = headers.get("x-powered-by");
  if (xPoweredBy) {
    issues.push(`X-Powered-By header reveals tech stack: ${xPoweredBy}`);
    score -= 35;
  }

  if (score < 0) score = 0;
  if (score === 100) {
    return {
      name: "Environment Disclosure",
      score,
      severity: "Low",
      details: "No sensitive environment info disclosed in headers.",
    };
  }

  return {
    name: "Environment Disclosure",
    score,
    severity: severityFromScore(score),
    details: issues.join(" "),
  };
}

async function checkFilePresence(url: string): Promise<CheckResult> {
  // Check common sensitive file existence
  // Check via GET requests with 10000ms timeout each, parallel

  const paths = ["/.git/HEAD", "/.env", "/config.php", "/.htaccess", "/README.md"];

  const baseUrl = new URL(url);
  baseUrl.hash = ""; baseUrl.search = "";
  const base = baseUrl.toString().replace(/\/$/, "");

  const results = await Promise.all(
    paths.map(async (path) => {
      try {
        const res = await safeFetch(base + path, {
          method: "GET",
          timeoutMs: 10000,
          headers: { "User-Agent": "web-misconfiguration-scan/1.0 apimesh.xyz" },
        });
        return { path, ok: res.ok, status: res.status, length: Number(res.headers.get("content-length") || "0") };
      } catch (e) {
        return { path, ok: false, status: 0, length: 0 };
      }
    })
  );

  // Evaluate findings
  const foundPaths = results.filter(r => r.ok && r.status === 200 && r.length > 10).map(r => r.path);
  let score = 100 - (foundPaths.length * 15);
  if (score < 0) score = 0;

  const details = foundPaths.length > 0
    ? `Accessible sensitive files: ${foundPaths.join(", ")}`
    : "No common sensitive files detected.";

  const severity = severityFromScore(score);
  
  return {
    name: "File Presence",
    score,
    severity,
    details,
  };
}

async function checkCommonVulnerabilities(url: string): Promise<CheckResult> {
  // Check common misconfiguration vulnerabilities, e.g. insecure headers, missing cookie flags
  // For demo: check if X-XSS-Protection header is set to 0 or missing
  // and if cookies have Secure or HttpOnly flags

  let headers: Headers;
  try {
    headers = await fetchHeaders(url);
  } catch (e) {
    throw new Error(`Failed to fetch headers: ${e instanceof Error ? e.message : String(e)}`);
  }

  let score = 100;
  const issues: string[] = [];

  const xssProtection = headers.get("x-xss-protection");
  if (!xssProtection) {
    issues.push("X-XSS-Protection header is missing.");
    score -= 20;
  } else if (xssProtection.trim() === "0") {
    issues.push("X-XSS-Protection header is disabled via '0'.");
    score -= 10;
  }

  // Check cookie flags
  const setCookieHeaders = headers.get("set-cookie");
  if (setCookieHeaders) {
    // Parse cookie strings - very basic
    const cookies = setCookieHeaders.split(",");
    const insecureCookies = cookies.filter(c => !/;\s*secure/i.test(c) || !/;\s*httponly/i.test(c));
    if (insecureCookies.length > 0) {
      issues.push(`Cookies missing Secure or HttpOnly flags: ${insecureCookies.join(", ")}`);
      score -= 20;
    }
  }

  if (score < 0) score = 0;
  const severity = severityFromScore(score);
  const details = issues.length > 0 ? issues.join(" ") : "Common vulnerabilities checks passed.";

  return {
    name: "Common Vulnerabilities",
    score,
    severity,
    details,
  };
}

async function checkOpenPorts(url: string): Promise<CheckResult> {
  // As we cannot scan ports directly here, we'll simulate check by querying a public port scan API or similar
  // Since external APIs are disallowed, we do a basic DNS resolution and heuristics
  // For demo: always return score 100 with no issues

  return {
    name: "Open Ports",
    score: 100,
    severity: "Low",
    details: "Port scanning not supported. Recommend external security scans for open ports.",
  };
}

// Main analyze function
export async function analyzeMisconfiguration(rawUrl: string): Promise<ScanResult | { error: string }> {
  const validation = validateExternalUrl(rawUrl);
  if ("error" in validation) return { error: validation.error };

  const url = validation.url.toString();

  try {
    // Run all checks in parallel
    const [secHeaders, envDisc, filePres, vuln, openPorts] = await Promise.all([
      checkSecurityHeaders(url),
      checkEnvironmentDisclosure(url),
      checkFilePresence(url),
      checkCommonVulnerabilities(url),
      checkOpenPorts(url),
    ]);

    // Calculate weighted average risk score
    // Weights chosen arbitrarily to reflect importance
    const weights = {
      SecurityHeaders: 0.3,
      EnvironmentDisclosure: 0.25,
      FilePresence: 0.2,
      CommonVulnerabilities: 0.15,
      OpenPorts: 0.1,
    };

    const weightedScore =
      secHeaders.score * weights.SecurityHeaders +
      envDisc.score * weights.EnvironmentDisclosure +
      filePres.score * weights.FilePresence +
      vuln.score * weights.CommonVulnerabilities +
      openPorts.score * weights.OpenPorts;

    // Risk score is inverse of average security score
    const riskScore = Math.round(100 - weightedScore);

    // Grade based on risk score (inverse of security)
    let grade = "A";
    if (riskScore >= 80) grade = "F";
    else if (riskScore >= 60) grade = "D";
    else if (riskScore >= 40) grade = "C";
    else if (riskScore >= 20) grade = "B";

    // Combine all checks
    const checks = [secHeaders, envDisc, filePres, vuln, openPorts];

    // Aggregate recommendations
    const recommendations: Recommendation[] = [];

    if (!secHeaders.details.includes("missing")) {
      // No security header misses
    } else {
      recommendations.push({
        issue: "Missing or weak security headers",
        severity: "High",
        suggestion: "Implement all recommended security headers, especially Content-Security-Policy, HSTS, and X-Frame-Options.",
      });
    }

    if (envDisc.details) {
      recommendations.push({
        issue: "Environment information is exposed",
        severity: "High",
        suggestion: "Remove sensitive headers like Server and X-Powered-By or mask version details.",
      });
    }

    if (filePres.details && !filePres.details.includes("No common sensitive files")) {
      recommendations.push({
        issue: "Sensitive files accessible",
        severity: "Medium",
        suggestion: "Restrict access to .git, .env, config.php, and similar sensitive files or folders via webserver configs.",
      });
    }

    if (vuln.details && !vuln.details.includes("Common vulnerabilities checks passed")) {
      recommendations.push({
        issue: "Common HTTP vulnerabilities found",
        severity: "Medium",
        suggestion: "Address missing HTTP headers and ensure cookies are Secure and HttpOnly.",
      });
    }

    // Add a generic recommendation
    recommendations.push({
      issue: "Regular maintenance",
      severity: "Medium",
      suggestion: "Regularly scan and patch server components to minimize vulnerabilities.",
    });

    return {
      url,
      riskScore,
      grade,
      checks,
      recommendations,
      scannedAt: new Date().toISOString(),
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Failed to analyze misconfiguration: ${msg}` };
  }
}

// Quick preview function, just checks a few headers
export async function previewMisconfiguration(rawUrl: string): Promise<PreviewResult | { error: string }> {
  const validation = validateExternalUrl(rawUrl);
  if ("error" in validation) return { error: validation.error };
  const url = validation.url.toString();

  try {
    const headers = await fetchHeaders(url);

    const headerNames = ["strict-transport-security", "x-frame-options", "x-content-type-options"];
    const headerChecks: HeaderCheck[] = [];
    let score = 100;

    for (const name of headerNames) {
      const value = headers.get(name);
      if (!value) {
        headerChecks.push({ name, present: false, value: null, rating: "F", issues: ["Header missing"] });
        score -= 30;
      } else {
        // Basic rating
        let rating = "A";
        const issues: string[] = [];
        if (name === "strict-transport-security") {
          if (!value.match(/max-age=\d+/)) {
            rating = "C";
            issues.push("max-age directive missing or invalid");
            score -= 20;
          }
        }
        headerChecks.push({ name, present: true, value, rating, issues });
      }
    }

    if (score < 0) score = 0;
    let grade = scoreToGrade(score);

    return {
      url,
      headerChecks,
      riskScore: 100 - score,
      grade,
      scannedAt: new Date().toISOString(),
      note: "Preview scans limited headers only. Full scan requires payment.",
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Failed to perform preview scan: ${msg}` };
  }
}
