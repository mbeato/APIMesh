import {
  safeFetch,
  validateExternalUrl,
  readBodyCapped,
} from "../../shared/ssrf";

export interface AuditScore {
  score: number; // 0-100
  grade: string; // A-F
}

export interface AuditRecommendations {
  issue: string;
  severity: "low" | "medium" | "high";
  suggestion: string;
}

export interface WebConfigurationAuditResult {
  url: string;
  checksPerformed: string[];
  // Scores for each check
  scores?: {
    robotsTxtScore: number;
    sitemapScore: number;
    headersScore: number;
    metaTagsScore: number;
    envExposureScore: number;
    overallScore: number;
    grade: string;
  };
  // For preview
  summaryScore?: number;
  grade?: string;
  recommendations: AuditRecommendations[];
  details: string;
  duration_ms?: number;
}

function gradeFromScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  if (score >= 30) return "E";
  return "F";
}

// Utilities
async function fetchRobotsTxt(url: URL, signal: AbortSignal): Promise<string | null> {
  try {
    const origin = url.origin;
    const res = await safeFetch(origin + "/robots.txt", { signal });
    if (!res.ok) return null;
    const text = await readBodyCapped(res, 100_000);
    return text;
  } catch {
    return null;
  }
}

async function fetchSitemapXml(url: URL, signal: AbortSignal): Promise<string | null> {
  try {
    const origin = url.origin;
    const candidatePaths = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"];
    for (const path of candidatePaths) {
      try {
        const res = await safeFetch(origin + path, { signal });
        if (res.ok) {
          const text = await readBodyCapped(res, 200_000);
          if (text && text.includes("<urlset") || text.includes("<sitemapindex")) {
            return text;
          }
        }
      } catch {
        // try next
      }
    }
    return null;
  } catch {
    return null;
  }
}

async function fetchMainPageHeaders(url: URL, signal: AbortSignal): Promise<Headers | null> {
  try {
    // We use HEAD request to get headers only
    const res = await safeFetch(url.toString(), { method: "HEAD", signal, timeoutMs: 8000 });
    if (!res.ok) return null;
    return res.headers;
  } catch {
    return null;
  }
}

async function fetchMainPageHtml(url: URL, signal: AbortSignal): Promise<string | null> {
  try {
    const res = await safeFetch(url.toString(), { method: "GET", signal, timeoutMs: 10_000 });
    if (!res.ok) return null;
    const text = await readBodyCapped(res, 300_000);
    return text;
  } catch {
    return null;
  }
}

async function checkDotEnvExposure(url: URL, signal: AbortSignal): Promise<boolean | null> {
  try {
    // Attempt to fetch .env from the root
    const envUrl = new URL("/.env", url.origin).toString();
    const res = await safeFetch(envUrl, { signal, timeoutMs: 8000 });
    if (res.ok) {
      const text = await readBodyCapped(res, 100_000);
      // Heuristics: presence of KEY= or typical env syntax
      if (text && /\w+=/.test(text)) return true;
    } else if (res.status === 404 || res.status === 403) {
      return false;
    }
    return false;
  } catch {
    return null;
  }
}

function analyzeRobotsTxt(content: string | null): { score: number; issues: AuditRecommendations[] } {
  const issues: AuditRecommendations[] = [];
  if (!content) {
    issues.push({
      issue: "Missing robots.txt",
      severity: "medium",
      suggestion: "Create and configure robots.txt to control crawler access and limit sensitive path exposure.",
    });
    return { score: 40, issues };
  }
  // Check for common mistakes
  if (/Disallow:\s*\/\s*/i.test(content)) {
    // over disallowing may block everything
    issues.push({
      issue: "robots.txt with full site disallow",
      severity: "low",
      suggestion: "Review robots.txt to allow indexing of necessary pages.",
    });
  }
  if (!/User-agent:/i.test(content)) {
    issues.push({
      issue: "robots.txt missing User-agent directive",
      severity: "medium",
      suggestion: "Add User-agent directives to specify crawler rules.",
    });
  }
  let score = 80;
  if (issues.length > 0) score -= 30;
  if (content.length > 20_000) score -= 20; // suspicious big robots.txt
  if (score < 0) score = 0;
  return { score, issues };
}

function analyzeSitemapXml(content: string | null): { score: number; issues: AuditRecommendations[] } {
  const issues: AuditRecommendations[] = [];
  if (!content) {
    issues.push({
      issue: "Missing sitemap.xml",
      severity: "medium",
      suggestion: "Add sitemap.xml to assist search engines and improve indexing.",
    });
    return { score: 40, issues };
  }
  // Check for well formed xml with <urlset> or <sitemapindex>
  if (!/<(urlset|sitemapindex)[\s>]/i.test(content)) {
    issues.push({
      issue: "Sitemap XML malformed or missing root elements",
      severity: "high",
      suggestion: "Fix sitemap.xml format to valid Sitemap Protocol XML.",
    });
    return { score: 50, issues };
  }
  // Check if sitemap very small
  if ((content.match(/<url>/gi) || []).length < 3) {
    issues.push({
      issue: "Sitemap contains very few URLs",
      severity: "low",
      suggestion: "Ensure sitemap.xml contains all relevant pages for SEO.",
    });
  }
  return { score: 80, issues };
}

function analyzeHeaders(headers: Headers | null): { score: number; issues: AuditRecommendations[] } {
  const issues: AuditRecommendations[] = [];
  if (!headers) {
    issues.push({
      issue: "No headers received",
      severity: "high",
      suggestion: "Ensure the website is reachable and responds with headers.",
    });
    return { score: 0, issues };
  }

  // Check essential security headers
  const expectedHeaders = [
    { name: "content-security-policy", importance: "high" },
    { name: "strict-transport-security", importance: "high" },
    { name: "x-frame-options", importance: "medium" },
    { name: "x-content-type-options", importance: "medium" },
    { name: "referrer-policy", importance: "medium" },
  ];
  let score = 100;
  for (const hdr of expectedHeaders) {
    if (!headers.has(hdr.name)) {
      issues.push({
        issue: `Missing header: ${hdr.name}`,
        severity: hdr.importance === "high" ? "high" : "medium",
        suggestion: `Add the ${hdr.name} header to improve security and privacy.`,
      });
      score -= hdr.importance === "high" ? 20 : 10;
    }
  }
  if (score < 0) score = 0;
  return { score, issues };
}

function analyzeMetaTags(html: string | null): { score: number; issues: AuditRecommendations[] } {
  const issues: AuditRecommendations[] = [];
  if (!html) {
    issues.push({
      issue: "Main page HTML not available",
      severity: "high",
      suggestion: "Ensure the website is reachable and returns HTML content.",
    });
    return { score: 0, issues };
  }

  // Basic meta tags to check
  const requiredTags = [
    { tag: "meta[name=viewport]", desc: "Responsive viewport meta tag" },
    { tag: "meta[charset]", desc: "Character encoding declaration" },
    { tag: "meta[http-equiv=Content-Security-Policy]", desc: "CSP Meta tag (deprecated but sometimes present)" },
    { tag: "meta[name=robots]", desc: "Robots control meta tag" },
  ];
  
  // Simple searching
  let score = 100;
  for (const tag of requiredTags) {
    const regex = new RegExp(`<${tag.tag.replace(/\[/g, "\\[").replace(/\]/g, "\\]")}.+?>`, "i");
    if (!regex.test(html)) {
      issues.push({
        issue: `Missing ${tag.desc}`,
        severity: "low",
        suggestion: `Add ${tag.desc} to the HTML document's <head> section.`,
      });
      score -= 15;
    }
  }

  if (score < 0) score = 0;
  return { score, issues };
}

async function runFullAudit(rawUrl: string): Promise<WebConfigurationAuditResult | { error: string }> {
  const start = performance.now();
  // Validate URL
  const validation = validateExternalUrl(rawUrl);
  if ("error" in validation) {
    return { error: validation.error };
  }
  const url = validation.url;

  // Prepare AbortSignal
  const signal = AbortSignal.timeout(10_000);

  // Parallel fetch operations
  let [robotsTxt, sitemapXml, mainHeaders, mainHtml, envExposure] =
    await Promise.all([
      fetchRobotsTxt(url, signal),
      fetchSitemapXml(url, signal),
      fetchMainPageHeaders(url, signal),
      fetchMainPageHtml(url, signal),
      checkDotEnvExposure(url, signal),
    ]);

  // Analyze each
  const robotsAnalysis = analyzeRobotsTxt(robotsTxt);
  const sitemapAnalysis = analyzeSitemapXml(sitemapXml);
  const headersAnalysis = analyzeHeaders(mainHeaders);
  const metaTagsAnalysis = analyzeMetaTags(mainHtml);

  // Env exposure
  let envExposureScore = 100;
  const recommendations: AuditRecommendations[] = [];
  if (envExposure === true) {
    envExposureScore = 0;
    recommendations.push({
      issue: ".env file publicly accessible",
      severity: "high",
      suggestion: "Block public access to the .env file by server configuration and remove sensitive data exposure.",
    });
  } else if (envExposure === null) {
    envExposureScore = 40;
    recommendations.push({
      issue: ".env file access check failed",
      severity: "medium",
      suggestion: "Ensure .env file is not accessible to public; audit server configuration.",
    });
  }

  // Aggregate recommendations from analyses
  const allRecommendations = [
    ...robotsAnalysis.issues,
    ...sitemapAnalysis.issues,
    ...headersAnalysis.issues,
    ...metaTagsAnalysis.issues,
    ...recommendations,
  ];

  // Compute overall score weighted average:
  // weights: robots 20%, sitemap 15%, headers 30%, metaTags 20%, envExposure 15%
  const overallScoreRaw =
    robotsAnalysis.score * 0.20 +
    sitemapAnalysis.score * 0.15 +
    headersAnalysis.score * 0.30 +
    metaTagsAnalysis.score * 0.20 +
    envExposureScore * 0.15;

  const overallScore = Math.round(overallScoreRaw);
  const grade = gradeFromScore(overallScore);

  const duration_ms = Math.round(performance.now() - start);

  const details = `Audit completed combining robots.txt, sitemap.xml, HTTP headers, meta tags, and .env file presence checks. Each component was assigned a severity-weighted score and overall grade computed.`;

  return {
    url: url.toString(),
    checksPerformed: ["robots.txt", "sitemap.xml", "headers", "metaTags", ".envExposure"],
    scores: {
      robotsTxtScore: Math.round(robotsAnalysis.score),
      sitemapScore: Math.round(sitemapAnalysis.score),
      headersScore: Math.round(headersAnalysis.score),
      metaTagsScore: Math.round(metaTagsAnalysis.score),
      envExposureScore: envExposureScore,
      overallScore,
      grade,
    },
    recommendations: allRecommendations,
    details,
    duration_ms,
  };
}

async function runPreviewAudit(
  rawUrl: string,
  signal: AbortSignal
): Promise<WebConfigurationAuditResult | { error: string }> {
  const start = performance.now();
  // Validate URL
  const validation = validateExternalUrl(rawUrl);
  if ("error" in validation) {
    return { error: validation.error };
  }
  const url = validation.url;

  // To speed preview, fetch robots.txt, sitemap.xml, and main headers only in parallel
  try {
    const [robotsTxt, sitemapXml, mainHeaders] = await Promise.all([
      fetchRobotsTxt(url, signal),
      fetchSitemapXml(url, signal),
      fetchMainPageHeaders(url, signal),
    ]);

    const robotsAnalysis = analyzeRobotsTxt(robotsTxt);
    const sitemapAnalysis = analyzeSitemapXml(sitemapXml);
    const headersAnalysis = analyzeHeaders(mainHeaders);

    // Combine partial score with simpler weights
    const summaryScoreRaw =
      robotsAnalysis.score * 0.35 + sitemapAnalysis.score * 0.35 + headersAnalysis.score * 0.30;
    const summaryScore = Math.round(summaryScoreRaw);
    const grade = gradeFromScore(summaryScore);
    const duration_ms = Math.round(performance.now() - start);

    const details = `Preview audit performed with limited checks: robots.txt, sitemap.xml, and HTTP headers. For full audit including meta tags and .env exposure, purchase full access.`;

    const allRecommendations = [...robotsAnalysis.issues, ...sitemapAnalysis.issues, ...headersAnalysis.issues];

    return {
      url: url.toString(),
      checksPerformed: ["robots.txt", "sitemap.xml", "headers"],
      summaryScore,
      grade,
      recommendations: allRecommendations,
      details,
      duration_ms,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: msg };
  }
}

export { runFullAudit, runPreviewAudit };
