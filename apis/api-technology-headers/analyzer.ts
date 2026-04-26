import { safeFetch, validateExternalUrl } from "../../shared/ssrf";

export interface Technology {
  name: string;
  version: string | null;
  confidence: number; // 0-100
}

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface TechnologyHeadersResult {
  url: string;
  technologies: Technology[];
  outdated: boolean;
  score: number; // 0-100
  grade: string; // A-F
  recommendations: Recommendation[];
  explanation: string;
}

export interface PreviewResult {
  url: string;
  technologies: Technology[];
  score: number;
  grade: string;
  recommendations: Recommendation[];
  explanation: string;
  preview: true;
}

// We define server header keys often seen
const SERVER_HEADER_KEYS = ["server", "x-powered-by", "x-generator", "via"];

// Known technology patterns mapping header (name to regex for version)
const TECH_PATTERNS: {
  [tech: string]: {
    header: string;
    regex: RegExp | null; // if null => presence is enough, no version
    deprecatedVersions?: string[];
  };
} = {
  Apache: { header: "server", regex: /Apache\/?(\d+\.\d+(\.\d+)?)/i, deprecatedVersions: ["2.2", "2.4"] },
  nginx: { header: "server", regex: /nginx\/?(\d+\.\d+(\.\d+)?)/i },
  PHP: { header: "x-powered-by", regex: /PHP\/?(\d+\.\d+(\.\d+)?)/i, deprecatedVersions: ["7.4", "8.0"] },
  IIS: { header: "server", regex: /Microsoft-IIS\/?(\d+\.\d+)/i },
  Express: { header: "x-powered-by", regex: /Express/i },
  WordPress: { header: "x-powered-by", regex: /WordPress/i },
  "Cloudflare": { header: "server", regex: /cloudflare/i },
  "LiteSpeed": { header: "server", regex: /litespeed/i },
  "OpenResty": { header: "server", regex: /openresty/i },
  "DotNet": { header: "x-powered-by", regex: /ASP\.NET/i },
  "Shopify": { header: "via", regex: /shopify/i },
};

function sanitizeFetchError(err: unknown): string {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  if (msg.includes("private") || msg.includes("internal")) return "URL not allowed";
  if (msg.includes("timeout")) return "Request timed out";
  if (msg.includes("dns") || msg.includes("notfound")) return "DNS lookup failed";
  if (msg.includes("redirect")) return "Too many redirects";
  if (msg.includes("invalid url")) return "Invalid URL";
  return "Unable to reach the target URL";
}

function letterGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 50) return "D";
  return "F";
}

function calculateScore(technologies: Technology[], outdated: boolean): number {
  if (technologies.length === 0) return 0;
  // Base score 100 reduced by outdated severity and confidence weighted
  let score = 100;
  if (outdated) {
    score -= 30;
  }
  for (const tech of technologies) {
    if (tech.confidence < 50) score -= 10;
  }
  if (score < 0) score = 0;
  if (score > 100) score = 100;
  return Math.round(score);
}

function recommendOutdated(tech: Technology): Recommendation {
  return {
    issue: `${tech.name} version ${tech.version ?? "unknown"} is outdated or insecure`,
    severity: 80,
    suggestion: `Upgrade ${tech.name} to the latest stable version to patch security vulnerabilities and improve performance`,
  };
}

function recommendUnknownVersion(tech: Technology): Recommendation {
  return {
    issue: `${tech.name} detected but version is unknown`,
    severity: 50,
    suggestion: `Ensure version information for ${tech.name} is exposed in headers or perform a full scan to determine versions accurately`,
  };
}

function recommendNoTechFound(): Recommendation {
  return {
    issue: "Unable to identify server or platform technology from headers",
    severity: 60,
    suggestion: "Try running the paid scan with more exhaustive methods or check if headers are obscured or stripped",
  };
}

async function fetchAndParseHeaders(url: string): Promise<Headers> {
  const res = await safeFetch(url, {
    method: "GET",
    signal: AbortSignal.timeout(10_000),
    headers: { "User-Agent": "api-technology-headers/1.0 apimesh.xyz" },
  });

  return res.headers;
}

function identifyTechnologies(headers: Headers): Technology[] {
  const technologies: Technology[] = [];

  for (const [techName, data] of Object.entries(TECH_PATTERNS)) {
    const headerValue = headers.get(data.header);
    if (!headerValue) continue;

    if (data.regex) {
      const match = headerValue.match(data.regex);
      if (match) {
        const version = match[1] ?? null;
        const confidence = 80 + (version ? 10 : 0);
        technologies.push({ name: techName, version, confidence });
      }
    } else {
      // Presence-only tech
      if (data.header === "x-powered-by") {
        // Check exact keyword presence case-insensitive
        const found = headerValue.toLowerCase().includes(techName.toLowerCase());
        if (found) {
          technologies.push({ name: techName, version: null, confidence: 60 });
        }
      } else {
        // assume present
        technologies.push({ name: techName, version: null, confidence: 50 });
      }
    }
  }

  return technologies;
}

function detectOutdatedTechnologies(technologies: Technology[]): boolean {
  for (const tech of technologies) {
    const known = TECH_PATTERNS[tech.name];
    if (tech.version && known && known.deprecatedVersions) {
      for (const deprecated of known.deprecatedVersions) {
        if (tech.version.startsWith(deprecated)) {
          return true;
        }
      }
    }
  }
  return false;
}

// Compose recommendations from detected technologies
function generateRecommendations(technologies: Technology[], outdated: boolean): Recommendation[] {
  const recs: Recommendation[] = [];
  if (technologies.length === 0) {
    recs.push(recommendNoTechFound());
    return recs;
  }

  for (const tech of technologies) {
    if (tech.version === null) {
      recs.push(recommendUnknownVersion(tech));
    } else {
      const known = TECH_PATTERNS[tech.name];
      if (known?.deprecatedVersions) {
        for (const deprecated of known.deprecatedVersions) {
          if (tech.version.startsWith(deprecated)) {
            recs.push(recommendOutdated(tech));
            break;
          }
        }
      }
    }
  }

  // Additional general recommendations if outdated
  if (outdated && recs.length === 0) {
    recs.push({
      issue: "Detected technologies may be outdated or have unknown vulnerabilities",
      severity: 70,
      suggestion: "Review all server and platform software versions for updates and patches",
    });
  }

  return recs;
}

function explanationText(technologies: Technology[], outdated: boolean): string {
  if (technologies.length === 0) {
    return "No identifiable server or platform technologies were detected from the headers.";
  }

  const techStrings: string[] = technologies.map(t => {
    if (t.version) return `${t.name} ${t.version}`;
    return t.name;
  });

  let exp = `The analyzed headers suggest the presence of the following technologies: ${techStrings.join(", ")}.`;

  if (outdated) {
    exp += " One or more of these technologies appear to be outdated, which may pose security risks.";
  } else {
    exp += " Technologies appear reasonably up to date.";
  }
  return exp;
}

export async function fullTechnologyHeadersAudit(rawUrl: string): Promise<TechnologyHeadersResult | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: check.error };

  let headers: Headers;
  try {
    headers = await fetchAndParseHeaders(check.url.toString());
  } catch (err: any) {
    return { error: sanitizeFetchError(err) };
  }

  const techs = identifyTechnologies(headers);
  const outdated = detectOutdatedTechnologies(techs);
  const score = calculateScore(techs, outdated);
  const grade = letterGrade(score);
  const recommendations = generateRecommendations(techs, outdated);
  const explanation = explanationText(techs, outdated);

  return {
    url: check.url.toString(),
    technologies: techs,
    outdated,
    score,
    grade,
    recommendations,
    explanation,
  };
}

export async function previewTechnologyHeaders(rawUrl: string): Promise<PreviewResult | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: check.error };

  let headers: Headers;
  try {
    // Use a HEAD request with 15 seconds timeout for preview (free)
    const res = await safeFetch(check.url.toString(), {
      method: "HEAD",
      signal: AbortSignal.timeout(15_000),
      headers: { "User-Agent": "api-technology-headers/1.0-preview apimesh.xyz" },
    });
    headers = res.headers;
  } catch (err: any) {
    return { error: sanitizeFetchError(err) };
  }

  // Identify fewer technologies: only check 'server' and 'x-powered-by' headers
  const technologies: Technology[] = [];

  const serverHdr = headers.get("server");
  if (serverHdr) {
    for (const [techName, data] of Object.entries(TECH_PATTERNS)) {
      if (data.header !== "server") continue;
      if (data.regex) {
        const match = serverHdr.match(data.regex);
        if (match) {
          technologies.push({ name: techName, version: match[1] ?? null, confidence: 70 });
          break;
        }
      } else {
        if (serverHdr.toLowerCase().includes(techName.toLowerCase())) {
          technologies.push({ name: techName, version: null, confidence: 50 });
          break;
        }
      }
    }
  }

  if (technologies.length === 0) {
    // fallback, try x-powered-by
    const xpbHdr = headers.get("x-powered-by");
    if (xpbHdr) {
      for (const [techName, data] of Object.entries(TECH_PATTERNS)) {
        if (data.header !== "x-powered-by") continue;
        if (data.regex) {
          const match = xpbHdr.match(data.regex);
          if (match) {
            technologies.push({ name: techName, version: match[1] ?? null, confidence: 65 });
            break;
          }
        } else {
          if (xpbHdr.toLowerCase().includes(techName.toLowerCase())) {
            technologies.push({ name: techName, version: null, confidence: 50 });
            break;
          }
        }
      }
    }
  }

  const outdated = detectOutdatedTechnologies(technologies);
  const score = calculateScore(technologies, outdated);
  const grade = letterGrade(score);
  const recommendations = generateRecommendations(technologies, outdated);
  const explanation = explanationText(technologies, outdated);

  return {
    url: check.url.toString(),
    technologies,
    score,
    grade,
    recommendations,
    explanation,
    preview: true,
  };
}
