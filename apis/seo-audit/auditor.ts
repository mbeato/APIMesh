// On-page SEO auditor — fetches HTML and performs comprehensive analysis using cheerio

import * as cheerio from "cheerio";
import { validateExternalUrl, safeFetch, readBodyCapped } from "../../shared/ssrf";

// ─── Types ────────────────────────────────────────────────────────────────────

interface Issue {
  severity: "critical" | "warning" | "info";
  message: string;
}

interface TitleAnalysis {
  text: string | null;
  length: number;
  issues: string[];
}

interface MetaDescriptionAnalysis {
  text: string | null;
  length: number;
  issues: string[];
}

interface HeadingsAnalysis {
  h1_count: number;
  h1_texts: string[];
  h2_count: number;
  h3_count: number;
  h4_count: number;
  h5_count: number;
  h6_count: number;
  hierarchy_issues: string[];
}

interface ImagesAnalysis {
  total: number;
  missing_alt: number;
  images_without_alt: string[];
}

interface LinkResult {
  url: string;
  status: number | null;
  error: string | null;
}

interface LinksAnalysis {
  internal: number;
  external: number;
  nofollow: number;
  broken: LinkResult[];
}

interface ContentAnalysis {
  word_count: number;
  text_to_html_ratio: number;
}

interface CanonicalAnalysis {
  url: string | null;
  self_referencing: boolean;
}

interface OgTags {
  "og:title": string | null;
  "og:description": string | null;
  "og:image": string | null;
  "og:url": string | null;
}

interface JsonLdAnalysis {
  types: string[];
  count: number;
}

interface RobotsAnalysis {
  meta_robots: string | null;
  x_robots_tag: string | null;
}

export interface FullAudit {
  url: string;
  title: TitleAnalysis;
  meta_description: MetaDescriptionAnalysis;
  headings: HeadingsAnalysis;
  images: ImagesAnalysis;
  links: LinksAnalysis;
  content: ContentAnalysis;
  canonical: CanonicalAnalysis;
  og_tags: OgTags;
  json_ld: JsonLdAnalysis;
  robots: RobotsAnalysis;
  lang: string | null;
  score: number;
  issues: Issue[];
  audited_at: string;
}

export interface PreviewAudit {
  url: string;
  title: { text: string | null; length: number };
  meta_description: { text: string | null; length: number };
  h1: string | null;
  score: number;
  preview: true;
  audited_at: string;
  note: string;
}

// ─── Fetch page ───────────────────────────────────────────────────────────────

interface FetchedPage {
  html: string;
  finalUrl: string;
  xRobotsTag: string | null;
}

async function fetchPage(url: string): Promise<FetchedPage> {
  const validation = validateExternalUrl(url);
  if ("error" in validation) {
    throw new Error(validation.error);
  }

  const response = await safeFetch(url, {
    timeoutMs: 20_000,
    headers: { "User-Agent": "seo-audit/1.0 apimesh.xyz" },
  });

  const contentType = response.headers.get("content-type") || "";
  const isHtml =
    contentType.includes("text/html") ||
    contentType.includes("text/xhtml") ||
    contentType.includes("application/xhtml+xml");
  if (!contentType || !isHtml) {
    throw new Error(`URL returned non-HTML content type: ${contentType}`);
  }

  const html = await readBodyCapped(response, 2 * 1024 * 1024);
  if (!html || html.length === 0) {
    throw new Error("URL returned empty response body");
  }

  return {
    html,
    finalUrl: response.url || url,
    xRobotsTag: response.headers.get("x-robots-tag"),
  };
}

// ─── Analysis helpers ─────────────────────────────────────────────────────────

function analyzeTitle($: cheerio.CheerioAPI): TitleAnalysis {
  const titleEl = $("title").first();
  const rawText = titleEl.length ? titleEl.text().trim() : null;
  const text = rawText ? rawText.slice(0, 1000) : null;
  const length = rawText ? rawText.length : 0;
  const issues: string[] = [];

  if (!text) {
    issues.push("missing");
  } else {
    if (length > 60) issues.push("too long (>60 characters)");
    if (length < 30) issues.push("too short (<30 characters)");
  }

  return { text, length, issues };
}

function analyzeMetaDescription($: cheerio.CheerioAPI): MetaDescriptionAnalysis {
  const metaEl = $('meta[name="description"]').first();
  const rawText = metaEl.length ? (metaEl.attr("content") || "").trim() : null;
  const text = rawText ? rawText.slice(0, 1000) : null;
  const length = rawText ? rawText.length : 0;
  const issues: string[] = [];

  if (!text) {
    issues.push("missing");
  } else {
    if (length > 160) issues.push("too long (>160 characters)");
    if (length < 70) issues.push("too short (<70 characters)");
  }

  return { text, length, issues };
}

function analyzeHeadings($: cheerio.CheerioAPI): HeadingsAnalysis {
  const h1Elements = $("h1");
  const h1Texts = h1Elements.map((_, el) => $(el).text().trim()).get().filter(Boolean)
    .slice(0, 10)
    .map((t: string) => t.slice(0, 1000));

  const counts = {
    h1: h1Elements.length,
    h2: $("h2").length,
    h3: $("h3").length,
    h4: $("h4").length,
    h5: $("h5").length,
    h6: $("h6").length,
  };

  const hierarchyIssues: string[] = [];

  if (counts.h1 === 0) {
    hierarchyIssues.push("Missing H1 tag");
  } else if (counts.h1 > 1) {
    hierarchyIssues.push(`Multiple H1 tags found (${counts.h1})`);
  }

  // Check for skipped heading levels
  const levels = [counts.h1, counts.h2, counts.h3, counts.h4, counts.h5, counts.h6];
  for (let i = 1; i < levels.length; i++) {
    if (levels[i] > 0) {
      // Check if any preceding level is missing while this one exists
      let foundGap = false;
      for (let j = 0; j < i; j++) {
        if (levels[j] === 0) {
          foundGap = true;
          break;
        }
      }
      if (foundGap) {
        hierarchyIssues.push(`Skipped heading level (H${i + 1} used without all preceding levels)`);
        break; // Report once
      }
    }
  }

  return {
    h1_count: counts.h1,
    h1_texts: h1Texts,
    h2_count: counts.h2,
    h3_count: counts.h3,
    h4_count: counts.h4,
    h5_count: counts.h5,
    h6_count: counts.h6,
    hierarchy_issues: hierarchyIssues,
  };
}

function analyzeImages($: cheerio.CheerioAPI): ImagesAnalysis {
  const images = $("img");
  const total = images.length;
  const withoutAlt: string[] = [];

  images.each((_, el) => {
    const alt = $(el).attr("alt");
    if (alt === undefined || alt === null) {
      const src = $(el).attr("src") || $(el).attr("data-src") || "(no src)";
      // Reject data: and javascript: URIs; only allow http(s) or relative paths
      if (/^(https?:\/\/|\/)/i.test(src) || src === "(no src)") {
        withoutAlt.push(src.slice(0, 500));
      }
    }
  });

  return {
    total,
    missing_alt: withoutAlt.length,
    images_without_alt: withoutAlt.slice(0, 10),
  };
}

function extractLinks($: cheerio.CheerioAPI, pageUrl: string): {
  internal: string[];
  external: string[];
  nofollow: number;
  allHrefs: string[];
} {
  let parsedPage: URL;
  try {
    parsedPage = new URL(pageUrl);
  } catch {
    return { internal: [], external: [], nofollow: 0, allHrefs: [] };
  }

  const internal: string[] = [];
  const external: string[] = [];
  let nofollow = 0;
  const allHrefs: string[] = [];

  $("a[href]").each((_, el) => {
    const href = $(el).attr("href");
    if (!href) return;

    const rel = ($(el).attr("rel") || "").toLowerCase();
    if (rel.includes("nofollow")) nofollow++;

    let resolved: URL;
    try {
      resolved = new URL(href, pageUrl);
    } catch {
      return; // Skip malformed URLs
    }

    // Skip non-http links (mailto:, tel:, javascript:, etc.)
    if (resolved.protocol !== "http:" && resolved.protocol !== "https:") return;

    const fullUrl = resolved.toString();
    allHrefs.push(fullUrl);

    if (resolved.hostname === parsedPage.hostname) {
      internal.push(fullUrl);
    } else {
      external.push(fullUrl);
    }
  });

  return { internal, external, nofollow, allHrefs };
}

async function checkLinks(urls: string[]): Promise<LinkResult[]> {
  const toCheck = urls.slice(0, 20);
  const LINK_BATCH_SIZE = 5;
  const allResults: (PromiseSettledResult<LinkResult>)[] = [];

  for (let i = 0; i < toCheck.length; i += LINK_BATCH_SIZE) {
    const batch = toCheck.slice(i, i + LINK_BATCH_SIZE);
    const batchResults = await Promise.allSettled(
      batch.map(async (url): Promise<LinkResult> => {
        try {
          const validation = validateExternalUrl(url);
          if ("error" in validation) {
            return { url, status: null, error: validation.error };
          }

          const res = await safeFetch(url, {
            method: "HEAD",
            timeoutMs: 8_000,
            headers: { "User-Agent": "seo-audit/1.0 apimesh.xyz" },
          });

          if (res.status !== 200) {
            return { url, status: res.status, error: null };
          }
          return { url, status: 200, error: null };
        } catch (e: any) {
          return { url, status: null, error: e?.message || "Request failed" };
        }
      })
    );
    allResults.push(...batchResults);
  }

  const broken: LinkResult[] = [];
  for (const result of allResults) {
    if (result.status === "fulfilled") {
      const r = result.value;
      if (r.status !== 200) {
        broken.push(r);
      }
    } else {
      // Promise rejected (shouldn't happen since we catch inside, but be safe)
      broken.push({ url: "unknown", status: null, error: result.reason?.message || "Unknown error" });
    }
  }

  return broken;
}

function analyzeContent($: cheerio.CheerioAPI, rawHtml: string): ContentAnalysis {
  // Remove script and style elements, then extract text
  const clone = $.root().clone();
  clone.find("script, style, noscript").remove();
  const textContent = clone.text().replace(/\s+/g, " ").trim();
  const words = textContent.split(/\s+/).filter(w => w.length > 0);
  const wordCount = words.length;

  const textLength = textContent.length;
  const htmlLength = rawHtml.length;
  const ratio = htmlLength > 0 ? Math.round((textLength / htmlLength) * 10000) / 100 : 0;

  return {
    word_count: wordCount,
    text_to_html_ratio: ratio,
  };
}

function analyzeCanonical($: cheerio.CheerioAPI, pageUrl: string): CanonicalAnalysis {
  const canonicalEl = $('link[rel="canonical"]').first();
  const canonicalUrl = canonicalEl.length ? (canonicalEl.attr("href") || "").trim() : null;

  let selfReferencing = false;
  if (canonicalUrl) {
    try {
      const canonical = new URL(canonicalUrl, pageUrl);
      const page = new URL(pageUrl);
      selfReferencing = canonical.origin + canonical.pathname === page.origin + page.pathname;
    } catch {
      // Malformed canonical
    }
  }

  return {
    url: canonicalUrl || null,
    self_referencing: selfReferencing,
  };
}

function analyzeOgTags($: cheerio.CheerioAPI): OgTags {
  const get = (property: string): string | null => {
    const el = $(`meta[property="${property}"]`).first();
    if (!el.length) return null;
    return (el.attr("content") || "").trim() || null;
  };

  return {
    "og:title": get("og:title"),
    "og:description": get("og:description"),
    "og:image": get("og:image"),
    "og:url": get("og:url"),
  };
}

function analyzeJsonLd($: cheerio.CheerioAPI): JsonLdAnalysis {
  const scripts = $('script[type="application/ld+json"]');
  const types: string[] = [];

  scripts.each((_, el) => {
    const content = $(el).html();
    if (!content) return;

    try {
      const parsed = JSON.parse(content);
      extractTypes(parsed, types);
    } catch {
      // Invalid JSON-LD, skip
    }
  });

  return {
    types: [...new Set(types)],
    count: scripts.length,
  };
}

function extractTypes(obj: any, types: string[], depth: number = 0): void {
  if (!obj || typeof obj !== "object") return;
  if (depth > 10) return;
  if (types.length >= 50) return;

  if (Array.isArray(obj)) {
    for (const item of obj.slice(0, 100)) {
      if (types.length >= 50) return;
      extractTypes(item, types, depth + 1);
    }
    return;
  }

  if (obj["@type"]) {
    const t = obj["@type"];
    if (Array.isArray(t)) {
      types.push(...t.filter((v: unknown) => typeof v === "string").slice(0, 50 - types.length));
    } else if (typeof t === "string") {
      types.push(t);
    }
  }

  // Check @graph
  if (obj["@graph"] && Array.isArray(obj["@graph"])) {
    for (const item of obj["@graph"].slice(0, 100)) {
      if (types.length >= 50) return;
      extractTypes(item, types, depth + 1);
    }
  }
}

function analyzeRobots($: cheerio.CheerioAPI, xRobotsTag: string | null): RobotsAnalysis {
  const metaRobots = $('meta[name="robots"]').first();
  const metaContent = metaRobots.length ? (metaRobots.attr("content") || "").trim() : null;

  return {
    meta_robots: metaContent || null,
    x_robots_tag: xRobotsTag || null,
  };
}

function analyzeLang($: cheerio.CheerioAPI): string | null {
  const lang = $("html").attr("lang");
  return lang ? lang.trim() : null;
}

// ─── Scoring ──────────────────────────────────────────────────────────────────

function calculateScore(
  title: TitleAnalysis,
  metaDesc: MetaDescriptionAnalysis,
  headings: HeadingsAnalysis,
  images: ImagesAnalysis,
  content: ContentAnalysis,
  canonical: CanonicalAnalysis,
  ogTags: OgTags,
  jsonLd: JsonLdAnalysis,
  robots: RobotsAnalysis,
  lang: string | null,
): { score: number; issues: Issue[] } {
  let score = 0;
  const issues: Issue[] = [];

  // Title present and good length: +10
  if (title.text) {
    if (title.issues.length === 0) {
      score += 10;
    } else {
      score += 5; // Partial credit: present but wrong length
      for (const issue of title.issues) {
        issues.push({ severity: "warning", message: `Title ${issue}` });
      }
    }
  } else {
    issues.push({ severity: "critical", message: "Missing title tag" });
  }

  // Meta description present and good length: +10
  if (metaDesc.text) {
    if (metaDesc.issues.length === 0) {
      score += 10;
    } else {
      score += 5;
      for (const issue of metaDesc.issues) {
        issues.push({ severity: "warning", message: `Meta description ${issue}` });
      }
    }
  } else {
    issues.push({ severity: "critical", message: "Missing meta description" });
  }

  // Single H1: +10
  if (headings.h1_count === 1) {
    score += 10;
  } else if (headings.h1_count === 0) {
    issues.push({ severity: "critical", message: "Missing H1 tag" });
  } else {
    score += 3;
    issues.push({ severity: "warning", message: `Multiple H1 tags (${headings.h1_count})` });
  }

  // Heading hierarchy correct: +5
  if (headings.hierarchy_issues.length === 0) {
    score += 5;
  } else {
    for (const issue of headings.hierarchy_issues) {
      issues.push({ severity: "warning", message: issue });
    }
  }

  // All images have alt text: +10
  if (images.total === 0) {
    score += 10; // No images = no issue
    issues.push({ severity: "info", message: "No images found on page" });
  } else if (images.missing_alt === 0) {
    score += 10;
  } else {
    const ratio = (images.total - images.missing_alt) / images.total;
    score += Math.round(ratio * 10);
    issues.push({
      severity: "warning",
      message: `${images.missing_alt} of ${images.total} images missing alt text`,
    });
  }

  // Good text-to-html ratio (>10%): +5
  if (content.text_to_html_ratio > 10) {
    score += 5;
  } else {
    issues.push({
      severity: "warning",
      message: `Low text-to-HTML ratio (${content.text_to_html_ratio}%)`,
    });
  }

  // Canonical present and self-referencing: +10
  if (canonical.url && canonical.self_referencing) {
    score += 10;
  } else if (canonical.url) {
    score += 5;
    issues.push({ severity: "info", message: "Canonical URL present but not self-referencing" });
  } else {
    issues.push({ severity: "warning", message: "Missing canonical tag" });
  }

  // OG tags complete (all 4): +10
  const ogValues = Object.values(ogTags);
  const ogPresent = ogValues.filter(v => v !== null).length;
  if (ogPresent === 4) {
    score += 10;
  } else if (ogPresent > 0) {
    score += Math.round((ogPresent / 4) * 10);
    const missing = Object.entries(ogTags)
      .filter(([, v]) => v === null)
      .map(([k]) => k);
    issues.push({ severity: "warning", message: `Missing Open Graph tags: ${missing.join(", ")}` });
  } else {
    issues.push({ severity: "warning", message: "No Open Graph tags found" });
  }

  // JSON-LD present: +5
  if (jsonLd.count > 0) {
    score += 5;
  } else {
    issues.push({ severity: "info", message: "No JSON-LD structured data found" });
  }

  // Meta robots allows indexing: +10
  const robotsCombined = [robots.meta_robots, robots.x_robots_tag]
    .filter(Boolean)
    .join(", ")
    .toLowerCase();
  if (robotsCombined.includes("noindex")) {
    issues.push({ severity: "critical", message: "Page is set to noindex" });
  } else {
    score += 10;
  }

  // Lang attribute present: +5
  if (lang) {
    score += 5;
  } else {
    issues.push({ severity: "warning", message: "Missing lang attribute on <html> tag" });
  }

  // Word count > 300: +10
  if (content.word_count > 300) {
    score += 10;
  } else {
    issues.push({
      severity: content.word_count < 100 ? "critical" : "warning",
      message: `Low word count (${content.word_count} words)`,
    });
  }

  // Cap score at 100
  score = Math.min(100, Math.max(0, score));

  return { score, issues };
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function auditFull(url: string): Promise<FullAudit> {
  const page = await fetchPage(url);
  const $ = cheerio.load(page.html);

  const title = analyzeTitle($);
  const metaDesc = analyzeMetaDescription($);
  const headings = analyzeHeadings($);
  const images = analyzeImages($);
  const content = analyzeContent($, page.html);
  const canonical = analyzeCanonical($, page.finalUrl);
  const ogTags = analyzeOgTags($);
  const jsonLd = analyzeJsonLd($);
  const robots = analyzeRobots($, page.xRobotsTag);
  const lang = analyzeLang($);

  // Link analysis (with parallel checking)
  const linkData = extractLinks($, page.finalUrl);
  let broken: LinkResult[] = [];
  try {
    broken = await checkLinks(linkData.allHrefs);
  } catch {
    // Link checking failure should not crash the audit
  }

  const links: LinksAnalysis = {
    internal: linkData.internal.length,
    external: linkData.external.length,
    nofollow: linkData.nofollow,
    broken,
  };

  const { score, issues } = calculateScore(
    title, metaDesc, headings, images, content, canonical, ogTags, jsonLd, robots, lang,
  );

  return {
    url,
    title,
    meta_description: metaDesc,
    headings,
    images,
    links,
    content,
    canonical,
    og_tags: ogTags,
    json_ld: jsonLd,
    robots,
    lang,
    score,
    issues,
    audited_at: new Date().toISOString(),
  };
}

export async function auditPreview(url: string): Promise<PreviewAudit> {
  const page = await fetchPage(url);
  const $ = cheerio.load(page.html);

  const title = analyzeTitle($);
  const metaDesc = analyzeMetaDescription($);
  const headings = analyzeHeadings($);
  const images = analyzeImages($);
  const content = analyzeContent($, page.html);
  const canonical = analyzeCanonical($, page.finalUrl);
  const ogTags = analyzeOgTags($);
  const jsonLd = analyzeJsonLd($);
  const robots = analyzeRobots($, page.xRobotsTag);
  const lang = analyzeLang($);

  const { score } = calculateScore(
    title, metaDesc, headings, images, content, canonical, ogTags, jsonLd, robots, lang,
  );

  const h1 = headings.h1_texts.length > 0 ? headings.h1_texts[0] : null;

  return {
    url,
    title: { text: title.text, length: title.length },
    meta_description: { text: metaDesc.text, length: metaDesc.length },
    h1,
    score,
    preview: true,
    audited_at: new Date().toISOString(),
    note: "Preview shows title, meta description, H1, and score only. Pay via x402 for full SEO audit with headings, images, links, structured data, and detailed issues.",
  };
}
