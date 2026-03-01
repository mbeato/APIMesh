// brand-assets/extractor.ts

import * as cheerio from "cheerio";
import { safeFetch, readBodyCapped } from "../../shared/ssrf";

const FETCH_OPTS = {
  timeoutMs: 8000,
  headers: { "User-Agent": "brand-assets/1.0 apimesh.xyz" },
};

const MAX_CSS_BYTES = 50 * 1024; // 50KB
const MAX_HTML_BYTES = 256 * 1024; // 256KB

function sanitizeReturnedUrl(url: string | null): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return url.slice(0, 2048);
  } catch {
    return null;
  }
}

export interface BrandAssets {
  domain: string;
  logo: string | null;
  favicon: { url: string; format: string } | null;
  colors: {
    primary: string | null;
    secondary: string | null;
  };
  theme_color: string | null;
  og_image: string | null;
  site_name: string | null;
  extractedAt: string;
}

export interface PreviewAssets {
  domain: string;
  favicon: string;
  theme_color: string | null;
  extractedAt: string;
}

// --- Domain validation ---

const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export function validateDomain(raw: string): { domain: string } | { error: string } {
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed) return { error: "Missing domain parameter" };
  if (trimmed.includes(" ")) return { error: "Domain must not contain spaces" };
  if (trimmed.includes("://")) return { error: "Provide bare domain only (no protocol)" };
  if (trimmed.includes("/")) return { error: "Provide bare domain only (no paths)" };
  if (!trimmed.includes(".")) return { error: "Domain must contain a dot" };
  if (!DOMAIN_RE.test(trimmed)) return { error: "Invalid domain format" };
  return { domain: trimmed };
}

// --- Google Favicon API (always works) ---

function googleFaviconUrl(domain: string, size: number = 64): string {
  return `https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=${size}`;
}

// --- Preview: lightweight, no HTML fetching ---

export function previewExtract(domain: string): PreviewAssets {
  return {
    domain,
    favicon: googleFaviconUrl(domain),
    theme_color: null,
    extractedAt: new Date().toISOString(),
  };
}

// --- Full extraction ---

export async function fullExtract(domain: string): Promise<BrandAssets> {
  const result: BrandAssets = {
    domain,
    logo: null,
    favicon: null,
    colors: { primary: null, secondary: null },
    theme_color: null,
    og_image: null,
    site_name: null,
    extractedAt: new Date().toISOString(),
  };

  const baseUrl = `https://${domain}`;
  let html: string | null = null;
  let $: cheerio.CheerioAPI | null = null;

  // Step 1: Fetch the page HTML
  try {
    const res = await safeFetch(baseUrl, FETCH_OPTS);
    if (res.ok) {
      html = await readBodyCapped(res, MAX_HTML_BYTES);
      $ = cheerio.load(html);
    }
  } catch {
    // Domain may not resolve — continue with fallbacks
  }

  // Step 2: Extract assets from HTML if available
  if ($) {
    extractLogo($, baseUrl, result);
    extractFavicon($, baseUrl, result);
    extractMeta($, result);
  }

  // Step 3: Fallback logo — if no logo found from HTML, use Google favicon
  if (!result.logo) {
    result.logo = googleFaviconUrl(domain, 128);
  }

  // Step 4: Fallback favicon — always provide Google's
  if (!result.favicon) {
    result.favicon = {
      url: googleFaviconUrl(domain),
      format: "png",
    };
  }

  // Step 5: Try to extract colors from first CSS stylesheet
  if ($) {
    await extractColorsFromCss($, baseUrl, result);
  }

  // Update timestamp
  result.extractedAt = new Date().toISOString();
  return result;
}

// --- Logo extraction (priority: SVG icon > apple-touch-icon > Google favicon > /favicon.ico) ---

function extractLogo($: cheerio.CheerioAPI, baseUrl: string, result: BrandAssets): void {
  // Priority 1: SVG icon links
  const svgIcon = $('link[rel="icon"][type="image/svg+xml"]').attr("href");
  if (svgIcon) {
    const resolved = sanitizeReturnedUrl(resolveUrl(svgIcon, baseUrl));
    if (resolved) { result.logo = resolved; return; }
  }

  // Also check for any SVG icon without explicit type
  const iconWithSvg = $('link[rel="icon"]').filter((_, el) => {
    const href = $(el).attr("href") || "";
    return href.endsWith(".svg");
  }).first().attr("href");
  if (iconWithSvg) {
    const resolved = sanitizeReturnedUrl(resolveUrl(iconWithSvg, baseUrl));
    if (resolved) { result.logo = resolved; return; }
  }

  // Priority 2: apple-touch-icon (usually a high-res PNG)
  const appleIcon = $('link[rel="apple-touch-icon"]').attr("href")
    || $('link[rel="apple-touch-icon-precomposed"]').attr("href");
  if (appleIcon) {
    const resolved = sanitizeReturnedUrl(resolveUrl(appleIcon, baseUrl));
    if (resolved) { result.logo = resolved; return; }
  }

  // Priority 3: Google favicon API (set in fallback in fullExtract)
  // Priority 4: /favicon.ico — will be handled by favicon extraction
}

// --- Favicon extraction ---

function extractFavicon($: cheerio.CheerioAPI, baseUrl: string, result: BrandAssets): void {
  // Check all icon link tags
  const iconLinks = $('link[rel="icon"], link[rel="shortcut icon"]');

  if (iconLinks.length > 0) {
    // Prefer SVG > PNG > ICO
    let bestHref: string | null = null;
    let bestFormat = "ico";

    iconLinks.each((_, el) => {
      const href = $(el).attr("href");
      if (!href) return;

      const type = $(el).attr("type") || "";
      const ext = href.split("?")[0].split(".").pop()?.toLowerCase() || "";

      if (type === "image/svg+xml" || ext === "svg") {
        if (!bestHref || bestFormat !== "svg") {
          bestHref = href;
          bestFormat = "svg";
        }
      } else if (type === "image/png" || ext === "png") {
        if (!bestHref || (bestFormat !== "svg")) {
          bestHref = href;
          bestFormat = "png";
        }
      } else {
        if (!bestHref) {
          bestHref = href;
          bestFormat = ext === "ico" ? "ico" : ext || "ico";
        }
      }
    });

    if (bestHref) {
      const resolved = sanitizeReturnedUrl(resolveUrl(bestHref, baseUrl));
      if (resolved) {
        result.favicon = {
          url: resolved,
          format: bestFormat,
        };
        return;
      }
    }
  }

  // Fallback: /favicon.ico
  result.favicon = {
    url: `${baseUrl}/favicon.ico`,
    format: "ico",
  };
}

// --- Meta tag extraction ---

function extractMeta($: cheerio.CheerioAPI, result: BrandAssets): void {
  // theme-color — cap length and validate looks like a color
  const rawThemeColor = $('meta[name="theme-color"]').attr("content") || null;
  if (rawThemeColor) {
    const trimmed = rawThemeColor.trim().slice(0, 50);
    // Only accept values that look like hex colors (#xxx, #xxxxxx, #xxxxxxxx)
    result.theme_color = isHexColor(trimmed) ? trimmed : null;
  }

  // og:image — sanitize URL
  const rawOgImage =
    $('meta[property="og:image"]').attr("content")
    || $('meta[name="og:image"]').attr("content")
    || null;
  result.og_image = sanitizeReturnedUrl(rawOgImage);

  // site_name: og:site_name > title — cap length
  const rawSiteName =
    $('meta[property="og:site_name"]').attr("content")
    || $('meta[name="og:site_name"]').attr("content")
    || $("title").first().text().trim()
    || null;
  result.site_name = rawSiteName ? rawSiteName.slice(0, 200) : null;

  // If theme_color looks like a hex color, also use as primary color hint
  if (result.theme_color && isHexColor(result.theme_color.trim())) {
    if (!result.colors.primary) {
      result.colors.primary = normalizeHex(result.theme_color.trim());
    }
  }
}

// --- CSS color extraction ---

const CSS_COLOR_PATTERNS = [
  /--primary[-_]?color\s*:\s*([^;]+);/i,
  /--brand[-_]?color\s*:\s*([^;]+);/i,
  /--color[-_]?primary\s*:\s*([^;]+);/i,
  /--main[-_]?color\s*:\s*([^;]+);/i,
  /--accent[-_]?color\s*:\s*([^;]+);/i,
];

const CSS_SECONDARY_PATTERNS = [
  /--secondary[-_]?color\s*:\s*([^;]+);/i,
  /--color[-_]?secondary\s*:\s*([^;]+);/i,
];

async function extractColorsFromCss(
  $: cheerio.CheerioAPI,
  baseUrl: string,
  result: BrandAssets
): Promise<void> {
  // Find first external stylesheet
  const stylesheetHref = $('link[rel="stylesheet"]').first().attr("href");
  if (!stylesheetHref) return;

  const cssUrl = resolveUrl(stylesheetHref, baseUrl);
  if (!cssUrl) return;

  // Restrict CSS fetch to same-origin only
  try {
    const parsedCssUrl = new URL(cssUrl);
    const parsedBase = new URL(baseUrl);
    if (parsedCssUrl.hostname !== parsedBase.hostname) return;
  } catch {
    return;
  }

  try {
    const res = await safeFetch(cssUrl, {
      ...FETCH_OPTS,
      timeoutMs: 5000,
    });
    if (!res.ok) return;

    // Verify Content-Type is CSS or plain text
    const contentType = res.headers.get("content-type") || "";
    if (!contentType.includes("text/css") && !contentType.includes("text/plain")) return;

    const css = await readBodyCapped(res, MAX_CSS_BYTES);

    // Extract primary color
    if (!result.colors.primary) {
      for (const pattern of CSS_COLOR_PATTERNS) {
        const match = css.match(pattern);
        if (match) {
          const value = match[1].trim();
          if (isHexColor(value)) {
            result.colors.primary = normalizeHex(value);
            break;
          }
        }
      }
    }

    // Extract secondary color
    if (!result.colors.secondary) {
      for (const pattern of CSS_SECONDARY_PATTERNS) {
        const match = css.match(pattern);
        if (match) {
          const value = match[1].trim();
          if (isHexColor(value)) {
            result.colors.secondary = normalizeHex(value);
            break;
          }
        }
      }
    }
  } catch {
    // CSS fetch failed — not critical
  }
}

// --- Utility functions ---

function resolveUrl(href: string, baseUrl: string): string {
  if (/^(javascript|data|vbscript|blob):/i.test(href.trim())) return "";
  if (/^https?:\/\//i.test(href)) return href;
  if (href.startsWith("//")) return "https:" + href;
  if (href.startsWith("/")) return baseUrl + href;
  return baseUrl + "/" + href;
}

function isHexColor(value: string): boolean {
  return /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(value);
}

function normalizeHex(value: string): string {
  const hex = value.toLowerCase();
  // Expand shorthand #abc -> #aabbcc
  if (hex.length === 4) {
    return `#${hex[1]}${hex[1]}${hex[2]}${hex[2]}${hex[3]}${hex[3]}`;
  }
  return hex;
}
