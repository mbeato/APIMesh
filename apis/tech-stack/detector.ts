import { validateExternalUrl, safeFetch, readBodyCapped } from "../../shared/ssrf";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TechDetection {
  name: string;
  category: string;
  confidence: "high" | "medium" | "low";
  evidence: string;
}

export interface TechStackResult {
  url: string;
  technologies: TechDetection[];
  summary: {
    cms: string[];
    frameworks: string[];
    languages: string[];
    servers: string[];
    analytics: string[];
    cdn: string[];
    hosting: string[];
    javascript: string[];
    css: string[];
    security: string[];
    other: string[];
  };
  headers: Record<string, string>;
  checkedAt: string;
}

export interface TechStackPreview {
  url: string;
  technologies: TechDetection[];
  summary: { [key: string]: string[] };
  checkedAt: string;
}

// ---------------------------------------------------------------------------
// Header-Based Detection
// ---------------------------------------------------------------------------

interface HeaderRule {
  header: string;
  pattern?: RegExp;
  name: string;
  category: string;
}

const HEADER_RULES: HeaderRule[] = [
  // Servers
  { header: "server", pattern: /nginx/i, name: "Nginx", category: "servers" },
  { header: "server", pattern: /apache/i, name: "Apache", category: "servers" },
  { header: "server", pattern: /cloudflare/i, name: "Cloudflare", category: "cdn" },
  { header: "server", pattern: /microsoft-iis/i, name: "IIS", category: "servers" },
  { header: "server", pattern: /litespeed/i, name: "LiteSpeed", category: "servers" },
  { header: "server", pattern: /caddy/i, name: "Caddy", category: "servers" },
  { header: "server", pattern: /envoy/i, name: "Envoy", category: "servers" },
  { header: "server", pattern: /gunicorn/i, name: "Gunicorn", category: "servers" },

  // Frameworks via X-Powered-By
  { header: "x-powered-by", pattern: /express/i, name: "Express.js", category: "frameworks" },
  { header: "x-powered-by", pattern: /next\.js/i, name: "Next.js", category: "frameworks" },
  { header: "x-powered-by", pattern: /nuxt/i, name: "Nuxt.js", category: "frameworks" },
  { header: "x-powered-by", pattern: /php/i, name: "PHP", category: "languages" },
  { header: "x-powered-by", pattern: /asp\.net/i, name: "ASP.NET", category: "frameworks" },
  { header: "x-powered-by", pattern: /flask/i, name: "Flask", category: "frameworks" },
  { header: "x-powered-by", pattern: /django/i, name: "Django", category: "frameworks" },
  { header: "x-powered-by", pattern: /rails/i, name: "Ruby on Rails", category: "frameworks" },
  { header: "x-powered-by", pattern: /hono/i, name: "Hono", category: "frameworks" },

  // CDN / Hosting
  { header: "cf-ray", name: "Cloudflare", category: "cdn" },
  { header: "x-vercel-id", name: "Vercel", category: "hosting" },
  { header: "x-amz-cf-id", name: "Amazon CloudFront", category: "cdn" },
  { header: "x-served-by", pattern: /cache/i, name: "Fastly", category: "cdn" },
  { header: "x-netlify-request-id", name: "Netlify", category: "hosting" },
  { header: "fly-request-id", name: "Fly.io", category: "hosting" },
  { header: "x-render-origin-server", name: "Render", category: "hosting" },
  { header: "x-heroku-request-id", name: "Heroku", category: "hosting" },

  // Security
  { header: "strict-transport-security", name: "HSTS", category: "security" },
  { header: "content-security-policy", name: "CSP", category: "security" },
  { header: "x-frame-options", name: "X-Frame-Options", category: "security" },

  // CMS
  { header: "x-drupal-cache", name: "Drupal", category: "cms" },
  { header: "x-generator", pattern: /drupal/i, name: "Drupal", category: "cms" },
  { header: "x-generator", pattern: /wordpress/i, name: "WordPress", category: "cms" },
];

function detectFromHeaders(headers: Headers): TechDetection[] {
  const detections: TechDetection[] = [];
  const seen = new Set<string>();

  for (const rule of HEADER_RULES) {
    const value = headers.get(rule.header);
    if (!value) continue;

    if (rule.pattern) {
      if (rule.pattern.test(value) && !seen.has(rule.name)) {
        seen.add(rule.name);
        detections.push({
          name: rule.name,
          category: rule.category,
          confidence: "high",
          evidence: `${rule.header}: ${value.slice(0, 100)}`,
        });
      }
    } else if (!seen.has(rule.name)) {
      seen.add(rule.name);
      detections.push({
        name: rule.name,
        category: rule.category,
        confidence: "high",
        evidence: `${rule.header} header present`,
      });
    }
  }

  return detections;
}

// ---------------------------------------------------------------------------
// HTML-Based Detection
// ---------------------------------------------------------------------------

interface HtmlRule {
  pattern: RegExp;
  name: string;
  category: string;
  confidence: "high" | "medium" | "low";
}

const HTML_RULES: HtmlRule[] = [
  // CMS
  { pattern: /wp-content|wp-includes/i, name: "WordPress", category: "cms", confidence: "high" },
  { pattern: /<meta[^>]+name=["']generator["'][^>]+content=["']WordPress/i, name: "WordPress", category: "cms", confidence: "high" },
  { pattern: /sites\/default\/files|drupal\.js/i, name: "Drupal", category: "cms", confidence: "high" },
  { pattern: /<meta[^>]+name=["']generator["'][^>]+content=["']Joomla/i, name: "Joomla", category: "cms", confidence: "high" },
  { pattern: /\/media\/jui\/js\//i, name: "Joomla", category: "cms", confidence: "medium" },
  { pattern: /content=["']Shopify/i, name: "Shopify", category: "cms", confidence: "high" },
  { pattern: /cdn\.shopify\.com/i, name: "Shopify", category: "cms", confidence: "high" },
  { pattern: /squarespace\.com/i, name: "Squarespace", category: "cms", confidence: "high" },
  { pattern: /content=["']Wix\.com/i, name: "Wix", category: "cms", confidence: "high" },
  { pattern: /wixstatic\.com/i, name: "Wix", category: "cms", confidence: "high" },
  { pattern: /ghost\.org|ghost-url/i, name: "Ghost", category: "cms", confidence: "medium" },
  { pattern: /content=["']Hugo/i, name: "Hugo", category: "cms", confidence: "high" },
  { pattern: /webflow\.com/i, name: "Webflow", category: "cms", confidence: "high" },

  // JS Frameworks
  { pattern: /__next|_next\/static/i, name: "Next.js", category: "frameworks", confidence: "high" },
  { pattern: /__nuxt|_nuxt\//i, name: "Nuxt.js", category: "frameworks", confidence: "high" },
  { pattern: /ng-version=|ng-app/i, name: "Angular", category: "frameworks", confidence: "high" },
  { pattern: /data-reactroot|__NEXT_DATA__|react-dom/i, name: "React", category: "javascript", confidence: "high" },
  { pattern: /vue\.js|v-cloak|data-v-[a-f0-9]/i, name: "Vue.js", category: "javascript", confidence: "high" },
  { pattern: /svelte|__svelte/i, name: "Svelte", category: "javascript", confidence: "high" },
  { pattern: /ember\.js|data-ember/i, name: "Ember.js", category: "javascript", confidence: "high" },
  { pattern: /astro-island|data-astro/i, name: "Astro", category: "frameworks", confidence: "high" },
  { pattern: /gatsby-image|___gatsby/i, name: "Gatsby", category: "frameworks", confidence: "high" },
  { pattern: /remix-run|__remix/i, name: "Remix", category: "frameworks", confidence: "medium" },

  // JS Libraries
  { pattern: /jquery[.-][\d]/i, name: "jQuery", category: "javascript", confidence: "high" },
  { pattern: /bootstrap[.-][\d]|bootstrap\.min/i, name: "Bootstrap", category: "css", confidence: "high" },
  { pattern: /tailwindcss|tailwind\.min/i, name: "Tailwind CSS", category: "css", confidence: "high" },
  { pattern: /alpine\.?js|x-data=/i, name: "Alpine.js", category: "javascript", confidence: "medium" },
  { pattern: /htmx\.org|hx-get|hx-post/i, name: "htmx", category: "javascript", confidence: "high" },
  { pattern: /unpkg\.com|cdnjs\.cloudflare\.com|jsdelivr\.net/i, name: "CDN-hosted Libraries", category: "other", confidence: "low" },

  // Analytics
  { pattern: /google-analytics\.com|gtag|googletagmanager/i, name: "Google Analytics", category: "analytics", confidence: "high" },
  { pattern: /analytics\.js|ga\.js/i, name: "Google Analytics", category: "analytics", confidence: "medium" },
  { pattern: /plausible\.io/i, name: "Plausible", category: "analytics", confidence: "high" },
  { pattern: /fathom\.js|usefathom\.com/i, name: "Fathom", category: "analytics", confidence: "high" },
  { pattern: /segment\.com|analytics\.min\.js/i, name: "Segment", category: "analytics", confidence: "medium" },
  { pattern: /hotjar\.com/i, name: "Hotjar", category: "analytics", confidence: "high" },
  { pattern: /clarity\.ms/i, name: "Microsoft Clarity", category: "analytics", confidence: "high" },
  { pattern: /mixpanel\.com/i, name: "Mixpanel", category: "analytics", confidence: "high" },
  { pattern: /facebook\.net\/en_US\/fbevents/i, name: "Facebook Pixel", category: "analytics", confidence: "high" },
  { pattern: /matomo\.js|piwik\.js/i, name: "Matomo", category: "analytics", confidence: "high" },

  // Hosting / Platform clues in HTML
  { pattern: /netlify/i, name: "Netlify", category: "hosting", confidence: "low" },
  { pattern: /vercel/i, name: "Vercel", category: "hosting", confidence: "low" },
  { pattern: /herokuapp\.com/i, name: "Heroku", category: "hosting", confidence: "medium" },
  { pattern: /firebaseapp\.com|firebasestorage/i, name: "Firebase", category: "hosting", confidence: "high" },
  { pattern: /amazonaws\.com\/|s3\.amazonaws/i, name: "AWS S3", category: "hosting", confidence: "medium" },

  // Fonts
  { pattern: /fonts\.googleapis\.com/i, name: "Google Fonts", category: "other", confidence: "high" },
  { pattern: /use\.typekit\.net/i, name: "Adobe Fonts", category: "other", confidence: "high" },
];

function detectFromHtml(html: string): TechDetection[] {
  const detections: TechDetection[] = [];
  const seen = new Set<string>();

  for (const rule of HTML_RULES) {
    if (rule.pattern.test(html) && !seen.has(rule.name)) {
      seen.add(rule.name);
      const match = html.match(rule.pattern);
      detections.push({
        name: rule.name,
        category: rule.category,
        confidence: rule.confidence,
        evidence: `HTML pattern: ${match?.[0]?.slice(0, 80) ?? rule.pattern.source.slice(0, 60)}`,
      });
    }
  }

  return detections;
}

// ---------------------------------------------------------------------------
// Summarize
// ---------------------------------------------------------------------------

function summarize(detections: TechDetection[]): TechStackResult["summary"] {
  const summary: TechStackResult["summary"] = {
    cms: [], frameworks: [], languages: [], servers: [],
    analytics: [], cdn: [], hosting: [], javascript: [],
    css: [], security: [], other: [],
  };

  const seen = new Set<string>();
  for (const d of detections) {
    if (seen.has(d.name)) continue;
    seen.add(d.name);
    const cat = d.category as keyof typeof summary;
    if (summary[cat]) {
      summary[cat].push(d.name);
    } else {
      summary.other.push(d.name);
    }
  }

  return summary;
}

// ---------------------------------------------------------------------------
// Deduplicate
// ---------------------------------------------------------------------------

function dedup(detections: TechDetection[]): TechDetection[] {
  const seen = new Map<string, TechDetection>();
  for (const d of detections) {
    const existing = seen.get(d.name);
    if (!existing || confidenceRank(d.confidence) > confidenceRank(existing.confidence)) {
      seen.set(d.name, d);
    }
  }
  return [...seen.values()];
}

function confidenceRank(c: "high" | "medium" | "low"): number {
  return c === "high" ? 3 : c === "medium" ? 2 : 1;
}

// ---------------------------------------------------------------------------
// Collect Safe Headers
// ---------------------------------------------------------------------------

function collectHeaders(headers: Headers): Record<string, string> {
  const safe: Record<string, string> = {};
  const interesting = [
    "server", "x-powered-by", "x-generator", "x-frame-options",
    "strict-transport-security", "content-security-policy",
    "content-type", "x-content-type-options", "x-xss-protection",
    "cf-ray", "x-vercel-id", "x-amz-cf-id", "x-netlify-request-id",
    "fly-request-id", "x-drupal-cache", "x-render-origin-server",
  ];
  for (const name of interesting) {
    const val = headers.get(name);
    if (val) safe[name] = val.slice(0, 200);
  }
  return safe;
}

// ---------------------------------------------------------------------------
// Full Detection (Paid)
// ---------------------------------------------------------------------------

const MAX_BODY = 512_000; // 512 KB

export async function detectFull(url: string): Promise<TechStackResult> {
  const res = await safeFetch(url, { timeoutMs: 10_000 });

  if (!res.ok) {
    throw new Error(`URL returned HTTP ${res.status}`);
  }

  const contentType = res.headers.get("content-type") ?? "";
  if (!contentType.includes("text/html") && !contentType.includes("application/xhtml")) {
    throw new Error("URL returned non-HTML content");
  }

  const html = await readBodyCapped(res, MAX_BODY);
  if (!html.trim()) {
    throw new Error("URL returned empty body");
  }

  const headerDetections = detectFromHeaders(res.headers);
  const htmlDetections = detectFromHtml(html);
  const all = dedup([...headerDetections, ...htmlDetections]);

  return {
    url,
    technologies: all,
    summary: summarize(all),
    headers: collectHeaders(res.headers),
    checkedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Preview Detection (Free — headers only, no body fetch)
// ---------------------------------------------------------------------------

export async function detectPreview(url: string): Promise<TechStackPreview> {
  // HEAD request for headers only
  const res = await safeFetch(url, { timeoutMs: 8_000, method: "HEAD" });

  const headerDetections = detectFromHeaders(res.headers);
  const all = dedup(headerDetections);

  const summary: Record<string, string[]> = {};
  for (const d of all) {
    if (!summary[d.category]) summary[d.category] = [];
    if (!summary[d.category].includes(d.name)) summary[d.category].push(d.name);
  }

  return {
    url,
    technologies: all,
    summary,
    checkedAt: new Date().toISOString(),
  };
}
