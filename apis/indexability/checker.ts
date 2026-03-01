import { validateExternalUrl, safeFetch, readBodyCapped } from "../../shared/ssrf";

// ── Types ───────────────────────────────────────────────────────────────────

export interface RobotsTxtCheck {
  allowed: boolean;
  reason: string;
  robotsTxtStatus: number | null;
  matchedRule: string | null;
  matchedAgent: string | null;
}

export interface HttpStatusCheck {
  status: number;
  statusText: string;
  indexable: boolean;
  redirect: boolean;
  redirectLocation: string | null;
}

export interface MetaRobotsCheck {
  found: boolean;
  content: string | null;
  noindex: boolean;
  nofollow: boolean;
}

export interface XRobotsTagCheck {
  found: boolean;
  value: string | null;
  noindex: boolean;
  nofollow: boolean;
}

export interface CanonicalCheck {
  found: boolean;
  href: string | null;
  isSelf: boolean;
  pointsElsewhere: boolean;
}

export interface IndexabilityResult {
  indexable: boolean;
  blocking_reason: string | null;
  checks: {
    robots_txt: RobotsTxtCheck;
    http_status: HttpStatusCheck;
    meta_robots: MetaRobotsCheck;
    x_robots_tag: XRobotsTagCheck;
    canonical: CanonicalCheck;
  };
  url: string;
  checkedAt: string;
}

export interface PreviewResult {
  preview: true;
  indexable: boolean;
  blocking_reason: string | null;
  checks: {
    http_status: HttpStatusCheck;
    meta_robots: MetaRobotsCheck;
  };
  url: string;
  checkedAt: string;
  note: string;
}

// ── Regex patterns ──────────────────────────────────────────────────────────

const META_ROBOTS_RE = /<meta\s+name=["'](?:robots|googlebot)["']\s+content=["']([^"']+)["']/gi;
const META_ROBOTS_REV_RE = /<meta\s+content=["']([^"']+)["']\s+name=["'](?:robots|googlebot)["']/gi;
const CANONICAL_RE = /<link\s+rel=["']canonical["']\s+href=["']([^"']+)["']/i;
const CANONICAL_REV_RE = /<link\s+href=["']([^"']+)["']\s+rel=["']canonical["']/i;

// ── Security constants ─────────────────────────────────────────────────────

const ROBOTS_MAX_LINES = 10_000;
const ROBOTS_MAX_AGENT_BLOCKS = 500;
const ROBOTS_MAX_RULES_PER_BLOCK = 1_000;
const ROBOTS_MAX_RULE_PATH_CHARS = 2048;

// ── Security helpers ───────────────────────────────────────────────────────

function sanitizeReflectedUrl(raw: string | null, base?: string): string | null {
  if (!raw) return null;
  try {
    const u = base ? new URL(raw, base) : new URL(raw);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.toString().slice(0, 2048);
  } catch {
    return null;
  }
}

function sanitizeFetchError(err: unknown): string {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  if (msg.includes("timeout")) return "Request timed out";
  if (msg.includes("dns") || msg.includes("notfound")) return "DNS lookup failed";
  if (msg.includes("refused")) return "Connection refused";
  if (msg.includes("redirect")) return "Too many redirects";
  if (msg.includes("private") || msg.includes("internal")) return "URL not allowed";
  if (msg.includes("too large")) return "Response too large";
  return "Network error";
}

// ── robots.txt parsing ──────────────────────────────────────────────────────

interface RobotRule {
  type: "allow" | "disallow";
  path: string;
}

interface AgentBlock {
  agents: string[];
  rules: RobotRule[];
}

function parseRobotsTxtBlocks(text: string): AgentBlock[] {
  const blocks: AgentBlock[] = [];
  let currentAgents: string[] = [];
  let currentRules: RobotRule[] = [];
  let linesProcessed = 0;

  const flushBlock = () => {
    if (currentAgents.length > 0 && blocks.length < ROBOTS_MAX_AGENT_BLOCKS) {
      blocks.push({ agents: currentAgents.slice(), rules: currentRules.slice() });
    }
    currentAgents = [];
    currentRules = [];
  };

  for (const rawLine of text.split("\n")) {
    linesProcessed++;
    if (linesProcessed > ROBOTS_MAX_LINES) break;

    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;

    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;

    const field = line.slice(0, colonIdx).trim().toLowerCase();
    const value = line.slice(colonIdx + 1).trim();

    if (field === "user-agent") {
      // If we already have rules, flush current block and start new
      if (currentRules.length > 0) {
        flushBlock();
      }
      currentAgents.push(value.toLowerCase());
    } else if (field === "allow" || field === "disallow") {
      // Cap rule path length and rules per block
      if (currentRules.length < ROBOTS_MAX_RULES_PER_BLOCK) {
        const cappedPath = value.slice(0, ROBOTS_MAX_RULE_PATH_CHARS);
        currentRules.push({ type: field as "allow" | "disallow", path: cappedPath });
      }
    }
  }
  flushBlock();
  return blocks;
}

function matchRobotRule(urlPath: string, rulePath: string): boolean {
  if (!rulePath) return false;

  // Cap wildcard count to prevent ReDoS
  const wildcardCount = (rulePath.match(/\*/g) || []).length;
  if (wildcardCount > 10) {
    return urlPath.startsWith(rulePath.replace(/\*/g, ""));
  }

  // Handle wildcard and end-of-string anchor per Google's spec
  // Convert rule to regex: * -> .*, $ at end is literal end anchor
  try {
    let pattern = rulePath
      .replace(/[.+?^{}()|[\]\\]/g, "\\$&") // escape regex chars except * and $
      .replace(/\*/g, ".*");

    if (rulePath.endsWith("$")) {
      pattern = pattern.slice(0, -2) + "$";
    }

    return new RegExp("^" + pattern).test(urlPath);
  } catch {
    // Fallback: simple prefix match
    return urlPath.startsWith(rulePath);
  }
}

function checkRobotsTxtRules(blocks: AgentBlock[], urlPath: string): { allowed: boolean; matchedRule: string | null; matchedAgent: string | null } {
  // Prefer Googlebot-specific block, then fallback to wildcard
  let targetBlock: AgentBlock | null = null;
  let matchedAgent: string | null = null;

  for (const block of blocks) {
    if (block.agents.includes("googlebot")) {
      targetBlock = block;
      matchedAgent = "googlebot";
      break;
    }
  }

  if (!targetBlock) {
    for (const block of blocks) {
      if (block.agents.includes("*")) {
        targetBlock = block;
        matchedAgent = "*";
        break;
      }
    }
  }

  if (!targetBlock) {
    return { allowed: true, matchedRule: null, matchedAgent: null };
  }

  // Longest match wins (per Google's robots.txt spec)
  let bestMatch: { type: "allow" | "disallow"; path: string; length: number } | null = null;

  for (const rule of targetBlock.rules) {
    if (matchRobotRule(urlPath, rule.path)) {
      const ruleLength = rule.path.replace(/\*/g, "").length;
      if (!bestMatch || ruleLength > bestMatch.length) {
        bestMatch = { type: rule.type, path: rule.path, length: ruleLength };
      }
    }
  }

  if (!bestMatch) {
    return { allowed: true, matchedRule: null, matchedAgent };
  }

  return {
    allowed: bestMatch.type === "allow",
    matchedRule: `${bestMatch.type}: ${bestMatch.path}`,
    matchedAgent,
  };
}

// ── Layer checks ────────────────────────────────────────────────────────────

async function checkRobotsTxt(parsedUrl: URL): Promise<RobotsTxtCheck> {
  const robotsUrl = `${parsedUrl.origin}/robots.txt`;

  try {
    const res = await safeFetch(robotsUrl, { timeoutMs: 5000 });
    const status = res.status;

    // 4xx = allowed (no restrictions)
    if (status >= 400 && status < 500) {
      return {
        allowed: true,
        reason: "robots.txt returned 4xx (no restrictions)",
        robotsTxtStatus: status,
        matchedRule: null,
        matchedAgent: null,
      };
    }

    // 5xx = blocked (conservative)
    if (status >= 500) {
      return {
        allowed: false,
        reason: "robots.txt returned 5xx (blocked conservatively per Google spec)",
        robotsTxtStatus: status,
        matchedRule: null,
        matchedAgent: null,
      };
    }

    const text = await readBodyCapped(res, 512 * 1024); // 512 KB cap for robots.txt
    const blocks = parseRobotsTxtBlocks(text);
    const urlPath = parsedUrl.pathname + parsedUrl.search;
    const result = checkRobotsTxtRules(blocks, urlPath);

    return {
      allowed: result.allowed,
      reason: result.allowed
        ? result.matchedRule
          ? `Allowed by robots.txt (${result.matchedRule})`
          : "No blocking rule found in robots.txt"
        : `Blocked by robots.txt (${result.matchedRule})`,
      robotsTxtStatus: status,
      matchedRule: result.matchedRule,
      matchedAgent: result.matchedAgent,
    };
  } catch (err: unknown) {
    // Network error fetching robots.txt = treat as allowed
    return {
      allowed: true,
      reason: `robots.txt unreachable (${sanitizeFetchError(err)}) — treated as allowed`,
      robotsTxtStatus: null,
      matchedRule: null,
      matchedAgent: null,
    };
  }
}

function checkHttpStatus(status: number, statusText: string, headers: Headers, baseUrl: string): HttpStatusCheck {
  const redirect = status >= 300 && status < 400;
  const rawLocation = redirect ? headers.get("location") : null;
  const redirectLocation = sanitizeReflectedUrl(rawLocation, baseUrl);

  // 200-299 = indexable, everything else is not directly indexable
  const indexable = status >= 200 && status < 300;

  // Sanitize statusText from untrusted server
  const safeStatusText = statusText.replace(/[^\x20-\x7E]/g, "").slice(0, 100);

  return {
    status,
    statusText: safeStatusText,
    indexable,
    redirect,
    redirectLocation,
  };
}

function checkMetaRobots(html: string): MetaRobotsCheck {
  // Reset regex lastIndex
  META_ROBOTS_RE.lastIndex = 0;
  META_ROBOTS_REV_RE.lastIndex = 0;

  const contents: string[] = [];

  let match: RegExpExecArray | null;
  while ((match = META_ROBOTS_RE.exec(html)) !== null) {
    contents.push(match[1].toLowerCase());
  }
  while ((match = META_ROBOTS_REV_RE.exec(html)) !== null) {
    contents.push(match[1].toLowerCase());
  }

  if (contents.length === 0) {
    return { found: false, content: null, noindex: false, nofollow: false };
  }

  const combined = contents.join(", ");
  const noindex = contents.some((c) => c.includes("noindex"));
  const nofollow = contents.some((c) => c.includes("nofollow"));

  return { found: true, content: combined, noindex, nofollow };
}

function checkXRobotsTag(headers: Headers): XRobotsTagCheck {
  const value = headers.get("x-robots-tag");

  if (!value) {
    return { found: false, value: null, noindex: false, nofollow: false };
  }

  const sanitized = value.replace(/[\r\n\t\x00-\x1f\x7f]/g, " ").trim().slice(0, 512);
  const lower = sanitized.toLowerCase();
  return {
    found: true,
    value: sanitized,
    noindex: lower.includes("noindex"),
    nofollow: lower.includes("nofollow"),
  };
}

function checkCanonical(html: string, url: string): CanonicalCheck {
  const match = CANONICAL_RE.exec(html) || CANONICAL_REV_RE.exec(html);

  if (!match) {
    return { found: false, href: null, isSelf: false, pointsElsewhere: false };
  }

  const rawHref = match[1].trim();
  const href = sanitizeReflectedUrl(rawHref, url);

  if (!href) {
    return { found: true, href: null, isSelf: false, pointsElsewhere: true };
  }

  // Normalize both URLs for comparison (remove trailing slash, fragment)
  let normalizedHref: string;
  let normalizedUrl: string;
  try {
    const canonicalParsed = new URL(href);
    normalizedHref = canonicalParsed.origin + canonicalParsed.pathname.replace(/\/+$/, "") + canonicalParsed.search;
    const urlParsed = new URL(url);
    normalizedUrl = urlParsed.origin + urlParsed.pathname.replace(/\/+$/, "") + urlParsed.search;
  } catch {
    return { found: true, href, isSelf: false, pointsElsewhere: true };
  }

  const isSelf = normalizedHref === normalizedUrl;

  return {
    found: true,
    href,
    isSelf,
    pointsElsewhere: !isSelf,
  };
}

// ── Public API ──────────────────────────────────────────────────────────────

export async function fullCheck(rawUrl: string): Promise<IndexabilityResult | { error: string }> {
  const validation = validateExternalUrl(rawUrl);
  if ("error" in validation) {
    return { error: validation.error };
  }

  const parsedUrl = validation.url;
  const url = parsedUrl.toString();
  const blockingReasons: string[] = [];

  // 1. robots.txt check
  const robotsTxt = await checkRobotsTxt(parsedUrl);
  if (!robotsTxt.allowed) {
    blockingReasons.push(`robots.txt: ${robotsTxt.reason}`);
  }

  // 2-5. Fetch the actual URL for HTTP status, meta robots, x-robots-tag, canonical
  let httpStatus: HttpStatusCheck;
  let metaRobots: MetaRobotsCheck;
  let xRobotsTag: XRobotsTagCheck;
  let canonical: CanonicalCheck;

  try {
    const res = await safeFetch(url, { timeoutMs: 10000 });

    // 2. HTTP status
    httpStatus = checkHttpStatus(res.status, res.statusText, res.headers, url);
    if (!httpStatus.indexable) {
      blockingReasons.push(`HTTP status: ${res.status} ${res.statusText}`);
    }

    // 4. X-Robots-Tag (check header before consuming body)
    xRobotsTag = checkXRobotsTag(res.headers);
    if (xRobotsTag.noindex) {
      blockingReasons.push(`X-Robots-Tag: ${xRobotsTag.value}`);
    }

    // Read body for meta robots and canonical (2 MB cap)
    const html = httpStatus.indexable ? await readBodyCapped(res, 2 * 1024 * 1024) : "";

    // 3. Meta robots
    metaRobots = checkMetaRobots(html);
    if (metaRobots.noindex) {
      blockingReasons.push(`Meta robots: ${metaRobots.content}`);
    }

    // 5. Canonical
    canonical = checkCanonical(html, url);
    if (canonical.pointsElsewhere) {
      blockingReasons.push(`Canonical points elsewhere: ${canonical.href}`);
    }
  } catch (err: unknown) {
    return { error: `Failed to fetch URL: ${sanitizeFetchError(err)}` };
  }

  return {
    indexable: blockingReasons.length === 0,
    blocking_reason: blockingReasons.length > 0 ? blockingReasons[0] : null,
    checks: {
      robots_txt: robotsTxt,
      http_status: httpStatus,
      meta_robots: metaRobots,
      x_robots_tag: xRobotsTag,
      canonical,
    },
    url,
    checkedAt: new Date().toISOString(),
  };
}

export async function previewCheck(rawUrl: string): Promise<PreviewResult | { error: string }> {
  const validation = validateExternalUrl(rawUrl);
  if ("error" in validation) {
    return { error: validation.error };
  }

  const url = validation.url.toString();
  const blockingReasons: string[] = [];

  let httpStatus: HttpStatusCheck;
  let metaRobots: MetaRobotsCheck;

  try {
    const res = await safeFetch(url, { timeoutMs: 8000 });

    httpStatus = checkHttpStatus(res.status, res.statusText, res.headers, url);
    if (!httpStatus.indexable) {
      blockingReasons.push(`HTTP status: ${res.status} ${res.statusText}`);
    }

    // Read body for meta robots (2 MB cap)
    const html = httpStatus.indexable ? await readBodyCapped(res, 2 * 1024 * 1024) : "";

    metaRobots = checkMetaRobots(html);
    if (metaRobots.noindex) {
      blockingReasons.push(`Meta robots: ${metaRobots.content}`);
    }
  } catch (err: unknown) {
    return { error: `Failed to fetch URL: ${sanitizeFetchError(err)}` };
  }

  return {
    preview: true,
    indexable: blockingReasons.length === 0,
    blocking_reason: blockingReasons.length > 0 ? blockingReasons[0] : null,
    checks: {
      http_status: httpStatus,
      meta_robots: metaRobots,
    },
    url,
    checkedAt: new Date().toISOString(),
    note: "Preview checks HTTP status and meta robots only. Use /check with x402 payment for full 5-layer analysis (robots.txt, canonical, X-Robots-Tag).",
  };
}
