import { validateExternalUrl } from "../../shared/ssrf";

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const HOP_TIMEOUT_MS = 8000;
const MAX_HOPS = 20;
const SELECTED_HEADERS = ["server", "x-robots-tag", "cache-control"];

const CANONICAL_RE = /<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']/i;
const CANONICAL_RE_ALT = /href=["']([^"']+)["'][^>]+rel=["']canonical["']/i;

export interface RedirectHop {
  url: string;
  statusCode: number;
  redirectType: number | null;
  location: string | null;
  latencyMs: number;
  headers: Record<string, string>;
}

export interface RedirectChainResult {
  chain: RedirectHop[];
  finalUrl: string;
  finalStatus: number;
  chainLength: number;
  totalLatencyMs: number;
  hasLoop: boolean;
  canonical: string | null;
  issues: string[];
}

function pickHeaders(headers: Headers): Record<string, string> {
  const picked: Record<string, string> = {};
  for (const name of SELECTED_HEADERS) {
    const value = headers.get(name);
    if (value !== null) {
      picked[name] = value;
    }
  }
  return picked;
}

function resolveLocation(location: string, currentUrl: string): string {
  const resolved = new URL(location, currentUrl);
  if (resolved.protocol !== "http:" && resolved.protocol !== "https:") {
    throw new Error("Redirect to unsupported scheme");
  }
  return resolved.toString();
}

async function extractCanonical(url: string): Promise<string | null> {
  try {
    const check = validateExternalUrl(url);
    if ("error" in check) return null;

    const res = await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(HOP_TIMEOUT_MS),
      headers: {
        "User-Agent": "redirect-chain-analyzer/1.0 apimesh.xyz",
        Accept: "text/html",
      },
    });

    if (res.status !== 200) return null;

    const contentType = res.headers.get("content-type") || "";
    if (!contentType.includes("text/html")) return null;

    // Read only the first 64KB to find the canonical tag (it's in <head>)
    const reader = res.body?.getReader();
    if (!reader) return null;

    let html = "";
    let bytesRead = 0;
    const decoder = new TextDecoder();
    const maxBytes = 64 * 1024;

    while (bytesRead < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      bytesRead += value.byteLength;
      html += decoder.decode(value, { stream: true });

      // Check for canonical in what we have so far
      const match = CANONICAL_RE.exec(html) || CANONICAL_RE_ALT.exec(html);
      if (match) {
        const raw = match[1];
        const canonCheck = validateExternalUrl(raw);
        if ("error" in canonCheck) {
          // Don't return internal/invalid canonicals
          reader.cancel();
          return null;
        }
        reader.cancel();
        return canonCheck.url.toString();
      }

      // If we've passed </head>, no point reading further
      if (html.includes("</head>")) {
        reader.cancel();
        break;
      }
    }

    reader.cancel();

    // One final check on accumulated HTML
    const match = CANONICAL_RE.exec(html) || CANONICAL_RE_ALT.exec(html);
    if (match) {
      const raw = match[1];
      const canonCheck = validateExternalUrl(raw);
      if ("error" in canonCheck) {
        return null;
      }
      return canonCheck.url.toString();
    }
    return null;
  } catch {
    return null;
  }
}

function detectIssues(chain: RedirectHop[], finalUrl: string, canonical: string | null, hasLoop: boolean): string[] {
  const issues: string[] = [];

  if (hasLoop) {
    issues.push("Redirect loop detected");
  }

  // Check for mixed redirect types
  const redirectTypes = new Set(
    chain
      .filter((hop) => hop.redirectType !== null)
      .map((hop) => hop.redirectType)
  );
  if (redirectTypes.size > 1) {
    const types = Array.from(redirectTypes).sort().join(" and ");
    issues.push(`Mixed redirect types (${types})`);
  }

  // Chain length warning (more than 3 hops means intermediate redirects)
  const redirectHops = chain.filter((hop) => hop.redirectType !== null);
  if (redirectHops.length > 3) {
    issues.push("Chain longer than 3 hops");
  }

  // Canonical mismatch
  if (canonical && canonical !== finalUrl) {
    issues.push("Final URL differs from canonical");
  }

  return issues;
}

export async function traceRedirectChain(
  startUrl: string,
  options: { maxHops?: number; extractCanonical?: boolean } = {}
): Promise<RedirectChainResult> {
  const maxHops = options.maxHops ?? MAX_HOPS;
  const shouldExtractCanonical = options.extractCanonical ?? true;

  const chain: RedirectHop[] = [];
  const visited = new Set<string>();
  let currentUrl = startUrl;
  let hasLoop = false;

  while (chain.length < maxHops) {
    // SSRF check for each hop
    const check = validateExternalUrl(currentUrl);
    if ("error" in check) {
      console.error(`[redirect-chain] Unsafe URL at hop ${chain.length + 1}: ${check.error} (${currentUrl})`);
      throw new Error(`Redirect chain contains a disallowed URL at hop ${chain.length + 1}`);
    }

    // Detect loop
    if (visited.has(currentUrl)) {
      hasLoop = true;
      // Add the loop-causing hop with info but stop following
      chain.push({
        url: currentUrl,
        statusCode: 0,
        redirectType: null,
        location: null,
        latencyMs: 0,
        headers: {},
      });
      break;
    }
    visited.add(currentUrl);

    const start = performance.now();
    let res: Response;
    try {
      res = await fetch(currentUrl, {
        redirect: "manual",
        signal: AbortSignal.timeout(HOP_TIMEOUT_MS),
        headers: {
          "User-Agent": "redirect-chain-analyzer/1.0 apimesh.xyz",
          Accept: "text/html, */*",
        },
      });
    } catch (err: any) {
      const latencyMs = Math.round(performance.now() - start);
      chain.push({
        url: currentUrl,
        statusCode: 0,
        redirectType: null,
        location: null,
        latencyMs,
        headers: {},
      });
      const errorMsg = err?.name === "TimeoutError" ? "Request timed out" : (err?.message || "Network error");
      console.error(`[redirect-chain] Failed to fetch ${currentUrl}: ${errorMsg}`);
      throw new Error(`Failed to reach destination at hop ${chain.length}: ${errorMsg}`);
    }
    const latencyMs = Math.round(performance.now() - start);

    const statusCode = res.status;
    const isRedirect = REDIRECT_STATUSES.has(statusCode);
    const location = res.headers.get("location");

    chain.push({
      url: currentUrl,
      statusCode,
      redirectType: isRedirect ? statusCode : null,
      location: isRedirect ? location : null,
      latencyMs,
      headers: pickHeaders(res.headers),
    });

    if (!isRedirect) {
      // Terminal response reached
      break;
    }

    if (!location) {
      console.error(`[redirect-chain] Redirect ${statusCode} at ${currentUrl} missing Location header`);
      throw new Error(`Redirect at hop ${chain.length} missing Location header`);
    }

    // Resolve relative Location headers
    currentUrl = resolveLocation(location, currentUrl);
  }

  // Check if we exceeded max hops
  if (chain.length >= maxHops && chain[chain.length - 1]?.redirectType !== null) {
    throw new Error(`Redirect chain exceeded maximum of ${maxHops} hops`);
  }

  const lastHop = chain[chain.length - 1];
  const finalUrl = hasLoop ? chain[chain.length - 2]?.url ?? startUrl : lastHop.url;
  const finalStatus = hasLoop ? 0 : lastHop.statusCode;

  // Extract canonical from final page if it returned 200
  let canonical: string | null = null;
  if (shouldExtractCanonical && finalStatus === 200) {
    canonical = await extractCanonical(finalUrl);
  }

  const totalLatencyMs = chain.reduce((sum, hop) => sum + hop.latencyMs, 0);
  const issues = detectIssues(chain, finalUrl, canonical, hasLoop);

  return {
    chain,
    finalUrl,
    finalStatus,
    chainLength: chain.length,
    totalLatencyMs,
    hasLoop,
    canonical,
    issues,
  };
}
