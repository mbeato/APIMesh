interface AvailabilityResult {
  platform: string;
  identifier: string;
  available: boolean | null;
  url: string;
  error?: string;
}

function sanitizeNetworkError(e: unknown): string {
  const err = e instanceof Error ? e : new Error(String(e));
  if (err.name === "TimeoutError") return "timeout";
  if ("code" in err) {
    const code = (err as NodeJS.ErrnoException).code;
    const safe: Record<string, string> = {
      ECONNREFUSED: "connection_refused",
      ENOTFOUND: "dns_not_found",
      ECONNRESET: "connection_reset",
      ETIMEDOUT: "timeout",
    };
    return safe[code ?? ""] ?? "network_error";
  }
  return "network_error";
}

async function checkHttp(
  url: string,
  platform: string,
  identifier: string
): Promise<AvailabilityResult> {
  try {
    const res = await fetch(url, {
      method: "HEAD",
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
    });
    return {
      platform,
      identifier,
      available: res.status === 404,
      url,
    };
  } catch (e: unknown) {
    return { platform, identifier, available: null, url, error: sanitizeNetworkError(e) };
  }
}

const MAX_JSON_BODY = 64 * 1024; // 64KB guard for external JSON responses

async function checkReddit(slug: string): Promise<AvailabilityResult> {
  const url = `https://www.reddit.com/r/${slug}/about.json`;
  try {
    const res = await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
      headers: { "User-Agent": "apimesh-checker/1.0" },
    });
    if (res.status === 404) {
      return { platform: "reddit", identifier: slug, available: true, url };
    }
    const buf = await res.arrayBuffer();
    if (buf.byteLength > MAX_JSON_BODY) {
      return { platform: "reddit", identifier: slug, available: null, url, error: "response_too_large" };
    }
    const data = JSON.parse(new TextDecoder().decode(buf)) as any;
    // Banned/private subs are NOT available for use
    const isTaken = data.reason === "banned" || data.reason === "private";
    const available = (data.error === 404 || (!data.data && !isTaken)) && !isTaken;
    return { platform: "reddit", identifier: slug, available, url };
  } catch (e: unknown) {
    return { platform: "reddit", identifier: slug, available: null, url, error: sanitizeNetworkError(e) };
  }
}

export async function checkDns(domain: string): Promise<AvailabilityResult> {
  const dnsUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`;
  try {
    const res = await fetch(dnsUrl, { signal: AbortSignal.timeout(5000) });
    const buf = await res.arrayBuffer();
    if (buf.byteLength > MAX_JSON_BODY) {
      return { platform: "domain", identifier: domain, available: null, url: `https://${domain}`, error: "response_too_large" };
    }
    const data = JSON.parse(new TextDecoder().decode(buf)) as any;
    const available = !data.Answer || data.Answer.length === 0;
    return { platform: "domain", identifier: domain, available, url: `https://${domain}` };
  } catch (e: unknown) {
    return { platform: "domain", identifier: domain, available: null, url: `https://${domain}`, error: sanitizeNetworkError(e) };
  }
}

// Expects a pre-sanitized slug (lowercase alphanumeric + hyphens only)
export async function checkPresence(slug: string): Promise<{
  query: string;
  results: AvailabilityResult[];
  checkedAt: string;
}> {
  const checks = [
    checkDns(`${slug}.com`),
    checkDns(`${slug}.io`),
    checkDns(`${slug}.xyz`),
    checkDns(`${slug}.dev`),
    checkDns(`${slug}.ai`),
    checkHttp(`https://github.com/${slug}`, "github-user", slug),
    checkHttp(`https://registry.npmjs.org/${slug}`, "npm", slug),
    checkHttp(`https://pypi.org/project/${slug}/`, "pypi", slug),
    checkReddit(slug),
  ];

  const results = await Promise.all(checks);

  return {
    query: slug,
    results,
    checkedAt: new Date().toISOString(),
  };
}
