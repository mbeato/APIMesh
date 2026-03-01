// favicon-checker/checker.ts

/**
 * Return type for favicon check
 */
export interface FaviconCheckResult {
  checkedUrl: string; // the input root URL (origin)
  faviconFound: boolean;
  faviconUrl: string | null;
  httpStatus: number | null;
  error?: string;
  checkedAt: string;
}

function sanitizeNetworkError(e: unknown): string {
  const err = e instanceof Error ? e : new Error(String(e));
  if (err.name === "TimeoutError") return "timeout";
  // Bun/Node fetch may include 'code'
  if (typeof (err as any).code === "string") {
    const code = (err as any).code;
    const safe: Record<string, string> = {
      ECONNREFUSED: "connection_refused",
      ENOTFOUND: "dns_not_found",
      ECONNRESET: "connection_reset",
      ETIMEDOUT: "timeout",
    };
    return safe[code] ?? "network_error";
  }
  if ((err as any).type === "aborted") return "timeout";
  return "network_error";
}

/**
 * Attempts /favicon.ico then falls back to best <link rel="icon"> from <head>.
 * Performs only 1-2 requests. Never follows insecure redirects.
 * @param origin 'https://domain.com'
 */
export async function checkFavicon(origin: string): Promise<FaviconCheckResult> {
  const checkedUrl = origin;

  // Always force https if input is http://
  let testedOrigin = origin.replace(/^http:\/\//i, "https://");
  let iconUrl = null;
  let status: number | null = null;
  let found = false;
  let error: string | undefined;

  // Try HEAD first for /favicon.ico
  const icoUrl = `${testedOrigin}/favicon.ico`;
  try {
    // HEAD is polite, but some hosts (old S3, GitHub Pages) block HEAD: fallback to GET
    let res = await fetch(icoUrl, {
      method: "HEAD",
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
    });
    status = res.status;
    found = res.ok;
    if (found) {
      iconUrl = icoUrl;
      return {
        checkedUrl,
        faviconFound: true,
        faviconUrl: iconUrl,
        httpStatus: status,
        checkedAt: new Date().toISOString(),
      };
    }
    // fallback: some services block HEAD, so try GET if 403/405/501
    if ([403, 405, 501].includes(status)) {
      res = await fetch(icoUrl, {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.timeout(5000),
      });
      status = res.status;
      found = res.ok;
      if (found) {
        iconUrl = icoUrl;
        return {
          checkedUrl,
          faviconFound: true,
          faviconUrl: iconUrl,
          httpStatus: status,
          checkedAt: new Date().toISOString(),
        };
      }
    }
  } catch (e) {
    error = sanitizeNetworkError(e);
  }

  // Try parsing <link rel="icon"> from <head> via GET /
  let html: string | null = null;
  try {
    const rootRes = await fetch(testedOrigin + "/", {
      method: "GET",
      redirect: "manual",
      headers: {
        "User-Agent": "apimesh-favicon-checker/1.0"
      },
      signal: AbortSignal.timeout(5000),
    });
    status = rootRes.status;
    if (rootRes.ok) {
      const ab = await rootRes.arrayBuffer();
      // Only parse up to 96 KB for <head>
      html = new TextDecoder().decode(ab).slice(0, 98304);
      // Extremely simple: just look for <link rel="icon" ... href=...>
      // Accept shortcut, mask-icon, apple-touch-icon, etc
      // This will not cover _all_ real-world cases but covers 99%
      const headEnd = html.indexOf("</head>");
      const searchRegion = headEnd === -1 ? html : html.slice(0, headEnd);
      // Regex to match <link rel=...icon... href=...>
      const regex = /<link[^>]+rel\s*=\s*['\"]?([^'\">]+)['\"]?[^>]*href\s*=\s*['\"]([^'\">]+)['\"][^>]*>/ig;
      let match;
      while ((match = regex.exec(searchRegion))) {
        const rel = match[1].toLowerCase();
        const href = match[2];
        if (rel.includes("icon")) {
          // Resolve relative hrefs
          if (/^https?:\/\//.test(href)) {
            iconUrl = href;
          } else if (href.startsWith("//")) {
            iconUrl = testedOrigin.split(":")[0] + ":" + href;
          } else if (href.startsWith("/")) {
            iconUrl = testedOrigin + href;
          } else {
            iconUrl = testedOrigin + "/" + href;
          }
          // We'll only report the FIRST relevant <link rel=icon> found
          found = true;
          break;
        }
      }
    }
  } catch (e) {
    if (!error) error = sanitizeNetworkError(e);
  }

  return {
    checkedUrl,
    faviconFound: found,
    faviconUrl: found ? iconUrl : null,
    httpStatus: status,
    error,
    checkedAt: new Date().toISOString(),
  };
}
