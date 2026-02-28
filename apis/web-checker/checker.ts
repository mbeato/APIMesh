interface AvailabilityResult {
  platform: string;
  identifier: string;
  available: boolean | null;
  url: string;
  error?: string;
}

async function checkHttp(
  url: string,
  platform: string,
  identifier: string
): Promise<AvailabilityResult> {
  try {
    const res = await fetch(url, {
      method: "HEAD",
      redirect: "follow",
      signal: AbortSignal.timeout(5000),
    });
    return {
      platform,
      identifier,
      available: res.status === 404,
      url,
    };
  } catch (e: any) {
    if (e.name === "TimeoutError" || e.code === "ECONNREFUSED") {
      return { platform, identifier, available: null, url, error: "timeout" };
    }
    return { platform, identifier, available: null, url, error: e.message };
  }
}

async function checkDns(domain: string): Promise<AvailabilityResult> {
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${domain}&type=A`,
      { signal: AbortSignal.timeout(5000) }
    );
    const data = (await res.json()) as any;
    const available = !data.Answer || data.Answer.length === 0;
    return {
      platform: "domain",
      identifier: domain,
      available,
      url: `https://dns.google/resolve?name=${domain}&type=A`,
    };
  } catch (e: any) {
    return {
      platform: "domain",
      identifier: domain,
      available: null,
      url: `https://dns.google/resolve?name=${domain}&type=A`,
      error: e.message,
    };
  }
}

export async function checkPresence(name: string): Promise<{
  query: string;
  results: AvailabilityResult[];
  checkedAt: string;
}> {
  const slug = name.toLowerCase().replace(/[^a-z0-9-]/g, "");

  const checks = [
    // Domains
    checkDns(`${slug}.com`),
    checkDns(`${slug}.io`),
    checkDns(`${slug}.xyz`),
    checkDns(`${slug}.dev`),
    checkDns(`${slug}.ai`),
    // GitHub
    checkHttp(`https://github.com/${slug}`, "github-user", slug),
    // npm
    checkHttp(`https://registry.npmjs.org/${slug}`, "npm", slug),
    // PyPI
    checkHttp(`https://pypi.org/project/${slug}/`, "pypi", slug),
    // Reddit
    checkHttp(`https://www.reddit.com/r/${slug}/about.json`, "reddit", slug),
  ];

  const results = await Promise.all(checks);

  return {
    query: name,
    results,
    checkedAt: new Date().toISOString(),
  };
}
