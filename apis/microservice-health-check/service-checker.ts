// Types for per-service result
export type ServiceCheckResult = {
  url: string;
  healthy: boolean;
  httpStatus: number | null;
  responseTimeMs: number | null;
  error?: string;
  checkedAt: string;
};

const MAX_TOTAL_TIME = 12_000; // Maximum total check per call
const PER_SERVICE_TIMEOUT = 6000; // max per service
const USER_AGENT = "apimesh-microservice-health-check/1.0";

function sanitizeServiceError(e: unknown): string {
  const err = e instanceof Error ? e : new Error(String(e));
  if (err.name === "TimeoutError") return "timeout";
  if (typeof (err as any).code === "string") {
    const code = (err as any).code as string;
    const safe: Record<string, string> = {
      ECONNREFUSED: "connection_refused",
      ENOTFOUND: "dns_not_found",
      ECONNRESET: "connection_reset",
      ETIMEDOUT: "timeout",
    };
    return safe[code] ?? "network_error";
  }
  return "network_error";
}

export async function checkServicesHealth(urls: string[]): Promise<{
  checkedAt: string;
  results: ServiceCheckResult[];
}> {
  const now = new Date().toISOString();
  // Perform HEAD. If fails, try GET with small byte limit
  const results = await Promise.all(urls.map(async (url) => {
    const start = Date.now();
    let healthy = false;
    let status: number | null = null;
    let error: string | undefined = undefined;
    let responseTimeMs: number | null = null;
    try {
      const ctrl = AbortSignal.timeout(PER_SERVICE_TIMEOUT);
      let res: Response;
      try {
        res = await fetch(url, {
          method: "HEAD",
          signal: ctrl,
          headers: { "User-Agent": USER_AGENT },
          redirect: "manual"
        });
      } catch (headErr) {
        // Some servers disallow HEAD: try GET, but don't buffer more than 16KB
        try {
          res = await fetch(url, {
            method: "GET",
            headers: { "User-Agent": USER_AGENT },
            signal: ctrl,
            redirect: "manual"
          });
          // Read up to 16KB then abort
          const reader = (res.body as ReadableStream<any>)?.getReader?.();
          if (reader) {
            let bytes = 0;
            while (bytes < 16 * 1024) {
              const { done, value } = await reader.read();
              if (done) break;
              bytes += value?.length || 0;
            }
            try { reader.releaseLock(); } catch {}
          } else {
            // If no stream, just don't buffer
          }
        } catch (getErr) {
          throw headErr;
        }
      }
      status = res.status;
      healthy = status >= 200 && status < 400;
      responseTimeMs = Date.now() - start;
    } catch (e) {
      error = sanitizeServiceError(e);
      responseTimeMs = Date.now() - start;
      status = null;
      healthy = false;
    }
    return {
      url,
      healthy,
      httpStatus: status,
      responseTimeMs,
      error,
      checkedAt: now,
    } satisfies ServiceCheckResult;
  }));
  return {
    checkedAt: new Date().toISOString(),
    results,
  };
}
