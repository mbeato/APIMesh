interface StatusCheckResult {
  url: string;
  status: number | null;
  ok: boolean | null;
  accessible: boolean | null;
  redirected: boolean | null;
  contentType?: string;
  contentLength?: number;
  error?: string;
  checkedAt: string;
}

function networkErrorToString(e: unknown): string {
  if (e instanceof Error) {
    if ('code' in e) {
      const code = (e as any).code;
      if (code === 'ECONNREFUSED') return 'connection_refused';
      if (code === 'ENOTFOUND') return 'dns_not_found';
      if (code === 'ECONNRESET') return 'connection_reset';
      if (code === 'ETIMEDOUT') return 'timeout';
    }
    if ((e as Error).name === 'TimeoutError') return 'timeout';
    return e.message || 'network_error';
  }
  return String(e);
}

// The user-agent is set for improved compatibility
const UA = 'status-code-checker/1.0 (+https://apimesh.xyz)';

export async function checkStatusCode(url: string): Promise<StatusCheckResult> {
  let resp: Response | null = null;
  let redirected = false;
  try {
    // Use HEAD method, fallback to GET if HEAD is not supported
    try {
      resp = await fetch(url, {
        method: 'HEAD',
        redirect: 'manual',
        headers: {
          'User-Agent': UA,
        },
        signal: AbortSignal.timeout(6000),
      });
    } catch (e: any) {
      // If HEAD is not allowed, fallback to GET
      if (e instanceof TypeError || String(e).includes('405')) {
        resp = await fetch(url, {
          method: 'GET',
          redirect: 'manual',
          headers: { 'User-Agent': UA },
          signal: AbortSignal.timeout(9000),
        });
      } else {
        throw e;
      }
    }
    
    redirected = resp.status >= 300 && resp.status < 400 && !!resp.headers.get('location');
    let len: number | undefined = undefined;
    const cl = resp.headers.get('content-length');
    if (cl) {
      const _n = Number(cl);
      if (!isNaN(_n)) len = _n;
    }
    return {
      url,
      status: resp.status,
      ok: resp.ok,
      accessible: resp.status >= 200 && resp.status < 400,
      redirected,
      contentType: resp.headers.get('content-type') || undefined,
      contentLength: len,
      checkedAt: new Date().toISOString(),
    };
  } catch (e: unknown) {
    return {
      url,
      status: null,
      ok: null,
      accessible: null,
      redirected: null,
      error: networkErrorToString(e),
      checkedAt: new Date().toISOString(),
    };
  }
}
