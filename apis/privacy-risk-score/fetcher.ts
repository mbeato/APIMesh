import { safeFetch, validateExternalUrl } from "../../shared/ssrf";

export interface FetchedSource {
  url: string;
  fetchedUrl: string;
  status: number;
  contentType: string | null;
  bodySnippet: string;
  error?: string;
}

export async function fetchUrl(urlStr: string): Promise<FetchedSource> {
  // Validate URL to avoid SSRF
  const check = validateExternalUrl(urlStr);
  if ("error" in check) {
    return {
      url: urlStr,
      fetchedUrl: "",
      status: 0,
      contentType: null,
      bodySnippet: "",
      error: `Invalid URL: ${check.error}`,
    };
  }

  const url = check.url.toString();

  try {
    const res = await safeFetch(url, {
      method: "GET",
      signal: AbortSignal.timeout(10000),
      headers: { "User-Agent": "privacy-risk-score/1.0 apimesh.xyz" },
    });

    const contentType = res.headers.get("content-type");

    // Read max ~4KB for snippet
    const MAX_SNIPPET_BYTES = 4096;
    let snippet = "";

    try {
      const reader = res.body?.getReader();
      if (reader) {
        let receivedLength = 0;
        const chunks: Uint8Array[] = [];

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            chunks.push(value);
            receivedLength += value.length;
            if (receivedLength >= MAX_SNIPPET_BYTES) break;
          }
        }

        const concat = new Uint8Array(receivedLength);
        let position = 0;
        for (const chunk of chunks) {
          concat.set(chunk, position);
          position += chunk.length;
        }

        snippet = new TextDecoder().decode(concat);
      } else {
        // fallback
        snippet = await res.text();
        if (snippet.length > MAX_SNIPPET_BYTES) {
          snippet = snippet.slice(0, MAX_SNIPPET_BYTES);
        }
      }
    } catch {
      snippet = "";
    }

    return {
      url: urlStr,
      fetchedUrl: res.url,
      status: res.status,
      contentType,
      bodySnippet: snippet,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      url: urlStr,
      fetchedUrl: "",
      status: 0,
      contentType: null,
      bodySnippet: "",
      error: msg,
    };
  }
}

export async function fetchMultiple(urls: string[]): Promise<FetchedSource[]> {
  // Run parallel fetches with Promise.all
  const fetchPromises = urls.map((url) => fetchUrl(url));
  return Promise.all(fetchPromises);
}
