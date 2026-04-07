/**
 * DataForSEO keyword volume client.
 *
 * Queries DataForSEO v3 for search volume data on candidate API keywords.
 * Falls back gracefully (returns []) when credentials are missing or API fails.
 */

export interface KeywordVolume {
  keyword: string;
  search_volume: number | null;
  competition: number | null;
  cpc: number | null;
}

export async function getKeywordVolumes(keywords: string[]): Promise<KeywordVolume[]> {
  const login = process.env.DATAFORSEO_LOGIN;
  const password = process.env.DATAFORSEO_PASSWORD;

  if (!login || !password) {
    console.log("[dataforseo] DATAFORSEO_LOGIN or DATAFORSEO_PASSWORD not set -- skipping");
    return [];
  }

  try {
    const auth = btoa(`${login}:${password}`);
    const res = await fetch(
      "https://api.dataforseo.com/v3/dataforseo_labs/google/search_volume/live",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Basic ${auth}`,
        },
        body: JSON.stringify([
          { keywords, language_code: "en", location_code: 2840 },
        ]),
        signal: AbortSignal.timeout(15_000),
      }
    );

    if (!res.ok) {
      console.warn(`[dataforseo] API returned ${res.status}`);
      return [];
    }

    const data = await res.json();
    const results = data?.tasks?.[0]?.result;

    if (!Array.isArray(results)) {
      console.warn("[dataforseo] Unexpected response structure");
      return [];
    }

    return results.map((r: any) => ({
      keyword: String(r.keyword ?? ""),
      search_volume: r.search_volume ?? null,
      competition: r.competition ?? null,
      cpc: r.cpc ?? null,
    }));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(`[dataforseo] Request failed: ${msg}`);
    return [];
  }
}
