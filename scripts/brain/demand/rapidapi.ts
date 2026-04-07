/**
 * RapidAPI marketplace demand signals.
 *
 * Scrapes RapidAPI search results to estimate how many APIs exist in a category.
 * This is a non-critical signal -- returns null on any failure.
 */

export interface MarketplaceDemand {
  category: string;
  listing_count: number;
  sample_names: string[];
}

export async function getRapidApiDemand(category: string): Promise<MarketplaceDemand | null> {
  try {
    const url = `https://rapidapi.com/search/${encodeURIComponent(category)}`;
    const res = await fetch(url, {
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; APIMesh/1.0)",
      },
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) {
      console.warn(`[rapidapi] Search returned ${res.status}`);
      return null;
    }

    const html = await res.text();

    // Try to find API card markers
    const cardPattern = /data-testid="api-card"/g;
    const cardMatches = html.match(cardPattern);
    let listingCount = cardMatches?.length ?? 0;

    // Extract API names from /hub/ links
    const hubPattern = /<a[^>]*href="\/hub\/([^"]+)"[^>]*>([^<]*)<\/a>/gi;
    const sampleNames: string[] = [];
    const seen = new Set<string>();
    let hubMatch;

    while ((hubMatch = hubPattern.exec(html)) !== null) {
      const name = hubMatch[1].replace(/-/g, " ").trim();
      if (name && !seen.has(name) && sampleNames.length < 5) {
        seen.add(name);
        sampleNames.push(name);
      }
    }

    // Fallback: if no card markers found (JS-rendered page), count /hub/ links
    if (listingCount === 0 && sampleNames.length > 0) {
      const hubLinks = html.match(/<a[^>]*href="\/hub\//gi);
      listingCount = hubLinks?.length ?? 0;
    }

    if (listingCount === 0 && sampleNames.length === 0) {
      console.log(`[rapidapi] No listings found for "${category}" (JS-rendered page)`);
      return null;
    }

    return {
      category,
      listing_count: listingCount,
      sample_names: sampleNames,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(`[rapidapi] Request failed: ${msg}`);
    return null;
  }
}
