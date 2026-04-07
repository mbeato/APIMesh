/**
 * Google Autocomplete fallback for keyword demand signals.
 *
 * Queries suggestqueries.google.com for autocomplete suggestions.
 * Used when DataForSEO credentials are not available.
 */

export async function getAutocompleteSuggestions(query: string): Promise<string[]> {
  try {
    const url = `https://suggestqueries.google.com/complete/search?client=firefox&q=${encodeURIComponent(query)}&hl=en`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(5_000),
    });

    if (!res.ok) {
      console.warn(`[autocomplete] Google returned ${res.status}`);
      return [];
    }

    const data = await res.json();

    // Response format: [query, [suggestion1, suggestion2, ...]]
    if (Array.isArray(data) && Array.isArray(data[1])) {
      return data[1].map(String);
    }

    return [];
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(`[autocomplete] Request failed: ${msg}`);
    return [];
  }
}
