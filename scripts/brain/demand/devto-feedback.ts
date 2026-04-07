/**
 * Dev.to engagement signal collector.
 *
 * Fetches our published Dev.to articles and extracts engagement metrics
 * to identify which API categories generate the most reader interest.
 */

export interface ArticleEngagement {
  title: string;
  slug: string;
  page_views: number;
  reactions: number;
  comments: number;
  tags: string[];
  published_at: string;
}

export async function getDevtoEngagement(): Promise<ArticleEngagement[]> {
  const apiKey = process.env.DEVTO_API_KEY;
  if (!apiKey) {
    console.log("[devto-feedback] DEVTO_API_KEY not set -- skipping");
    return [];
  }

  try {
    const res = await fetch("https://dev.to/api/articles/me?per_page=100", {
      headers: {
        "api-key": apiKey,
        Accept: "application/vnd.forem.api-v1+json",
      },
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) {
      console.warn(`[devto-feedback] Dev.to returned ${res.status}`);
      return [];
    }

    const articles = (await res.json()) as any[];

    return articles.map((a: any) => ({
      title: String(a.title ?? ""),
      slug: String(a.slug ?? ""),
      page_views: Number(a.page_views_count ?? 0),
      reactions: Number(a.positive_reactions_count ?? 0),
      comments: Number(a.comments_count ?? 0),
      tags: Array.isArray(a.tag_list) ? a.tag_list.map(String) : [],
      published_at: String(a.published_at ?? ""),
    }));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(`[devto-feedback] Request failed: ${msg}`);
    return [];
  }
}

/**
 * Aggregate page views per tag across all articles.
 * Returns a map of tag -> total_views to identify category interest.
 */
export function getCategoryInterest(articles: ArticleEngagement[]): Map<string, number> {
  const interest = new Map<string, number>();
  for (const article of articles) {
    for (const tag of article.tags) {
      interest.set(tag, (interest.get(tag) ?? 0) + article.page_views);
    }
  }
  return interest;
}
