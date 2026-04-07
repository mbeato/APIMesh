import { test, expect, mock, beforeEach } from "bun:test";
import { getDevtoEngagement, getCategoryInterest } from "./devto-feedback";

const originalFetch = globalThis.fetch;

beforeEach(() => {
  globalThis.fetch = originalFetch;
  delete process.env.DEVTO_API_KEY;
});

test("returns empty array when DEVTO_API_KEY is missing", async () => {
  const result = await getDevtoEngagement();
  expect(result).toEqual([]);
});

test("maps Dev.to article response to ArticleEngagement", async () => {
  process.env.DEVTO_API_KEY = "test-key";

  const mockArticles = [
    {
      title: "How to Build an SEO API",
      slug: "how-to-build-an-seo-api",
      page_views_count: 1500,
      positive_reactions_count: 42,
      comments_count: 7,
      tag_list: ["seo", "api", "webdev"],
      published_at: "2026-04-01T12:00:00Z",
    },
    {
      title: "Security Header Analysis",
      slug: "security-header-analysis",
      page_views_count: 800,
      positive_reactions_count: 25,
      comments_count: 3,
      tag_list: ["security", "api"],
      published_at: "2026-04-02T10:00:00Z",
    },
  ];

  globalThis.fetch = mock(() =>
    Promise.resolve(
      new Response(JSON.stringify(mockArticles), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    )
  ) as typeof fetch;

  const result = await getDevtoEngagement();
  expect(result).toHaveLength(2);
  expect(result[0]).toEqual({
    title: "How to Build an SEO API",
    slug: "how-to-build-an-seo-api",
    page_views: 1500,
    reactions: 42,
    comments: 7,
    tags: ["seo", "api", "webdev"],
    published_at: "2026-04-01T12:00:00Z",
  });
});

test("returns empty array on fetch error", async () => {
  process.env.DEVTO_API_KEY = "test-key";

  globalThis.fetch = mock(() => Promise.reject(new Error("Network error"))) as typeof fetch;

  const result = await getDevtoEngagement();
  expect(result).toEqual([]);
});

test("getCategoryInterest aggregates views per tag", () => {
  const articles = [
    { title: "A", slug: "a", page_views: 1000, reactions: 10, comments: 1, tags: ["seo", "api"], published_at: "2026-04-01T00:00:00Z" },
    { title: "B", slug: "b", page_views: 500, reactions: 5, comments: 0, tags: ["security", "api"], published_at: "2026-04-02T00:00:00Z" },
    { title: "C", slug: "c", page_views: 300, reactions: 3, comments: 2, tags: ["seo"], published_at: "2026-04-03T00:00:00Z" },
  ];

  const interest = getCategoryInterest(articles);
  expect(interest.get("seo")).toBe(1300); // 1000 + 300
  expect(interest.get("api")).toBe(1500); // 1000 + 500
  expect(interest.get("security")).toBe(500);
});
