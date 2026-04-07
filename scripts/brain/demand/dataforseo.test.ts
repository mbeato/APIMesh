import { test, expect, mock, beforeEach } from "bun:test";
import { getKeywordVolumes } from "./dataforseo";

const originalFetch = globalThis.fetch;

beforeEach(() => {
  globalThis.fetch = originalFetch;
  delete process.env.DATAFORSEO_LOGIN;
  delete process.env.DATAFORSEO_PASSWORD;
});

test("returns empty array when DATAFORSEO_LOGIN is missing", async () => {
  process.env.DATAFORSEO_PASSWORD = "test-pass";
  const result = await getKeywordVolumes(["seo api"]);
  expect(result).toEqual([]);
});

test("returns empty array when DATAFORSEO_PASSWORD is missing", async () => {
  process.env.DATAFORSEO_LOGIN = "test-login";
  const result = await getKeywordVolumes(["seo api"]);
  expect(result).toEqual([]);
});

test("returns KeywordVolume[] on successful API response", async () => {
  process.env.DATAFORSEO_LOGIN = "test-login";
  process.env.DATAFORSEO_PASSWORD = "test-pass";

  globalThis.fetch = mock(() =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          tasks: [
            {
              result: [
                { keyword: "seo api", search_volume: 1200, competition: 0.45, cpc: 2.5 },
                { keyword: "dns lookup api", search_volume: 800, competition: 0.3, cpc: 1.8 },
              ],
            },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      )
    )
  ) as typeof fetch;

  const result = await getKeywordVolumes(["seo api", "dns lookup api"]);
  expect(result).toHaveLength(2);
  expect(result[0]).toEqual({
    keyword: "seo api",
    search_volume: 1200,
    competition: 0.45,
    cpc: 2.5,
  });
  expect(result[1]).toEqual({
    keyword: "dns lookup api",
    search_volume: 800,
    competition: 0.3,
    cpc: 1.8,
  });
});

test("returns empty array on fetch timeout/error", async () => {
  process.env.DATAFORSEO_LOGIN = "test-login";
  process.env.DATAFORSEO_PASSWORD = "test-pass";

  globalThis.fetch = mock(() => Promise.reject(new Error("AbortError: timeout"))) as typeof fetch;

  const result = await getKeywordVolumes(["seo api"]);
  expect(result).toEqual([]);
});

test("returns empty array on non-ok response", async () => {
  process.env.DATAFORSEO_LOGIN = "test-login";
  process.env.DATAFORSEO_PASSWORD = "test-pass";

  globalThis.fetch = mock(() =>
    Promise.resolve(new Response("Unauthorized", { status: 401 }))
  ) as typeof fetch;

  const result = await getKeywordVolumes(["seo api"]);
  expect(result).toEqual([]);
});
