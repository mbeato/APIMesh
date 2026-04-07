import { test, expect, mock, beforeEach } from "bun:test";
import { getAutocompleteSuggestions } from "./autocomplete";

const originalFetch = globalThis.fetch;

beforeEach(() => {
  globalThis.fetch = originalFetch;
});

test("returns suggestions on successful response", async () => {
  globalThis.fetch = mock(() =>
    Promise.resolve(
      new Response(
        JSON.stringify(["api for security", ["api for security scanning", "api for security headers", "api for security audit"]]),
        { status: 200, headers: { "Content-Type": "application/json" } }
      )
    )
  ) as typeof fetch;

  const result = await getAutocompleteSuggestions("api for security");
  expect(result).toEqual([
    "api for security scanning",
    "api for security headers",
    "api for security audit",
  ]);
});

test("returns empty array on fetch failure", async () => {
  globalThis.fetch = mock(() => Promise.reject(new Error("Network error"))) as typeof fetch;

  const result = await getAutocompleteSuggestions("api for security");
  expect(result).toEqual([]);
});

test("returns empty array on non-ok response", async () => {
  globalThis.fetch = mock(() =>
    Promise.resolve(new Response("Error", { status: 503 }))
  ) as typeof fetch;

  const result = await getAutocompleteSuggestions("test query");
  expect(result).toEqual([]);
});

test("parses [query, [suggestions]] format correctly", async () => {
  globalThis.fetch = mock(() =>
    Promise.resolve(
      new Response(
        JSON.stringify(["dns api", ["dns api free", "dns api lookup", "dns api python"]]),
        { status: 200 }
      )
    )
  ) as typeof fetch;

  const result = await getAutocompleteSuggestions("dns api");
  expect(result).toHaveLength(3);
  expect(result[0]).toBe("dns api free");
});
