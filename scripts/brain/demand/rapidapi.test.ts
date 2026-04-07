import { test, expect, mock, beforeEach } from "bun:test";
import { getRapidApiDemand } from "./rapidapi";

const originalFetch = globalThis.fetch;

beforeEach(() => {
  globalThis.fetch = originalFetch;
});

test("extracts listing count and sample names from HTML", async () => {
  const mockHtml = `
    <html>
    <body>
      <a href="/hub/security-api-1">Security API 1</a>
      <a href="/hub/security-api-2">Security API 2</a>
      <a href="/hub/security-api-3">Security API 3</a>
      <a href="/hub/security-scanner">Security Scanner</a>
      <a href="/hub/vuln-check">Vulnerability Check</a>
      <a href="/hub/ssl-checker">SSL Checker</a>
      <a href="/about">About</a>
    </body>
    </html>
  `;

  globalThis.fetch = mock(() =>
    Promise.resolve(new Response(mockHtml, { status: 200 }))
  ) as typeof fetch;

  const result = await getRapidApiDemand("security");
  expect(result).not.toBeNull();
  expect(result!.category).toBe("security");
  expect(result!.listing_count).toBeGreaterThan(0);
  expect(result!.sample_names).toBeInstanceOf(Array);
  expect(result!.sample_names.length).toBeLessThanOrEqual(5);
});

test("returns null on fetch failure", async () => {
  globalThis.fetch = mock(() => Promise.reject(new Error("Network error"))) as typeof fetch;

  const result = await getRapidApiDemand("security");
  expect(result).toBeNull();
});

test("returns null on non-ok response", async () => {
  globalThis.fetch = mock(() =>
    Promise.resolve(new Response("Forbidden", { status: 403 }))
  ) as typeof fetch;

  const result = await getRapidApiDemand("security");
  expect(result).toBeNull();
});
