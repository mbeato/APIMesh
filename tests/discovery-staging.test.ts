import { test, expect, describe } from "bun:test";

// HTTP smoke tests against deployed staging. Verifies the discovery-endpoint
// work from apr 2026: /robots.txt + /openapi.json no longer 401, and both
// apex + per-subdomain /.well-known/mpp serve valid manifests.
//
// Run: bun test tests/discovery-staging.test.ts

const STAGING = "https://staging.apimesh.xyz";
const TIMEOUT = 10_000;

async function get(url: string, headers: Record<string, string> = {}) {
  return fetch(url, { headers, signal: AbortSignal.timeout(TIMEOUT) });
}

describe("staging /robots.txt", () => {
  test("returns 200 with text/plain", async () => {
    const res = await get(`${STAGING}/robots.txt`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/plain");
  });

  test("body includes User-agent + Sitemap", async () => {
    const res = await get(`${STAGING}/robots.txt`);
    const body = await res.text();
    expect(body).toContain("User-agent:");
    expect(body).toContain("Sitemap:");
  });

  test("is NOT 401 Unauthorized (apr 2026 regression guard)", async () => {
    const res = await get(`${STAGING}/robots.txt`);
    expect(res.status).not.toBe(401);
  });
});

describe("staging /openapi.json", () => {
  test("returns 200 JSON", async () => {
    const res = await get(`${STAGING}/openapi.json`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("json");
  });

  test("is a valid OpenAPI 3.1 root doc", async () => {
    const res = await get(`${STAGING}/openapi.json`);
    const doc: any = await res.json();
    expect(doc.openapi).toMatch(/^3\.1/);
    expect(doc.info?.title).toBe("APIMesh");
    expect(Array.isArray(doc.servers)).toBe(true);
    expect(doc.servers.length).toBeGreaterThan(10);
    expect(doc["x-apimesh-apis"]).toBeDefined();
  });

  test("is NOT 401 Unauthorized", async () => {
    const res = await get(`${STAGING}/openapi.json`);
    expect(res.status).not.toBe(401);
  });
});

describe("staging apex /.well-known/mpp", () => {
  test("returns 200 JSON", async () => {
    const res = await get(`${STAGING}/.well-known/mpp`);
    expect(res.status).toBe(200);
  });

  test("has required platform-manifest fields", async () => {
    const res = await get(`${STAGING}/.well-known/mpp`);
    const m: any = await res.json();
    expect(m.name).toBe("APIMesh");
    expect(m.provider?.url).toBeDefined();
    expect(Array.isArray(m.payment_methods)).toBe(true);
    expect(m.payment_methods.length).toBeGreaterThanOrEqual(3);
    expect(m.discovery?.openapi).toContain("/openapi.json");
    expect(Array.isArray(m.apis)).toBe(true);
    expect(m.apis.length).toBeGreaterThan(10);
    expect(m.api_count).toBe(m.apis.length);
  });

  test("every api entry has endpoint + price_usd + category", async () => {
    const res = await get(`${STAGING}/.well-known/mpp`);
    const m: any = await res.json();
    for (const api of m.apis.slice(0, 5)) {
      expect(typeof api.name).toBe("string");
      expect(api.endpoint).toMatch(/^https:\/\//);
      expect(typeof api.price_usd).toBe("number");
      expect(api.price_usd).toBeGreaterThan(0);
      expect(typeof api.category).toBe("string");
    }
  });
});

describe("staging per-subdomain /.well-known/mpp", () => {
  test("email-verify subdomain returns per-api manifest", async () => {
    const res = await get(`https://email-verify.staging.apimesh.xyz/.well-known/mpp`);
    expect(res.status).toBe(200);
    const m: any = await res.json();
    expect(m.name).toBe("email-verify");
    expect(m.api?.endpoint).toContain("email-verify");
    expect(m.discovery?.platform_manifest).toContain("/.well-known/mpp");
  });

  test("unknown subdomain returns 404", async () => {
    const res = await get(`https://not-a-real-api-xyz.staging.apimesh.xyz/.well-known/mpp`);
    expect(res.status).toBe(404);
  });

  test("existing /.well-known/x402 not regressed", async () => {
    const res = await get(`https://email-verify.staging.apimesh.xyz/.well-known/x402`);
    expect(res.status).toBe(200);
    const m: any = await res.json();
    expect(m.version).toBe(1);
    expect(Array.isArray(m.resources)).toBe(true);
  });
});

describe("staging 4-path crawler sequence (observed apr 2026)", () => {
  // Replay the exact 4-path discovery sequence the MPP crawler ran on apr 21.
  // All four must return 200 now.
  const paths = ["/.well-known/mpp", "/openapi.json", "/llms.txt", "/"];

  for (const path of paths) {
    test(`${path} returns 200`, async () => {
      const res = await get(`${STAGING}${path}`);
      expect(res.status).toBe(200);
    });
  }
});
