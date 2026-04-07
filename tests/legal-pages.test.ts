import { test, expect, describe } from "bun:test";

describe("Legal pages", () => {
  const LEGAL_PAGES = [
    { slug: "terms", title: "Terms of Service" },
    { slug: "privacy", title: "Privacy Policy" },
    { slug: "acceptable-use", title: "Acceptable Use" },
    { slug: "refund", title: "Refund" },
    { slug: "cookies", title: "Cookie" },
    { slug: "abuse", title: "Abuse" },
  ];

  // LEGAL-01 through LEGAL-06: Each page file exists and has required structure
  for (const page of LEGAL_PAGES) {
    test(`${page.slug} page exists with correct structure`, async () => {
      const file = Bun.file(`apis/landing/legal/${page.slug}.html`);
      expect(await file.exists()).toBe(true);
      const html = await file.text();
      expect(html).toContain(page.title);
      expect(html).toContain("legal-content");
      expect(html).toContain("Effective");
      expect(html).toContain('href="/"');
    });
  }

  // LEGAL-07: Each page has TL;DR box
  for (const page of LEGAL_PAGES) {
    test(`${page.slug} page has TL;DR box with at least 3 bullets`, async () => {
      const html = await Bun.file(`apis/landing/legal/${page.slug}.html`).text();
      expect(html).toContain("tldr-box");
      // At least 3 list items in TL;DR
      const tldrMatch = html.match(/class="tldr-box"[\s\S]*?<\/div>/);
      expect(tldrMatch).not.toBeNull();
      const liCount = (tldrMatch![0].match(/<li>/g) || []).length;
      expect(liCount).toBeGreaterThanOrEqual(3);
    });
  }

  // Design system consistency
  for (const page of LEGAL_PAGES) {
    test(`${page.slug} page uses APIMesh design system`, async () => {
      const html = await Bun.file(`apis/landing/legal/${page.slug}.html`).text();
      expect(html).toContain("--bg");
      expect(html).toContain("--accent");
      expect(html).toContain("--mono");
    });
  }
});

describe("Legal footer", () => {
  const PUBLIC_PAGES = [
    "landing", "signup", "login", "account", "billing",
    "keys", "settings", "forgot-password", "changelog", "verify",
  ];

  for (const page of PUBLIC_PAGES) {
    test(`${page}.html has legal footer links`, async () => {
      const html = await Bun.file(`apis/landing/${page}.html`).text();
      expect(html).toContain("/legal/terms");
      expect(html).toContain("/legal/privacy");
      expect(html).toContain("/legal/abuse");
    });
  }
});

describe("Legal routes", () => {
  test("index.ts registers legal page routes", async () => {
    const ts = await Bun.file("apis/dashboard/index.ts").text();
    expect(ts).toContain("LEGAL_PAGES");
    expect(ts).toContain("/legal/");
    expect(ts).toContain("Cache-Control");
    expect(ts).toContain("max-age=86400");
  });
});
