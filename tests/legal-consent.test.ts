import { test, expect, describe } from "bun:test";

describe("Signup consent", () => {
  // LEGAL-08: Signup form has consent checkbox
  test("signup.html has ToS consent checkbox", async () => {
    const html = await Bun.file("apis/landing/signup.html").text();
    expect(html).toContain('id="tos-agree"');
    expect(html).toContain("/legal/terms");
    expect(html).toContain("/legal/privacy");
  });

  // LEGAL-08: auth.js sends tos_agree
  test("auth.js includes tos_agree in signup payload", async () => {
    const js = await Bun.file("apis/landing/auth.js").text();
    expect(js).toContain("tos_agree");
    expect(js).toContain("tos-agree");
  });

  // LEGAL-08: Server enforces tos_agree
  test("signup handler checks tos_agree", async () => {
    const ts = await Bun.file("apis/dashboard/index.ts").text();
    expect(ts).toContain("tos_agree");
    expect(ts).toContain("tos_accepted_at");
  });

  // LEGAL-08: Migration exists
  test("migration 007 adds tos_accepted_at column", async () => {
    const sql = await Bun.file("data/migrations/007_tos_accepted.sql").text();
    expect(sql).toContain("tos_accepted_at");
    expect(sql.toLowerCase()).toContain("alter table users");
  });
});

describe("Stripe refund text", () => {
  // LEGAL-09: Stripe checkout includes refund acknowledgment
  test("createCheckoutSession includes custom_text for refund policy", async () => {
    const ts = await Bun.file("shared/stripe.ts").text();
    expect(ts).toContain("custom_text[submit][message]");
    expect(ts).toContain("non-refundable");
    expect(ts).toContain("apimesh.xyz/legal/refund");
  });
});
