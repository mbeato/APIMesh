import { test, expect, describe } from "bun:test";

describe("MPP Tempo integration", () => {
  test("mppx exports tempo with charge method", () => {
    const { tempo } = require("mppx/hono");
    expect(tempo).toBeDefined();
    expect(typeof tempo.charge).toBe("function");
  });

  test("tempo.charge() returns a method with name 'tempo'", () => {
    const { tempo } = require("mppx/hono");
    const method = tempo.charge({ recipient: "0x52e5B77b02F115FD7fC2D7E740971AEa85880808" });
    expect(method).toBeDefined();
    expect(method.name).toBe("tempo");
  });

  test("Mppx.create with stripe + tempo.charge exposes both methods", () => {
    const { Mppx, stripe, tempo } = require("mppx/hono");
    const instance = Mppx.create({
      methods: [
        stripe({
          secretKey: "sk_test_fake_key_for_testing",
          currency: "usd",
          decimals: 2,
          networkId: "internal",
          paymentMethodTypes: ["card"],
        }),
        tempo.charge({
          recipient: "0x52e5B77b02F115FD7fC2D7E740971AEa85880808",
        }),
      ],
      secretKey: "test-secret-key-for-mpp-testing-only",
      realm: "apimesh.xyz",
    });
    expect(instance).toBeDefined();
    expect(instance.stripe).toBeDefined();
    expect(instance.tempo).toBeDefined();
    expect(typeof instance.stripe.charge).toBe("function");
    expect(typeof instance.tempo.charge).toBe("function");
  });

  test("stripe.charge creates valid middleware", () => {
    const { Mppx, stripe, tempo } = require("mppx/hono");
    const instance = Mppx.create({
      methods: [
        stripe({
          secretKey: "sk_test_fake_key_for_testing",
          currency: "usd",
          decimals: 2,
          networkId: "internal",
          paymentMethodTypes: ["card"],
        }),
        tempo.charge({
          recipient: "0x52e5B77b02F115FD7fC2D7E740971AEa85880808",
        }),
      ],
      secretKey: "test-secret-key-for-mpp-testing-only",
      realm: "apimesh.xyz",
    });
    const middleware = instance.stripe.charge({
      amount: "500",
      description: "Test charge",
    });
    expect(middleware).toBeDefined();
    expect(typeof middleware).toBe("function");
  });

  test("mpp.ts module loads with Tempo enabled", async () => {
    process.env.MPP_ENABLED = "true";
    process.env.MPP_SECRET_KEY = "test-secret-key-for-mpp-testing-only";
    process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_testing";
    process.env.WALLET_ADDRESS = "0x52e5B77b02F115FD7fC2D7E740971AEa85880808";

    const mod = await import("../shared/mpp");
    expect(mod.MPP_ENABLED).toBe(true);
    expect(mod.mppInstance).toBeDefined();

    const mw = mod.mppChargeMiddleware("$0.005");
    expect(mw).toBeDefined();
    expect(typeof mw).toBe("function");
  });
});

describe("staging HTTP checks", () => {
  const STAGING = "https://staging.apimesh.xyz";

  test("staging health returns 200", async () => {
    const res = await fetch(`${STAGING}/health`, { signal: AbortSignal.timeout(10_000) });
    expect(res.status).toBe(200);
  });

  test("staging landing loads with logo", async () => {
    const res = await fetch(STAGING, { signal: AbortSignal.timeout(10_000) });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("APIMesh");
    expect(html).toContain("logo-nav.svg");
  });

  test("staging logo-nav.svg serves correctly", async () => {
    const res = await fetch(`${STAGING}/logo-nav.svg`, { signal: AbortSignal.timeout(10_000) });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("svg");
  });
});
