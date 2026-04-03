/**
 * MPP (Machine Payments Protocol) integration via mppx.
 *
 * Provides Stripe card payments alongside existing x402 crypto payments.
 * Controlled by MPP_ENABLED env flag for zero-downtime rollback.
 */

import { Mppx, stripe, tempo } from "mppx/hono";
import * as Store from "mppx/server";

// Feature flag — when false, MPP is completely disabled
export const MPP_ENABLED = process.env.MPP_ENABLED === "true";

// Secret key for HMAC-bound challenge IDs (stateless verification)
function resolveSecretKey(): string {
  const key = process.env.MPP_SECRET_KEY;
  if (key) return key;

  if (process.env.NODE_ENV === "production") {
    console.error("FATAL: MPP_SECRET_KEY must be set in production");
    process.exit(1);
  }

  // Dev only — generate ephemeral key (challenges won't survive restarts)
  const devKey = crypto.randomUUID() + crypto.randomUUID();
  console.warn("mpp: using ephemeral secret key (dev only)");
  return devKey;
}

// Stripe secret key — reuse the existing one from .env
function resolveStripeKey(): string {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) {
    if (process.env.NODE_ENV === "production") {
      console.error("FATAL: STRIPE_SECRET_KEY required for MPP Stripe integration");
      process.exit(1);
    }
    return "";
  }
  return key;
}

// Only initialize if enabled
let mppInstance: ReturnType<typeof Mppx.create<any>> | null = null;

if (MPP_ENABLED) {
  const secretKey = resolveSecretKey();
  const stripeSecretKey = resolveStripeKey();

  mppInstance = Mppx.create({
    methods: [
      stripe({
        secretKey: stripeSecretKey,
        currency: "usd",
        decimals: 2,
        networkId: "internal",
        paymentMethodTypes: ["card"],
      }),
      tempo.charge({
        recipient: process.env.WALLET_ADDRESS,
      }),
    ],
    secretKey,
    realm: process.env.MPP_REALM ?? "apimesh.xyz",
  });

  console.log("mpp: enabled (Stripe charge + Tempo stablecoin)");
} else {
  console.log("mpp: disabled (MPP_ENABLED != true)");
}

export { mppInstance };

/**
 * Create an MPP charge middleware for a given price.
 *
 * @param priceUsd - Price string like "$0.005" or "0.005"
 * @returns Hono MiddlewareHandler that gates on MPP payment, or null if MPP disabled
 */
export function mppChargeMiddleware(priceUsd: string) {
  if (!mppInstance) return null;

  // Strip $ prefix and convert to cents (Stripe uses smallest currency unit)
  const numeric = priceUsd.replace(/^\$/, "");
  const cents = Math.round(parseFloat(numeric) * 100);

  // Use stripe.charge to create the middleware — mppx advertises ALL configured
  // payment methods (Stripe + Tempo) in the 402 challenge automatically.
  // Amount is in smallest currency unit (cents for Stripe).
  return mppInstance.stripe.charge({
    amount: String(cents),
    description: `APIMesh API call ($${numeric})`,
  });
}
