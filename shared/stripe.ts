import { createHmac, timingSafeEqual } from "crypto";

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_API_BASE = "https://api.stripe.com/v1";
const BASE_URL = process.env.NODE_ENV === "staging"
  ? "https://staging.apimesh.xyz"
  : "https://apimesh.xyz";

export const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";

if (process.env.NODE_ENV === "production" && !STRIPE_SECRET_KEY) {
  console.error("FATAL: STRIPE_SECRET_KEY must be set in production");
  process.exit(1);
}

if (process.env.NODE_ENV === "production" && !STRIPE_WEBHOOK_SECRET) {
  console.error("FATAL: STRIPE_WEBHOOK_SECRET must be set in production");
  process.exit(1);
}

if (!STRIPE_SECRET_KEY) {
  console.warn("[stripe] STRIPE_SECRET_KEY not configured — Stripe features disabled in development.");
}

export interface CreditTier {
  price: number;       // in cents (for Stripe unit_amount)
  credits: number;     // in microdollars
  bonus: number;       // percentage (0, 10, 20, 30)
  label: string;       // display name
}

export const CREDIT_TIERS: Record<string, CreditTier> = {
  starter:  { price: 500,   credits: 500_000,    bonus: 0,  label: "Starter" },
  builder:  { price: 2000,  credits: 2_200_000,  bonus: 10, label: "Builder" },
  pro:      { price: 5000,  credits: 6_000_000,  bonus: 20, label: "Pro" },
  scale:    { price: 10000, credits: 13_000_000, bonus: 30, label: "Scale" },
};

/**
 * Create a Stripe Checkout session for a credit purchase.
 * Returns the hosted checkout page URL on success.
 */
export async function createCheckoutSession(
  userId: string,
  email: string,
  tier: string
): Promise<{ url: string } | { error: string }> {
  const tierConfig = CREDIT_TIERS[tier];
  if (!tierConfig) return { error: "Invalid tier" };

  if (!STRIPE_SECRET_KEY) {
    return { error: "Stripe is not configured" };
  }

  const params = new URLSearchParams();
  params.set("mode", "payment");
  params.set("success_url", `${BASE_URL}/account/billing?billing=success`);
  params.set("cancel_url", `${BASE_URL}/account/billing?billing=cancelled`);
  params.set("customer_email", email);
  params.set("line_items[0][price_data][currency]", "usd");
  params.set("line_items[0][price_data][product_data][name]", `APIMesh Credits — ${tierConfig.label}`);
  params.set("line_items[0][price_data][unit_amount]", String(tierConfig.price));
  params.set("line_items[0][quantity]", "1");
  params.set("metadata[user_id]", userId);
  params.set("metadata[tier]", tier);
  params.set("metadata[credits_amount]", String(tierConfig.credits));
  params.set("custom_text[submit][message]",
    "By completing this purchase, you acknowledge that APIMesh credits are non-refundable prepaid credits. See our Refund Policy at https://apimesh.xyz/legal/refund for details.");

  try {
    const res = await fetch(`${STRIPE_API_BASE}/checkout/sessions`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${STRIPE_SECRET_KEY}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });

    const data = await res.json();
    if (!res.ok) {
      console.error("[stripe] Checkout session error:", data.error?.message);
      return { error: data.error?.message || "Failed to create checkout session" };
    }

    // Validate Stripe URL before returning to client
    if (!data.url || !data.url.startsWith("https://checkout.stripe.com/")) {
      console.error("[stripe] Unexpected checkout URL:", data.url);
      return { error: "Invalid checkout URL received from Stripe" };
    }
    return { url: data.url };
  } catch (err: any) {
    console.error("[stripe] Checkout session fetch error:", err.message);
    return { error: "Failed to connect to Stripe" };
  }
}

/**
 * Verify Stripe webhook signature using HMAC-SHA256.
 * Rejects events older than 5 minutes (300 seconds).
 * Uses timing-safe comparison to prevent side-channel attacks.
 */
export function verifyWebhookSignature(
  rawBody: string,
  signatureHeader: string,
  secret: string
): boolean {
  const parts = signatureHeader.split(",");
  const timestampStr = parts.find(p => p.startsWith("t="))?.slice(2);
  const signatureHex = parts.find(p => p.startsWith("v1="))?.slice(3);

  if (!timestampStr || !signatureHex) return false;

  const timestamp = parseInt(timestampStr, 10);
  if (isNaN(timestamp)) return false;

  // Reject events older than 5 minutes
  const age = Math.abs(Math.floor(Date.now() / 1000) - timestamp);
  if (age > 300) return false;

  // Compute expected signature
  const payload = `${timestamp}.${rawBody}`;
  const expected = createHmac("sha256", secret).update(payload).digest("hex");

  // Timing-safe comparison (convert to buffers of same length)
  try {
    const sigBuf = Buffer.from(signatureHex, "hex");
    const expBuf = Buffer.from(expected, "hex");
    if (sigBuf.length !== expBuf.length) return false;
    return timingSafeEqual(sigBuf, expBuf);
  } catch {
    return false;
  }
}
