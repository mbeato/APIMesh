/**
 * Extract payer identity from MPP payment credentials.
 * Analogous to shared/x402-wallet.ts for x402 payments.
 */

/**
 * Parse payer identity from an MPP Authorization header.
 * MPP credentials use "Authorization: Payment <base64>" scheme.
 * The `source` field contains a DID like "did:pkh:eip155:1:0x..." for crypto,
 * or the Stripe customer ID is embedded in the receipt.
 *
 * Returns a string identifier for the payer, or null if not extractable.
 */
export function parseMppPayerFromAuth(authHeader: string | undefined): string | null {
  if (!authHeader) return null;

  // MPP uses "Payment <base64>" scheme in the Authorization header
  const match = authHeader.match(/^Payment\s+(.+)$/i);
  if (!match?.[1]) return null;

  try {
    // Decode the base64 credential
    const json = Buffer.from(match[1], "base64url").toString("utf-8");
    const parsed = JSON.parse(json);

    // source is a DID string like "did:pkh:eip155:1:0x..."
    if (parsed?.source && typeof parsed.source === "string") {
      return `mpp:${parsed.source}`;
    }

    // Fall back to challenge method for identification
    const method = parsed?.challenge?.method;
    if (method === "stripe") {
      // For Stripe, we won't have the customer ID until after verification,
      // but we can use the challenge ID as a correlation key
      return null;
    }
  } catch {
    // Invalid base64 or JSON — not an MPP credential
  }

  return null;
}

/**
 * Extract payer identity from an MPP Payment-Receipt response header.
 * The receipt contains the payment reference (e.g., Stripe PaymentIntent ID).
 */
export function parseMppPayerFromReceipt(receiptHeader: string | undefined): string | null {
  if (!receiptHeader) return null;

  try {
    const parsed = JSON.parse(Buffer.from(receiptHeader, "base64url").toString("utf-8"));

    // Stripe receipts have reference like "pi_xxx"
    if (parsed?.method === "stripe" && parsed?.reference) {
      return `stripe:${parsed.reference}`;
    }

    // Tempo receipts have a transaction hash reference
    if (parsed?.method === "tempo" && parsed?.reference) {
      return `tempo:${parsed.reference}`;
    }
  } catch {
    // Not valid receipt format
  }

  return null;
}
