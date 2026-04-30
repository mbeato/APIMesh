import type { MiddlewareHandler } from "hono";
import { logRequest, logRevenue } from "./db";
import { NETWORK } from "./x402";
import { parseMppPayerFromReceipt } from "./mpp-wallet";

function sanitizeLogField(value: string, maxLen = 512): string {
  return value.replace(/[\r\n\t\x00-\x1f\x7f]/g, " ").slice(0, maxLen);
}

export function apiLogger(apiName: string, priceUsd: number = 0): MiddlewareHandler {
  return async (c, next) => {
    const start = performance.now();
    await next();
    const ms = performance.now() - start;

    // x402 sets PAYMENT-RESPONSE header after successful settlement
    const paymentResponse = c.res.headers.get("PAYMENT-RESPONSE") || c.res.headers.get("X-PAYMENT-RESPONSE");
    const x402Paid = !!paymentResponse && c.res.status < 400;

    // MPP sets Payment-Receipt header after successful payment verification
    const mppReceipt = c.res.headers.get("Payment-Receipt");
    const mppPaid = !!mppReceipt && c.res.status < 400;

    // API key auth sets X-APIMesh-Paid header with USD amount when credits were deducted
    const apiKeyPaidHeader = c.req.header("x-apimesh-paid");
    const apiKeyPaid = !!apiKeyPaidHeader && c.res.status < 400;
    const apiKeyAmount = apiKeyPaid ? parseFloat(apiKeyPaidHeader!) : 0;

    const paid = x402Paid || mppPaid || apiKeyPaid;
    const amount = x402Paid ? priceUsd : (mppPaid ? priceUsd : (apiKeyPaid ? apiKeyAmount : 0));

    // Trust x-real-ip set by Caddy — "direct" means request bypassed proxy
    const clientIp = sanitizeLogField(c.req.header("x-real-ip") || "direct");
    const path = sanitizeLogField(c.req.path);
    const uaRaw = c.req.header("user-agent");
    const userAgent = uaRaw ? sanitizeLogField(uaRaw, 256) : undefined;

    // Payer wallet set by extractPayerWallet() middleware
    const payerWallet: string | undefined = c.get("payerWallet");

    // API key auth context — set by apiKeyAuth() on forwarded requests
    const userId = c.req.header("x-apimesh-user-id") || undefined;
    const apiKeyId = c.req.header("x-apimesh-key-id") || undefined;

    // Traffic attribution: where did this request come from?
    // Strip query string + fragment from the Referer URL to avoid persisting
    // accidental bearer tokens / session params from the upstream page's URL.
    // (SECURITY-AUDIT M2.) Modern browsers usually strip these via Referer-Policy,
    // but we don't trust client behavior — store only origin + pathname.
    const refererRaw = c.req.header("referer") || c.req.header("referrer");
    let referer: string | undefined;
    if (refererRaw) {
      try {
        const r = new URL(refererRaw);
        referer = sanitizeLogField(r.origin + r.pathname, 512);
      } catch {
        // Malformed referer — skip rather than store a junk value.
      }
    }
    let utmSource: string | undefined;
    let utmMedium: string | undefined;
    let utmCampaign: string | undefined;
    try {
      const reqUrl = new URL(c.req.url);
      const u = reqUrl.searchParams.get("utm_source");
      const m = reqUrl.searchParams.get("utm_medium");
      const cmp = reqUrl.searchParams.get("utm_campaign");
      if (u) utmSource = sanitizeLogField(u, 128);
      if (m) utmMedium = sanitizeLogField(m, 128);
      if (cmp) utmCampaign = sanitizeLogField(cmp, 128);
    } catch {
      // Malformed URL — skip UTM extraction silently
    }

    logRequest(
      apiName, path, c.req.method, c.res.status, ms,
      paid, amount, clientIp, payerWallet, userId, apiKeyId, userAgent,
      { referer, utmSource, utmMedium, utmCampaign }
    );

    if (paid && amount > 0) {
      if (x402Paid) {
        // x402 settlement — extract txHash from PAYMENT-RESPONSE
        let txHash = "";
        try {
          const decoded = Buffer.from(paymentResponse!, "base64").toString("utf-8");
          const settlement = JSON.parse(decoded);
          txHash = settlement?.transaction ?? settlement?.txHash ?? "";
        } catch {
          // Settlement header may not be base64 JSON — log without txHash
        }
        logRevenue(apiName, amount, txHash, NETWORK, payerWallet);
      } else if (mppPaid) {
        // MPP payment — extract reference from Payment-Receipt
        let reference = "";
        let mppMethod = "mpp";
        try {
          const decoded = Buffer.from(mppReceipt!, "base64url").toString("utf-8");
          const receipt = JSON.parse(decoded);
          reference = receipt?.reference ?? "";
          mppMethod = receipt?.method === "stripe" ? "mpp-stripe" : (receipt?.method === "tempo" ? "mpp-tempo" : "mpp");
        } catch {
          // Receipt may not be parseable — log without reference
        }
        const mppPayer = parseMppPayerFromReceipt(mppReceipt!) ?? payerWallet;
        logRevenue(apiName, amount, reference, mppMethod, mppPayer);
      } else if (apiKeyPaid) {
        // API key credit deduction — log with network="credits"
        logRevenue(apiName, amount, "", "credits", undefined);
      }
    }
  };
}
