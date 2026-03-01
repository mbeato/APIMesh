import type { MiddlewareHandler } from "hono";
import { logRequest, logRevenue } from "./db";
import { NETWORK } from "./x402";

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
    const paid = !!paymentResponse && c.res.status < 400;
    const amount = paid ? priceUsd : 0;

    // Trust x-real-ip set by Caddy — "direct" means request bypassed proxy
    const clientIp = sanitizeLogField(c.req.header("x-real-ip") || "direct");
    const path = sanitizeLogField(c.req.path);

    logRequest(apiName, path, c.req.method, c.res.status, ms, paid, amount, clientIp);

    if (paid && amount > 0) {
      // Attempt to extract txHash from settlement response
      let txHash = "";
      try {
        const decoded = Buffer.from(paymentResponse!, "base64").toString("utf-8");
        const settlement = JSON.parse(decoded);
        txHash = settlement?.transaction ?? settlement?.txHash ?? "";
      } catch {
        // Settlement header may not be base64 JSON — log without txHash
      }
      logRevenue(apiName, amount, txHash, NETWORK);
    }
  };
}
