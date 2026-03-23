import { lookupByHash } from "./api-key";
import { deductAndRecord, getBalance } from "./credits";
import { INTERNAL_AUTH_SECRET } from "./x402";
import db from "./db";

// Prices in microdollars (1 USD = 100,000 microdollars)
// Must match the per-API PRICE constants in each API's index.ts
export const API_PRICES: Record<string, number> = {
  "check":                       500,   // web-checker $0.005
  "http-status-checker":         200,   // $0.002
  "favicon-checker":             200,   // $0.002
  "microservice-health-check":   300,   // $0.003
  "status-code-checker":         200,   // $0.002
  "regex-builder":               200,   // $0.002
  "user-agent-analyzer":         200,   // $0.002
  "robots-txt-parser":           200,   // $0.002
  "mock-jwt-generator":          100,   // $0.001
  "yaml-validator":              200,   // $0.002
  "swagger-docs-creator":        200,   // $0.002
  "core-web-vitals":             500,   // $0.005
  "security-headers":            500,   // $0.005
  "redirect-chain":              100,   // $0.001
  "email-security":              1000,  // $0.01
  "seo-audit":                   300,   // $0.003
  "indexability":                100,   // $0.001
  "brand-assets":                200,   // $0.002
  "email-verify":                100,   // $0.001
  "tech-stack":                  300,   // $0.003
};

/**
 * API key authentication middleware for the router.
 * Checks for Bearer sk_live_... token, validates key, deducts credits.
 *
 * Returns:
 * - Response: error (401 invalid key, 402 insufficient credits) or success (forwarded response with X-Credits-Remaining)
 * - null: no Bearer token present, fall through to x402
 */
export async function apiKeyAuth(
  req: Request,
  subdomain: string,
  paidPaths: string[] | undefined,
  subApp: { fetch: (req: Request) => Promise<Response> }
): Promise<Response | null> {
  // 1. Check for Bearer token
  const authHeader = req.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;

  const token = authHeader.slice(7);
  if (!token.startsWith("sk_live_")) return null; // Not an APIMesh key — fall through

  // 2. Validate key
  const keyInfo = lookupByHash(db, token);
  if (!keyInfo) {
    return Response.json(
      { error: "Invalid or revoked API key" },
      { status: 401, headers: { "Content-Type": "application/json" } }
    );
  }

  // 3. Check if this is a paid path
  const url = new URL(req.url);
  const isPaid = paidPaths?.some(route => {
    const parts = route.split(" ");
    return parts.length === 2 && req.method === parts[0] && url.pathname === parts[1];
  }) ?? false;

  if (!isPaid) {
    // Free endpoint (preview, health, info) — forward without deduction
    const forwardHeaders = new Headers(req.headers);
    forwardHeaders.delete("authorization"); // sub-app doesn't need the raw key
    forwardHeaders.set("X-APIMesh-Internal", INTERNAL_AUTH_SECRET);
    forwardHeaders.set("X-APIMesh-User-Id", keyInfo.user_id);
    forwardHeaders.set("X-APIMesh-Key-Id", keyInfo.id);
    const modifiedReq = new Request(req, { headers: forwardHeaders });
    const response = await subApp.fetch(modifiedReq);
    // Strip internal header from response
    const cleanResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: new Headers(response.headers),
    });
    cleanResponse.headers.delete("x-apimesh-internal");
    return cleanResponse;
  }

  // 4. Look up pricing
  const cost = API_PRICES[subdomain];
  if (!cost) {
    // Unknown API pricing — shouldn't happen, but fall through to x402 as safety net
    console.warn(`[api-key-auth] No pricing found for subdomain: ${subdomain}`);
    return null;
  }

  // 5. Deduct credits atomically
  const result = deductAndRecord(db, keyInfo.user_id, cost, `${subdomain} API call`, keyInfo.id, subdomain);

  if (!result.success) {
    const balance = getBalance(db, keyInfo.user_id);
    return Response.json(
      {
        error: "Insufficient credits",
        balance_microdollars: balance,
        cost_microdollars: cost,
        topup_url: "https://apimesh.xyz/account/billing",
      },
      { status: 402, headers: { "Content-Type": "application/json" } }
    );
  }

  // 6. Forward request to sub-app with internal auth bypass header
  const forwardHeaders = new Headers(req.headers);
  forwardHeaders.delete("authorization"); // sub-app doesn't need the raw key
  forwardHeaders.set("X-APIMesh-Internal", INTERNAL_AUTH_SECRET);
  forwardHeaders.set("X-APIMesh-User-Id", keyInfo.user_id);
  forwardHeaders.set("X-APIMesh-Key-Id", keyInfo.id);
  const modifiedReq = new Request(req, { headers: forwardHeaders });

  const response = await subApp.fetch(modifiedReq);

  // 7. Add X-Credits-Remaining header to response, strip internal header
  const newResponse = new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: new Headers(response.headers),
  });
  newResponse.headers.delete("x-apimesh-internal");
  newResponse.headers.set("X-Credits-Remaining", String(result.newBalance));
  newResponse.headers.set("X-Auth-Method", "api-key");

  return newResponse;
}
