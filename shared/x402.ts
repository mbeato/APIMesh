import { paymentMiddleware as _rawPaymentMiddleware, x402ResourceServer } from "@x402/hono";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { MPP_ENABLED, mppInstance, mppChargeMiddleware } from "./mpp";

const WALLET_ADDRESS_RAW = process.env.WALLET_ADDRESS;
if (!WALLET_ADDRESS_RAW) {
  console.error("FATAL: WALLET_ADDRESS env var not set");
  process.exit(1);
}
if (!/^0x[0-9a-fA-F]{40}$/.test(WALLET_ADDRESS_RAW)) {
  console.error("FATAL: WALLET_ADDRESS is not a valid EVM address");
  process.exit(1);
}
export const WALLET_ADDRESS = WALLET_ADDRESS_RAW;

const CDP_KEY_ID = process.env.CDP_API_KEY_ID;
const CDP_KEY_SECRET = process.env.CDP_API_KEY_SECRET;

// Partial CDP key config is almost certainly a mistake — fail loudly
if (!!CDP_KEY_ID !== !!CDP_KEY_SECRET) {
  console.error(
    `FATAL: Partial CDP key configuration. ` +
    `CDP_API_KEY_ID is ${CDP_KEY_ID ? "set" : "MISSING"}, ` +
    `CDP_API_KEY_SECRET is ${CDP_KEY_SECRET ? "set" : "MISSING"}. ` +
    `Both must be set for mainnet, or both omitted for testnet.`
  );
  process.exit(1);
}

const USE_MAINNET = !!CDP_KEY_ID && !!CDP_KEY_SECRET;

export const NETWORK = USE_MAINNET ? "eip155:8453" : "eip155:84532";

async function buildCdpFacilitator() {
  const { generateJwt } = await import("@coinbase/cdp-sdk/auth");

  const makeAuthHeaders = async (method: string, path: string) => {
    const jwt = await generateJwt({
      apiKeyId: CDP_KEY_ID!,
      apiKeySecret: CDP_KEY_SECRET!,
      requestMethod: method,
      requestHost: "api.cdp.coinbase.com",
      requestPath: path,
    });
    return { Authorization: `Bearer ${jwt}` };
  };

  return new HTTPFacilitatorClient({
    url: "https://api.cdp.coinbase.com/platform/v2/x402",
    createAuthHeaders: async () => ({
      verify: await makeAuthHeaders("POST", "/platform/v2/x402/verify"),
      settle: await makeAuthHeaders("POST", "/platform/v2/x402/settle"),
      supported: await makeAuthHeaders("GET", "/platform/v2/x402/supported"),
    }),
  });
}

function buildTestnetFacilitator() {
  return new HTTPFacilitatorClient({
    url: "https://www.x402.org/facilitator",
  });
}

let facilitatorClient: HTTPFacilitatorClient;
if (USE_MAINNET) {
  try {
    facilitatorClient = await buildCdpFacilitator();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`FATAL: CDP facilitator init failed: ${message}`);
    process.exit(1);
  }
} else {
  facilitatorClient = buildTestnetFacilitator();
}

export const resourceServer = new x402ResourceServer(facilitatorClient)
  .register(NETWORK, new ExactEvmScheme());

console.log(`x402: ${USE_MAINNET ? "MAINNET (Base)" : "TESTNET (Base Sepolia)"}`);
console.log(`x402: payTo=${WALLET_ADDRESS}`);

export function paidRoute(price: string, description: string) {
  return {
    accepts: [
      {
        scheme: "exact" as const,
        price,
        network: NETWORK,
        payTo: WALLET_ADDRESS,
      },
    ],
    description,
    mimeType: "application/json",
  };
}

interface DiscoveryConfig {
  input: Record<string, unknown>;
  inputSchema: Record<string, unknown>;
  output?: { example: Record<string, unknown> };
  bodyType?: "json";
}

export function paidRouteWithDiscovery(price: string, description: string, discovery: DiscoveryConfig) {
  return {
    ...paidRoute(price, description),
    extensions: {
      ...declareDiscoveryExtension(discovery),
    },
  };
}

// Internal auth bypass secret — generated at startup, used by api-key-auth middleware
// to skip x402 payment for API-key-authenticated requests
export const INTERNAL_AUTH_SECRET = crypto.randomUUID();

// Wrap paymentMiddleware to support internal auth bypass + MPP dual-rail
export function paymentMiddleware(routes: any, server: any) {
  const x402Middleware = _rawPaymentMiddleware(routes, server);

  // Pre-compute MPP charge middlewares for each route (if MPP enabled)
  // routes is Record<"METHOD /path", { accepts: [...], ... }>
  const mppMiddlewares = new Map<string, ReturnType<typeof mppChargeMiddleware>>();
  if (MPP_ENABLED && mppInstance) {
    for (const [routeKey, config] of Object.entries(routes)) {
      const price = (config as any)?.accepts?.[0]?.price;
      if (price) {
        mppMiddlewares.set(routeKey, mppChargeMiddleware(price));
      }
    }
  }

  return async (c: any, next: any) => {
    // 1. Internal auth bypass (API key credits) — skip all payment
    const internalAuth = c.req.header("x-apimesh-internal");
    if (internalAuth === INTERNAL_AUTH_SECRET) {
      return next();
    }

    // 2. MPP payment — check for "Authorization: Payment ..." header
    if (MPP_ENABLED && mppInstance) {
      const authHeader = c.req.header("authorization") || "";
      const hasPaymentScheme = /^Payment\s+/i.test(authHeader) ||
        authHeader.split(",").some((s: string) => /^Payment\s+/i.test(s.trim()));

      if (hasPaymentScheme) {
        // Find the matching MPP middleware for this route
        const method = c.req.method;
        const path = new URL(c.req.url).pathname;
        const routeKey = `${method} ${path}`;
        const mppMw = mppMiddlewares.get(routeKey);

        if (mppMw) {
          // Use the mppx Hono payment middleware directly
          return mppMw(c, next);
        }
        // If no MPP middleware for this route, fall through to x402
      }
    }

    // 3. Default: x402 payment flow
    return x402Middleware(c, next);
  };
}
