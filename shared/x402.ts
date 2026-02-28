import { paymentMiddleware, x402ResourceServer } from "@x402/hono";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";

export const WALLET_ADDRESS = "0x52e5B77b02F115FD7fC2D7E740971AEa85880808";

const CDP_KEY_ID = process.env.CDP_API_KEY_ID;
const CDP_KEY_SECRET = process.env.CDP_API_KEY_SECRET;
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

const facilitatorClient = USE_MAINNET
  ? await buildCdpFacilitator()
  : buildTestnetFacilitator();

export const resourceServer = new x402ResourceServer(facilitatorClient)
  .register(NETWORK, new ExactEvmScheme());

console.log(`x402: ${USE_MAINNET ? "MAINNET (Base)" : "TESTNET (Base Sepolia)"}`);

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

export { paymentMiddleware };
