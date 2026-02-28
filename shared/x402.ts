import { paymentMiddleware, x402ResourceServer } from "@x402/hono";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";

export const WALLET_ADDRESS = "0x52e5B77b02F115FD7fC2D7E740971AEa85880808";

// Base mainnet
export const NETWORK = "eip155:8453";

const facilitatorClient = new HTTPFacilitatorClient({
  url: "https://www.x402.org/facilitator",
});

export const resourceServer = new x402ResourceServer(facilitatorClient)
  .register(NETWORK, new ExactEvmScheme());

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
