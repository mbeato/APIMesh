import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRouteWithDiscovery, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import { validateExternalUrl } from "../../shared/ssrf";
import { analyzeNetworkPath } from "./analyzer";
import type { NetworkPathInferResult } from "./types";

const app = new Hono();
const API_NAME = "network-path-infer";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01";
const PRICE_NUMBER = 0.01;

// 1. CORS middleware open to all origins
app.use("*", cors({
  origin: "*",
  allowMethods: ["GET"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
}));

// 2. Health check endpoint BEFORE rate limiter
app.get("/health", c => c.json({ status: "ok" }));

// 3. Rate limits
app.use("/infer", rateLimit("network-path-infer-infer", 10, 60_000));
app.use("*", rateLimit("network-path-infer", 30, 60_000));

// 4. extractPayerWallet sets c.set("payerWallet", ...)
app.use("*", extractPayerWallet());

// 5. apiLogger logs usage and revenue
app.use("*", apiLogger(API_NAME, PRICE_NUMBER));

// 6. Info endpoint
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs: {
      endpoints: [
        {
          method: "GET",
          path: "/infer",
          description: "Infer network physical routing paths, ASN hops, and geolocation for target IP or hostname",
          parameters: [
            { name: "target", type: "string", description: "Target IP address or hostname to infer network path" },
          ],
          example_response: {
            status: "ok",
            data: {
              targetIp: "8.8.8.8",
              targetHostname: "dns.google",
              asnHops: [
                {
                  hopIndex: 1,
                  ip: "192.168.0.1",
                  asn: null,
                  asnName: null,
                  country: "US",
                  region: "CA",
                  city: "Mountain View",
                },
                {
                  hopIndex: 2,
                  ip: "8.8.8.8",
                  asn: 15169,
                  asnName: "Google LLC",
                  country: "US",
                  region: "CA",
                  city: "Mountain View",
                },
              ],
              pathScore: 85,
              pathGrade: "B",
              geolocations: [
                { ip: "192.168.0.1", country: "US", region: "CA", city: "Mountain View", latitude: 37.4056, longitude: -122.0775 },
                { ip: "8.8.8.8", country: "US", region: "CA", city: "Mountain View", latitude: 37.4056, longitude: -122.0775 },
              ],
              topologyGraphSvg: "<svg>...</svg>",
              explanation: "Network path analysis indicates mostly public IP hops with private hops at start.",
              recommendations: [
                { issue: "Private IP hops detected", severity: "medium", suggestion: "Check if VPN or internal networking affects trace results." },
              ],
              analyzedAt: "2024-06-30T12:34:56.789Z",
            },
            meta: { timestamp: "2024-06-30T12:34:56.789Z", duration_ms: 2000, api_version: "1.0.0" }
          }
        },
        {
          method: "GET",
          path: "/preview",
          description: "Free preview with basic analysis for target IP or hostname",
          parameters: [
            { name: "target", type: "string", description: "Target IP or hostname" },
          ],
          example_response: {
            status: "ok",
            data: {
              targetIp: "8.8.8.8",
              asnHops: [{ hopIndex: 1, ip: "8.8.8.8", asn: 15169, asnName: "Google LLC", country: "US", region: "CA", city: "Mountain View" }],
              pathScore: 90,
              pathGrade: "A",
              explanation: "Basic lookup of target IP ASN and geolocation.",
              analyzedAt: "2024-06-30T12:00:00.000Z",
            },
            meta: { timestamp: "2024-06-30T12:00:00.000Z", duration_ms: 600, api_version: "1.0.0" }
          }
        }
      ],
      parameters: [
        { name: "target", type: "string", description: "The IP address or hostname to analyze" }
      ],
      examples: [
        { path: "/infer?target=8.8.8.8" },
        { path: "/preview?target=dns.google" }
      ]
    },
    pricing: {
      endpoints: {
        "/infer": PRICE
      },
      description: "Pricing based on comprehensive audit of network hops, ASN, geolocation, and topology visualization."
    }
  });
});

// 7. Free preview endpoint BEFORE paymentMiddleware
import { safeFetch } from "../../shared/ssrf";
app.get("/preview", rateLimit("network-path-infer-preview", 20, 60_000), async (c) => {
  const targetRaw = c.req.query("target");
  if (!targetRaw || typeof targetRaw !== "string") {
    return c.json({
      status: "error",
      error: "Missing 'target' query parameter (IP or hostname)",
      detail: "",
      meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" }
    }, 400);
  }

  // Validate target, allow IP or hostname syntax simple validation
  const target = targetRaw.trim();
  if (target.length > 255) {
    return c.json({
      status: "error",
      error: "'target' parameter too long",
      detail: "",
      meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" }
    }, 400);
  }

  const start = performance.now();

  try {
    // Simple preview: resolve target to IP and fetch ASN and Geo for that IP only
    // or treat if target is IP directly

    let resolvedIp = "";

    // Validate IP format simple
    if (/^(25[0-5]|2[0-4]\d|1?\d{1,2})(\.(25[0-5]|2[0-4]\d|1?\d{1,2})){3}$/.test(target)) {
      resolvedIp = target;
    } else {
      // Resolve hostname using DNS over HTTPS
      const dnsResRaw = await safeFetch(`https://dns.google/resolve?name=${encodeURIComponent(target)}&type=A`, { timeoutMs: 15000 });
      if (!dnsResRaw.ok) {
        return c.json({
          status: "error",
          error: "DNS lookup failed",
          detail: `DNS response status ${dnsResRaw.status}`,
          meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" }
        }, 400);
      }
      const dnsRes = await dnsResRaw.json();
      if (dnsRes.Answer && Array.isArray(dnsRes.Answer)) {
        const answer = dnsRes.Answer.find((a: any) => a.type === 1);
        if (!answer) {
          return c.json({
            status: "error",
            error: "No A record found",
            detail: "",
            meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" }
          }, 400);
        }
        resolvedIp = answer.data;
      } else {
        return c.json({
          status: "error",
          error: "DNS resolution failed",
          detail: "Invalid DNS response",
          meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" }
        }, 400);
      }
    }

    // Fetch ASN and Geo in parallel
    const signal = AbortSignal.timeout(20000);
    const [asnResponse, geoResponse] = await Promise.all([
      // We reuse analyzer's fetchAsnInfo function but replicate code here to avoid circular import
      (async () => {
        try {
          const url = `https://api.iptoasn.com/v1/as/ip/${encodeURIComponent(resolvedIp)}`;
          const res = await safeFetch(url, { signal });
          if (!res.ok) throw new Error(`IPtoASN status ${res.status}`);
          const data = await res.json();
          return { asn: data.asn, asnName: data.asn_description };
        } catch (_) {
          return { asn: null, asnName: null };
        }
      })(),
      (async () => {
        try {
          const url = `https://ipinfo.io/${encodeURIComponent(resolvedIp)}/json`;
          const res = await safeFetch(url, { signal });
          if (!res.ok) throw new Error(`ipinfo.io status ${res.status}`);
          const data = await res.json();
          const loc = typeof data.loc === "string" ? data.loc.split(",") : [];
          return {
            country: data.country || null,
            region: data.region || null,
            city: data.city || null,
            latitude: loc.length === 2 ? parseFloat(loc[0]) : null,
            longitude: loc.length === 2 ? parseFloat(loc[1]) : null
          };
        } catch (_) {
          return { country: null, region: null, city: null, latitude: null, longitude: null };
        }
      })()
    ]);

    const data = {
      targetIp: resolvedIp,
      targetHostname: resolvedIp === target ? undefined : target,
      asnHops: [
        {
          hopIndex: 1,
          ip: resolvedIp,
          asn: asnResponse.asn,
          asnName: asnResponse.asnName,
          country: geoResponse.country,
          region: geoResponse.region,
          city: geoResponse.city,
        },
      ],
      pathScore: 90,
      pathGrade: "A",
      geolocations: [
        {
          ip: resolvedIp,
          country: geoResponse.country,
          region: geoResponse.region,
          city: geoResponse.city,
          latitude: geoResponse.latitude,
          longitude: geoResponse.longitude,
        },
      ],
      explanation: "Basic preview with resolved IP ASN and geolocation.",
      recommendations: [],
      analyzedAt: new Date().toISOString(),
    };

    const duration_ms = Math.round(performance.now() - start);

    return c.json({ status: "ok", data, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ status: "error", error: "Preview temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, status);
  }
});

// 7. Spend cap middleware
app.use("*", spendCapMiddleware());

// 8. Payment middleware
app.use(
  paymentMiddleware(
    {
      "GET /infer": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive network path inference with multiple public ASN and IP geolocation APIs, hop analysis, scoring, recommendations, and topology visualization",
        {
          input: { target: "8.8.8.8" },
          inputSchema: {
            properties: {
              target: {
                type: "string",
                description: "Target IP address or hostname for network path inference",
              },
            },
            required: ["target"],
          },
        },
      ),
    },
    resourceServer
  )
);

interface InferQuery {
  target?: string;
}

// 9. Paid endpoint
app.get("/infer", async (c) => {
  const query = c.req.query<InferQuery>();
  const targetRaw = query.target;
  if (!targetRaw || typeof targetRaw !== "string") {
    return c.json({
      status: "error",
      error: "Missing 'target' query parameter (IP or hostname)",
      detail: "",
      meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" }
    }, 400);
  }
  if (targetRaw.length > 255) {
    return c.json({
      status: "error",
      error: "'target' parameter too long",
      detail: "",
      meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" }
    }, 400);
  }

  const start = performance.now();
  try {
    const result = await analyzeNetworkPath(targetRaw.trim());

    if ("error" in result) {
      return c.json({ status: "error", error: result.error, detail: "", meta: { timestamp: new Date().toISOString(), duration_ms: Math.round(performance.now() - start), api_version: "1.0.0" } }, 400);
    }

    const duration_ms = Math.round(performance.now() - start);
    return c.json({ status: "ok", data: result as NetworkPathInferResult, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ status: "error", error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, status);
  }
});

// 10. OnError handler
app.onError((err, c) => {
  if (typeof err === "object" && err !== null && "getResponse" in err) {
    return (err as any).getResponse();
  }
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

app.notFound((c) => c.json({ error: "Not found" }, 404));

export { app };

if (import.meta.main) console.log(`${API_NAME} listening on port ${PORT}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
