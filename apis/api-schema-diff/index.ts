import { Hono } from "hono";
import { cors } from "hono/cors";
import {
  paymentMiddleware,
  paidRouteWithDiscovery,
  resourceServer,
} from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { extractPayerWallet } from "../../shared/x402-wallet";
import { spendCapMiddleware } from "../../shared/spend-cap";
import { rateLimit } from "../../shared/rate-limit";
import {
  safeFetch,
  validateExternalUrl,
} from "../../shared/ssrf";
import {
  SchemaDiffRequest,
  SchemaDiffResponse,
  schemaDiffAnalysis,
  InfoDoc,
} from "./analyzer";

const app = new Hono();
const API_NAME = "api-schema-diff";
const PORT = Number(process.env.PORT) || 3001;
const PRICE = "$0.01"; // Comprehensive audit: 5+ checks, scoring, detailed report
const PRICE_NUM = 0.01;

// 1. CORS middleware open to all origins
app.use("*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST"],
    allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"],
  }),
);

// 2. Health endpoint BEFORE rate limiter
app.get("/health", (c) => c.json({ status: "ok" }));

// 3. Rate limit middleware
app.use("/compare", rateLimit("api-schema-diff-compare", 30, 60_000));
app.use("*", rateLimit("api-schema-diff", 90, 60_000));

// 4. Extract wallet and API logger
app.use("*", extractPayerWallet());
app.use("*", apiLogger(API_NAME, PRICE_NUM));

// 5. Info endpoint before spend cap and payment
app.get("/", (c) => {
  const docs: InfoDoc = {
    api: API_NAME,
    status: "healthy",
    version: "1.0.0",
    docs: {
      endpoints: [
        {
          method: "POST",
          path: "/compare",
          description: "Compare multiple API schema versions (REST or GraphQL) to highlight differences and score compatibility.",
          parameters: [
            {
              name: "schemas",
              in: "body",
              schema: {
                type: "array",
                items: { type: "object", properties: { url: { type: "string", description: "URL to schema JSON" }, version: { type: "string", description: "Version identifier or tag" } }, required: ["url", "version"] },
                minItems: 2,
                maxItems: 10
              },
              description: "Array of schema versions with URLs to fetch and version names",
            }
          ],
          exampleResponse: {
            status: "ok",
            data: {
              comparedVersions: ["1.0", "1.1"],
              type: "REST",
              differencesSummary: {
                added: 2,
                removed: 1,
                changed: 3
              },
              score: 87,
              grade: "B",
              recommendations: [
                {
                  issue: "Removed endpoint",
                  severity: 70,
                  suggestion: "Deprecate clients that use the removed endpoint or provide a migration path."
                }
              ],
              details: {}
            },
            meta: {
              timestamp: "...",
              duration_ms: 500,
              api_version: "1.0.0"
            }
          }
        }
      ],
      parameters: [
        { name: "schemas", description: "List of schema URLs and version labels to compare" }
      ],
      examples: [
        {
          description: "Compare two versions of a RESTful API OpenAPI 3 spec",
          method: "POST",
          path: "/compare",
          body: {
            schemas: [
              { url: "https://example.com/api/v1/openapi.json", version: "v1" },
              { url: "https://example.com/api/v2/openapi.json", version: "v2" }
            ]
          }
        }
      ]
    },
    pricing: {
      type: "comprehensive audit",
      price: PRICE
    }
  };

  return c.json(docs);
});

// 6. Spend cap before payment middleware
app.use("*", spendCapMiddleware());

// 7. Payment middleware
app.use(
  "*",
  paymentMiddleware(
    {
      "POST /compare": paidRouteWithDiscovery(
        PRICE,
        "Comprehensive API schema comparison audit with scoring, detailed diff report, and actionable recommendations.",
        {
          input: {
            schemas: [
              { url: "https://example.com/api/v1/schema.json", version: "v1" },
              { url: "https://example.com/api/v2/schema.json", version: "v2" },
            ],
          },
          inputSchema: {
            type: "object",
            properties: {
              schemas: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    url: { type: "string", description: "Schema URL (REST OpenAPI or GraphQL Introspection)" },
                    version: { type: "string", description: "Version label or tag" },
                  },
                  required: ["url", "version"],
                },
                minItems: 2,
                maxItems: 10,
                description: "List of schema versions to compare",
              },
            },
            required: ["schemas"],
          },
        }
      ),
    },
    resourceServer
  )
);

interface CompareRequestBody {
  schemas: Array<{ url: string; version: string }>;
}

// 8. Paid endpoint logic
app.post("/compare", async (c) => {
  const start = performance.now();

  let bodyJson: CompareRequestBody;
  try {
    bodyJson = await c.req.json();
  } catch (e) {
    return c.json(
      {
        status: "error",
        error: "Invalid JSON body",
        detail: (e instanceof Error) ? e.message : String(e),
        meta: {
          timestamp: new Date().toISOString(),
          duration_ms: 0,
          api_version: "1.0.0",
        },
      },
      400
    );
  }

  if (!bodyJson || !Array.isArray(bodyJson.schemas) || bodyJson.schemas.length < 2) {
    return c.json(
      {
        status: "error",
        error: "Invalid input: expect 'schemas' array of length >= 2",
        detail: "The 'schemas' parameter must be an array with at least 2 schema objects",
        meta: {
          timestamp: new Date().toISOString(),
          duration_ms: 0,
          api_version: "1.0.0",
        },
      },
      400
    );
  }

  if (bodyJson.schemas.length > 10) {
    return c.json(
      {
        status: "error",
        error: "Too many schema entries; maximum 10 allowed",
        detail: "Limit comparison to 10 schema versions at once",
        meta: {
          timestamp: new Date().toISOString(),
          duration_ms: 0,
          api_version: "1.0.0",
        },
      },
      400
    );
  }

  // Validate and fetch all schemas in parallel, with 10 seconds timeout each
  try {
    const valResults = bodyJson.schemas.map((s) => validateExternalUrl(s.url));
    for (const v of valResults) {
      if ("error" in v) {
        return c.json(
          {
            status: "error",
            error: "Invalid schema URL",
            detail: v.error,
            meta: {
              timestamp: new Date().toISOString(),
              duration_ms: 0,
              api_version: "1.0.0",
            },
          },
          400
        );
      }
    }

    const fetchPromises = bodyJson.schemas.map(({ url }) =>
      safeFetch(url, {
        timeoutMs: 10000,
        headers: { "User-Agent": "api-schema-diff/1.0 apimesh.xyz" },
      })
    );

    const responses = await Promise.all(fetchPromises);

    const jsonsPromises = responses.map(async (res, i) => {
      if (!res.ok) {
        throw new Error(
          `Failed to fetch schema at ${bodyJson.schemas[i].url}: HTTP status ${res.status}`
        );
      }
      // Limit response size to prevent abuse
      const text = await res.text();
      if (text.length > 2_000_000) {
        throw new Error(
          `Schema at ${bodyJson.schemas[i].url} exceeds 2MB size limit`
        );
      }
      try {
        return JSON.parse(text);
      } catch (e) {
        throw new Error(`Invalid JSON schema at ${bodyJson.schemas[i].url}`);
      }
    });

    const schemasData = await Promise.all(jsonsPromises);

    // Run analysis
    const result: SchemaDiffResponse = await schemaDiffAnalysis(bodyJson.schemas, schemasData);

    const duration_ms = Math.round(performance.now() - start);

    return c.json({ status: "ok", data: result, meta: { timestamp: new Date().toISOString(), duration_ms, api_version: "1.0.0" } });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return c.json({ status: "error", error: "Analysis temporarily unavailable", detail: msg, meta: { timestamp: new Date().toISOString(), duration_ms: 0, api_version: "1.0.0" } }, status);
  }
});

// 9. Error handler passes HTTPExceptions (such as 402) through, logs other errors
app.onError((err, c) => {
  if (typeof err === "object" && err !== null && "getResponse" in err) {
    return (err as any).getResponse();
  }
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ status: "error", error: "Internal server error" }, 500);
});

app.notFound((c) => c.json({ status: "error", error: "Not found" }, 404));

export { app };

if (import.meta.main) console.log(`${API_NAME} listening on port ${PORT}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
