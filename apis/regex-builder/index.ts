import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, paidRoute, resourceServer } from "../../shared/x402";
import { apiLogger } from "../../shared/logger";
import { rateLimit } from "../../shared/rate-limit";

const API_NAME = "regex-builder";
const API_PRICE = 0.002; // $0.002 per call
const API_PRICE_STR = "$0.002";
const SUBDOMAIN = "regex-builder.apimesh.xyz";
const PORT = Number(process.env.PORT) || 3001;

const app = new Hono();

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET", "POST"],
  allowHeaders: ["Content-Type", "X-PAYMENT", "payment-signature"]
}));

// Health check — before rate limiter for fast monitoring
app.get("/health", (c) => c.json({ status: "ok" }));

// Rate limits: 60/min global, 20/min /build, 20/min /test
app.use("/build", rateLimit("regex-builder-build", 20, 60_000));
app.use("/test", rateLimit("regex-builder-test", 20, 60_000));
app.use("*", rateLimit("regex-builder-generic", 60, 60_000));
app.use("*", apiLogger(API_NAME, API_PRICE));

// Info endpoint — after rate limiter, metered
app.get("/", (c) => {
  return c.json({
    api: API_NAME,
    status: "healthy",
    description: "Provides an interface to construct and test regular expressions.",
    docs: "POST /build, POST /test",
    endpoints: {
      "/build": {
        method: "POST",
        description: "Constructs a regex from JSON components, returns regex string and flags."
      },
      "/test": {
        method: "POST",
        description: "Test a regex string (and flags) against test inputs. Returns matches or errors."
      }
    },
    pricing: `${API_PRICE_STR} per call via x402`,
    subdomain: SUBDOMAIN
  });
});

app.use(
  paymentMiddleware(
    {
      "POST /build": paidRoute(API_PRICE_STR, "Construct regex from JSON structure, get pattern and flags."),
      "POST /test": paidRoute(API_PRICE_STR, "Test a regex pattern (and flags) against input strings."),
    },
    resourceServer
  )
);

/**
 * POST /build
 * Body: {
 *   pattern: string, // e.g. "foo.*bar",
 *   flags?: string,  // optional e.g. "gi"
 * }
 * OR: {
 *   components: [
 *     { type: "literal", value: string },
 *     { type: "charClass", value: "\\d" },
 *     ...
 *   ]
 *   flags?: string
 * }
 * Returns: regex string and sample usage
 */
app.post("/build", async (c) => {
  try {
    const body = await c.req.json();
    let pattern = "";
    let flags = "";

    if (typeof body !== "object" || (!body.pattern && !body.components)) {
      return c.json({ error: "Send either { pattern } or { components } in body" }, 400);
    }

    if (typeof body.pattern === "string") {
      pattern = body.pattern;
      if (body.flags && typeof body.flags === "string") {
        flags = body.flags;
      }
    } else if (Array.isArray(body.components)) {
      pattern = buildPatternFromComponents(body.components);
      if (body.flags && typeof body.flags === "string") {
        flags = body.flags;
      }
    } else {
      return c.json({ error: "Invalid body: must provide { pattern } or { components }" }, 400);
    }

    // Validate flags
    if (!isValidFlags(flags)) {
      return c.json({ error: `Invalid regex flags: "${flags}"` }, 400);
    }

    // Validate regex compilation
    try {
      const re = new RegExp(pattern, flags);
      // Sample test
      const sample = `const re = new RegExp(${JSON.stringify(pattern)}, "${flags}");`;
      return c.json({
        pattern,
        flags,
        regex: `/${pattern.replace(/\\/g, "\\\\")}/${flags}`,
        usage: sample
      });
    } catch (e: any) {
      return c.json({ error: `Invalid regex: ${e.message}` }, 400);
    }
  } catch (err) {
    return c.json({ error: "Invalid JSON" }, 400);
  }
});

/**
 * POST /test
 * Body: {
 *   pattern: string,
 *   flags?: string,
 *   testStrings: string[]
 * }
 * Returns: {
 *   results: Array<{ input: string, matches: string[] | null, error?: string }>
 * }
 */
app.post("/test", async (c) => {
  try {
    const body = await c.req.json();
    if (!body || typeof body !== "object") {
      return c.json({ error: "Invalid JSON body" }, 400);
    }
    const pattern: string = body.pattern;
    const flags: string = body.flags || "";
    const testStrings: string[] = body.testStrings;
    if (typeof pattern !== "string" || pattern.length === 0) {
      return c.json({ error: "pattern is required as string" }, 400);
    }
    if (!isValidFlags(flags)) {
      return c.json({ error: `Invalid regex flags: "${flags}"` }, 400);
    }
    if (!Array.isArray(testStrings) || !testStrings.every(s => typeof s === "string" && s.length <= 5000)) {
      return c.json({ error: "testStrings must be string array, each string up to 5000 chars" }, 400);
    }
    let re: RegExp;
    try {
      re = new RegExp(pattern, flags);
    } catch (e: any) {
      return c.json({ error: `Invalid regex: ${e.message}` }, 400);
    }
    // Limit maximum test strings
    const maxTests = 20;
    if (testStrings.length > maxTests) {
      return c.json({ error: `Too many testStrings (max ${maxTests})` }, 400);
    }
    const results = testStrings.map(input => {
      try {
        const matches = input.match(re);
        return {
          input,
          matches: matches ? Array.from(matches) : null
        };
      } catch (e: any) {
        return {
          input,
          matches: null,
          error: e && e.message ? String(e.message) : "regex error"
        };
      }
    });
    return c.json({
      pattern,
      flags,
      results
    });
  } catch (err) {
    return c.json({ error: "Invalid JSON" }, 400);
  }
});

// Graceful error handling
app.onError((err, c) => {
  if ("getResponse" in err) return (err as any).getResponse();
  console.error(`[${new Date().toISOString()}] ${API_NAME} error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

app.notFound((c) => c.json({ error: "Not found" }, 404));

function isValidFlags(flags: string): boolean {
  // Only JS RegExp flags: gimsuy
  return /^[gimsuy]*$/.test(flags);
}

type RegexComponent =
  | { type: "literal"; value: string }
  | { type: "charClass"; value: string }
  | { type: "group"; value: RegexComponent[]; capturing?: boolean }
  | { type: "quantifier"; quant: string; of: RegexComponent }
  | { type: "alternation"; options: RegexComponent[] }
  | { type: "anchor"; value: string }
  | { type: "raw"; value: string };

// Simple recursive builder
function buildPatternFromComponents(components: any[]): string {
  return components.map(buildComponentPattern).join("");
}
function buildComponentPattern(component: any): string {
  if (!component || typeof component !== "object" || typeof component.type !== "string") return "";
  switch (component.type) {
    case "literal":
      return escapeRegexLiteral(String(component.value ?? ""));
    case "charClass":
      return String(component.value ?? "");
    case "anchor":
      return String(component.value ?? "");
    case "raw":
      return String(component.value ?? "");
    case "quantifier":
      const quant = String(component.quant ?? "");
      return `(${buildComponentPattern(component.of)})${quant}`;
    case "group":
      {
        const cap = component.capturing === false ? "?:" : "";
        return `(${cap}${(Array.isArray(component.value) ? component.value.map(buildComponentPattern).join("") : "")})`;
      }
    case "alternation":
      if (Array.isArray(component.options)) {
        return `(${component.options.map(buildComponentPattern).join("|")})`;
      }
      return "";
    default:
      return "";
  }
}

function escapeRegexLiteral(str: string): string {
  // Escape chars with special meaning
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export { app };

if (import.meta.main) {
  // eslint-disable-next-line no-console
  console.log(`${API_NAME} listening on port ${PORT}`);
}

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
