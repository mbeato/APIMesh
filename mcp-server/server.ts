import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// API key for authenticated requests (optional — falls back to x402/free previews)
const APIMESH_API_KEY = process.env.APIMESH_API_KEY || "";
if (APIMESH_API_KEY) {
  console.log("[mcp] API key configured — requests will use Bearer auth");
}

// ---------------------------------------------------------------------------
// Helper: make an HTTP request and return a structured MCP tool result.
// Handles 402 (payment required) by returning the payment details.
// ---------------------------------------------------------------------------
async function callApi(
  url: string,
  options?: RequestInit,
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  try {
    // Build headers: preserve caller headers + inject API key if configured
    const headers: Record<string, string> = {};
    if (options?.headers) {
      const h = options.headers;
      if (h instanceof Headers) {
        h.forEach((v, k) => { headers[k] = v; });
      } else if (Array.isArray(h)) {
        h.forEach(([k, v]) => { headers[k] = v; });
      } else {
        Object.assign(headers, h);
      }
    }
    if (APIMESH_API_KEY) {
      headers["Authorization"] = `Bearer ${APIMESH_API_KEY}`;
    }

    const res = await fetch(url, { ...options, headers });
    const body = await res.text();

    if (res.status === 402) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                status: 402,
                message: "Payment Required (x402)",
                headers: Object.fromEntries(res.headers.entries()),
                body: tryParseJSON(body),
              },
              null,
              2,
            ),
          },
        ],
      };
    }

    if (!res.ok) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              { status: res.status, error: tryParseJSON(body) },
              null,
              2,
            ),
          },
        ],
        isError: true,
      };
    }

    return {
      content: [
        {
          type: "text",
          text: typeof tryParseJSON(body) === "object"
            ? JSON.stringify(tryParseJSON(body), null, 2)
            : body,
        },
      ],
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      content: [{ type: "text", text: `Fetch error: ${message}` }],
      isError: true,
    };
  }
}

function tryParseJSON(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function qs(params: Record<string, string | number | undefined>): string {
  const entries = Object.entries(params).filter(
    ([, v]) => v !== undefined && v !== null,
  );
  if (entries.length === 0) return "";
  return "?" + entries.map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`).join("&");
}

export function createServer(): McpServer {
  const server = new McpServer({
    name: "apimesh",
    version: "1.7.0",
  });

  server.tool(
    "web_checker",
    "Check if a brand name is available across 5 domain TLDs (.com, .io, .xyz, .dev, .ai), GitHub, npm, PyPI, and Reddit in one call. Free preview: GET https://check.apimesh.xyz/preview?name=... returns .com availability only",
    { name: z.string().describe("The brand or product name to check") },
    async ({ name }) => callApi(`https://check.apimesh.xyz/check${qs({ name })}`),
  );

  server.tool(
    "http_status_checker",
    "Check the live HTTP status of any URL, optionally verify against an expected code. Useful for uptime monitoring, redirect validation, and link checking",
    {
      url: z.string().describe("The URL to check"),
      expected: z.number().optional().describe("Expected HTTP status code"),
    },
    async ({ url, expected }) =>
      callApi(`https://http-status-checker.apimesh.xyz/check${qs({ url, expected })}`),
  );

  server.tool(
    "favicon_checker",
    "Check whether a website has a favicon and get its URL, format, and status. Useful for link previews and site branding validation",
    { url: z.string().describe("The URL to check for a favicon") },
    async ({ url }) =>
      callApi(`https://favicon-checker.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "microservice_health_check",
    "Check health and response times of up to 10 service URLs in parallel. Free preview: GET https://microservice-health-check.apimesh.xyz/preview?url=... checks 1 service for free",
    {
      services: z.array(z.string()).describe("Array of service URLs to health-check"),
    },
    async ({ services }) =>
      callApi("https://microservice-health-check.apimesh.xyz/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ services }),
      }),
  );

  server.tool(
    "robots_txt_parser",
    "Fetch and parse a website's robots.txt into structured rules, sitemaps, and crawl directives",
    { url: z.string().describe("The website URL whose robots.txt to parse") },
    async ({ url }) =>
      callApi(`https://robots-txt-parser.apimesh.xyz/analyze${qs({ url })}`),
  );

  server.tool(
    "core_web_vitals",
    "Get Core Web Vitals and Lighthouse performance scores for any URL. Returns LCP, CLS, INP field data plus performance, accessibility, best-practices, and SEO scores. Free preview: GET https://core-web-vitals.apimesh.xyz/preview?url=... returns performance score only",
    { url: z.string().describe("The URL to analyze") },
    async ({ url }) =>
      callApi(`https://core-web-vitals.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "security_headers",
    "Audit HTTP security headers for any URL. Checks 10 headers (CSP, HSTS, X-Frame-Options, etc.) with weighted grading A+ through F and remediation suggestions. Free preview: GET https://security-headers.apimesh.xyz/preview?url=... checks 3 key headers for free",
    { url: z.string().describe("The URL to audit") },
    async ({ url }) =>
      callApi(`https://security-headers.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "redirect_chain",
    "Trace the full redirect chain for any URL. Returns each hop with status code, location, and latency. Detects loops and extracts the final canonical URL. Free preview: GET https://redirect-chain.apimesh.xyz/preview?url=... traces up to 5 hops for free",
    { url: z.string().describe("The URL to trace") },
    async ({ url }) =>
      callApi(`https://redirect-chain.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "email_security",
    "Check email security configuration for any domain. Analyzes SPF, DMARC, DKIM (probes 10 common selectors), and MX records with provider detection. Free preview: GET https://email-security.apimesh.xyz/preview?domain=... checks SPF and DMARC for free",
    { domain: z.string().describe("The domain to check (e.g. example.com)") },
    async ({ domain }) =>
      callApi(`https://email-security.apimesh.xyz/check${qs({ domain })}`),
  );

  server.tool(
    "seo_audit",
    "Run a comprehensive on-page SEO audit on any URL. Analyzes title, meta description, headings, images, links, content, canonical, OG tags, JSON-LD, and robots directives with a 0-100 score. Free preview: GET https://seo-audit.apimesh.xyz/preview?url=... returns title, meta, H1, and score for free",
    { url: z.string().describe("The URL to audit") },
    async ({ url }) =>
      callApi(`https://seo-audit.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "indexability_checker",
    "Check if a URL is indexable by search engines. Performs 5-layer analysis: robots.txt rules, HTTP status, meta robots, X-Robots-Tag, and canonical tag. Free preview: GET https://indexability.apimesh.xyz/preview?url=... checks HTTP status and meta robots for free",
    { url: z.string().describe("The URL to check") },
    async ({ url }) =>
      callApi(`https://indexability.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "brand_assets",
    "Extract brand assets from any domain. Returns logo URL, favicon, theme colors, OG image, and site name. Free preview: GET https://brand-assets.apimesh.xyz/preview?domain=... returns Google favicon URL for free",
    { domain: z.string().describe("The domain to extract assets from (e.g. example.com)") },
    async ({ domain }) =>
      callApi(`https://brand-assets.apimesh.xyz/check${qs({ domain })}`),
  );

  server.tool(
    "email_verify",
    "Verify an email address: syntax validation, MX record check, disposable domain detection, role-address detection, free provider detection, and deliverability assessment. Free preview: GET https://email-verify.apimesh.xyz/preview?email=... checks syntax and disposable status for free",
    { email: z.string().describe("The email address to verify (e.g. user@example.com)") },
    async ({ email }) =>
      callApi(`https://email-verify.apimesh.xyz/check${qs({ email })}`),
  );

  server.tool(
    "tech_stack",
    "Detect the technology stack of any website. Analyzes HTTP headers and HTML to identify CMS, frameworks, languages, analytics, CDN, hosting, JavaScript libraries, and CSS frameworks. Free preview: GET https://tech-stack.apimesh.xyz/preview?url=... detects technologies from HTTP headers only",
    { url: z.string().describe("The URL to analyze (e.g. https://example.com)") },
    async ({ url }) =>
      callApi(`https://tech-stack.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "wallet_usage",
    "Check your wallet's APIMesh spend and cap status. Returns daily/7d/30d spend totals, active spend cap with remaining budget, and recent requests. No authentication required.",
    { address: z.string().describe("Your 0x wallet address (e.g. 0xabc...def)") },
    async ({ address }) =>
      callApi(`https://apimesh.xyz/wallet/${encodeURIComponent(address)}`),
  );

  server.tool(
    "web_resource_validator",
    "Validate presence and correctness of common web resources (robots.txt, sitemap.xml, openapi.json, agent.json) for any domain. Returns availability status for the requested resource.",
    {
      url: z.string().describe("The website URL to validate resources for (e.g. https://example.com)"),
      resource: z.enum(["robots.txt", "sitemap.xml", "openapi.json", "agent.json"]).describe("The web resource to validate"),
    },
    async ({ url, resource }) =>
      callApi(`https://web-resource-validator.apimesh.xyz/validate${qs({ url, resource })}`),
  );

  server.tool(
    "website_security_header_info",
    "Analyze security-related HTTP headers for any website. Checks Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, and Permissions-Policy with issue detection.",
    { url: z.string().describe("The website URL to analyze (e.g. https://example.com)") },
    async ({ url }) =>
      callApi(`https://website-security-header-info.apimesh.xyz/?url=${encodeURIComponent(url)}`),
  );

  server.tool(
    "website_vulnerability_scan",
    "Comprehensive website security audit combining hostname analysis, SSL certificate validation, HTTP security headers, cookie security, and Content Security Policy analysis. Returns an overall security score (0-100) with actionable recommendations. Supports basic, detailed, and full scan levels.",
    {
      url: z.string().describe("The website URL to scan (e.g. https://example.com)"),
      level: z.enum(["basic", "detailed", "full"]).optional().describe("Scan detail level (default: full)"),
    },
    async ({ url, level }) =>
      callApi(`https://website-vulnerability-scan.apimesh.xyz/scan${qs({ url, level })}`),
  );

  server.tool(
    "mock_jwt_generator",
    "Generate test JWTs with custom claims and expiry for local development. Returns a signed HS256 token. Useful for testing auth flows without a real identity provider.",
    {
      payload: z.record(z.unknown()).describe("JWT payload claims (e.g. { sub: '123', role: 'admin' })"),
      secret: z.string().min(3).describe("HMAC secret for HS256 signing"),
      expiresInSeconds: z.number().min(10).max(604800).optional().describe("Token expiry in seconds (default: 3600, max: 7 days)"),
    },
    async ({ payload, secret, expiresInSeconds }) =>
      callApi("https://mock-jwt-generator.apimesh.xyz/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ payload, secret, expiresInSeconds }),
      }),
  );

  server.tool(
    "regex_builder",
    "Build and test regex patterns. POST /build creates a regex from a pattern string or components. POST /test validates a pattern against test strings. Useful for generating and debugging regular expressions.",
    {
      mode: z.enum(["build", "test"]).describe("'build' to create a regex, 'test' to validate against strings"),
      pattern: z.string().max(500).describe("Regex pattern string"),
      flags: z.string().optional().describe("Regex flags (g, i, m, s, u, y)"),
      testStrings: z.array(z.string().max(1000)).max(20).optional().describe("Test strings (required for 'test' mode)"),
    },
    async ({ mode, pattern, flags, testStrings }) => {
      if (mode === "test") {
        return callApi("https://regex-builder.apimesh.xyz/test", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pattern, flags, testStrings }),
        });
      }
      return callApi("https://regex-builder.apimesh.xyz/build", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pattern, flags }),
      });
    },
  );

  server.tool(
    "status_code_checker",
    "Check the live HTTP status code of any URL. Returns the actual status code, reason phrase, and response headers. Simpler than http_status_checker — no expected-code validation.",
    {
      url: z.string().describe("The URL to check (must include http:// or https://)"),
    },
    async ({ url }) =>
      callApi(`https://status-code-checker.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "swagger_docs_creator",
    "Generate OpenAPI 3.0 documentation for an API endpoint. Provide the path, method, summary, and optionally parameters/requestBody/responses to get a complete OpenAPI spec fragment.",
    {
      path: z.string().describe("API endpoint path (e.g. /api/users)"),
      method: z.string().describe("HTTP method (GET, POST, PUT, DELETE)"),
      summary: z.string().describe("Short summary of what the endpoint does"),
      description: z.string().optional().describe("Full description of the endpoint"),
    },
    async ({ path, method, summary, description }) =>
      callApi("https://swagger-docs-creator.apimesh.xyz/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path, method, summary, description }),
      }),
  );

  server.tool(
    "user_agent_analyzer",
    "Parse a User-Agent string into structured data: browser name/version, OS name/version, device type, and bot detection. Useful for analytics and request filtering.",
    {
      ua: z.string().describe("The User-Agent string to parse"),
    },
    async ({ ua }) =>
      callApi(`https://user-agent-analyzer.apimesh.xyz/analyze${qs({ ua })}`),
  );

  server.tool(
    "yaml_validator",
    "Validate YAML syntax and structure. Returns parsed result on success or detailed error with line/column on failure. Useful for CI pipelines and config file validation.",
    {
      yaml: z.string().describe("The YAML string to validate"),
    },
    async ({ yaml }) =>
      callApi("https://yaml-validator.apimesh.xyz/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ yaml }),
      }),
  );

  server.tool(
    "wallet_set_cap",
    "Set a spend cap on your wallet. Once the daily or monthly USDC limit is reached, further paid API calls return 429 before payment is attempted. Set limits to null to remove a cap.",
    {
      address: z.string().describe("Your 0x wallet address"),
      daily_limit_usd: z.number().nullable().describe("Max daily spend in USD (null = unlimited)"),
      monthly_limit_usd: z.number().nullable().describe("Max monthly spend in USD (null = unlimited)"),
      label: z.string().nullable().optional().describe("Friendly label (e.g. 'Claude Desktop')"),
    },
    async ({ address, daily_limit_usd, monthly_limit_usd, label }) =>
      callApi(`https://apimesh.xyz/wallet/${encodeURIComponent(address)}/cap`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ daily_limit_usd, monthly_limit_usd, label: label ?? null }),
      }),
  );

  return server;
}
