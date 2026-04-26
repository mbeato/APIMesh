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
    version: "1.8.2",
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

  // Brain-built APIs — wrappers generated from each API's self-documented GET / spec

  server.tool(
    "subdomain_vulnerability_rankings",
    "Paid comprehensive subdomain enumeration and vulnerability ranking",
    {
      domain: z.string().describe("Domain name to scan, e.g., example.com"),
    },
    async ({ domain }) =>
      callApi(`https://subdomain-vulnerability-rankings.apimesh.xyz/assess${qs({ domain })}`),
  );

  server.tool(
    "csp_policy_heuristics",
    "Paid comprehensive audit with advanced heuristic analysis, web crawling, scoring, and detailed recommendations",
    {
      url: z.string().describe("Target URL to analyze"),
    },
    async ({ url }) =>
      callApi(`https://csp-policy-heuristics.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "ssl_tls_risk_analyzer",
    "Aggregates SSL/TLS configuration details from public scans, DNS records, and certificate transparency logs, then performs a risk assessment",
    {
      host: z.string().describe("Hostname or URL to analyze (http(s):// optional)"),
    },
    async ({ host }) =>
      callApi(`https://ssl-tls-risk-analyzer.apimesh.xyz/analyze${qs({ host })}`),
  );

  server.tool(
    "subdomain_vulnerability_ranking",
    "Paid comprehensive subdomain enumeration and vulnerability ranking",
    {
      domain: z.string().describe("Domain to enumerate e.g. example.com"),
    },
    async ({ domain }) =>
      callApi(`https://subdomain-vulnerability-ranking.apimesh.xyz/scan${qs({ domain })}`),
  );

  server.tool(
    "subdomain_exposure_score",
    "Paid comprehensive full subdomain exposure scoring and audit report",
    {
      domain: z.string().describe("Domain name to analyze subdomains for"),
    },
    async ({ domain }) =>
      callApi(`https://subdomain-exposure-score.apimesh.xyz/scan${qs({ domain })}`),
  );

  server.tool(
    "ip_infrastructure_analyst",
    "Analyze an IP address for ASN, ISP, geolocation, and routing info; returns comprehensive report with scoring and recommendations",
    {
      ip: z.string().describe("IPv4 or IPv6 address to analyze"),
    },
    async ({ ip }) =>
      callApi(`https://ip-infrastructure-analyst.apimesh.xyz/analyze${qs({ ip })}`),
  );

  server.tool(
    "subdomain_exposure_scorer",
    "Comprehensive enumeration and exposure scoring of all detected subdomains for a domain",
    {
      domain: z.string().describe("Base domain, e.g. example.com"),
    },
    async ({ domain }) =>
      callApi(`https://subdomain-exposure-scorer.apimesh.xyz/check${qs({ domain })}`),
  );

  server.tool(
    "ssl_tls_threat_assessment",
    "Comprehensive TLS security threat assessment for a domain",
    {
      domain: z.string().describe("The domain or hostname to assess SSL/TLS configurations for"),
    },
    async ({ domain }) =>
      callApi(`https://ssl-tls-threat-assessment.apimesh.xyz/assess${qs({ domain })}`),
  );

  server.tool(
    "privacy_policy_qualify",
    "Fetch and analyze privacy policies across domains for GDPR/CCPA compliance and data sharing signals",
    {
      url: z.string().describe("URL to privacy policy or site landing page (http or https)"),
    },
    async ({ url }) =>
      callApi(`https://privacy-policy-qualify.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "dns_propagation_mapper",
    "Comprehensive DNS propagation audit across multiple global DNS resolvers with delay correlation, misconfiguration detection, scoring, grading, and recommendations",
    {
      domain: z.string().describe("Domain name to check propagation status for"),
      recordType: z.string().optional().describe("DNS record type to evaluate, e.g. A, AAAA, CNAME, TXT"),
    },
    async ({ domain, recordType }) =>
      callApi(`https://dns-propagation-mapper.apimesh.xyz/check${qs({ domain, recordType })}`),
  );

  server.tool(
    "ip_infrastructure_analyzer",
    "Comprehensive IP infrastructure analysis: ASN, ISP, geolocation, routing checks, scoring, recommendations",
    {
      ip: z.string().describe("IPv4 or IPv6 address to analyze (required)"),
    },
    async ({ ip }) =>
      callApi(`https://ip-infrastructure-analyzer.apimesh.xyz/analyze${qs({ ip })}`),
  );

  server.tool(
    "ip_geolocation_enrichment",
    "Enrich an IP address with detailed ASN, ISP, geolocation, and routing data",
    {
      ip: z.string().describe("IPv4 or IPv6 address to analyze"),
    },
    async ({ ip }) =>
      callApi(`https://ip-geolocation-enrichment.apimesh.xyz/enrich${qs({ ip })}`),
  );

  server.tool(
    "website_authenticity_assessment",
    "Comprehensive website authenticity assessment combining SSL cert validation, DNS records, redirect chain analysis, and server headers",
    {
      url: z.string().describe("Target website URL (http(s)://...)"),
    },
    async ({ url }) =>
      callApi(`https://website-authenticity-assessment.apimesh.xyz/assess${qs({ url })}`),
  );

  server.tool(
    "ssl_and_tls_hardening_score",
    "Run full SSL, TLS, and HTTP security header comprehensive hardening score with actionable recommendations",
    {
      url: z.string().describe("HTTPS URL to analyze (http:// will be rejected)"),
    },
    async ({ url }) =>
      callApi(`https://ssl-and-tls-hardening-score.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "security_headers_checker",
    "Perform a comprehensive security headers audit with detailed scoring and remediation",
    {
      url: z.string().describe("Full URL starting with http(s)://"),
    },
    async ({ url }) =>
      callApi(`https://security-headers-checker.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "subdomain_exposure_ranking",
    "Comprehensive paid scan: exhaustive subdomain enumeration from DNS, CT logs, plus HTTP endpoint probing, header analysis, TLS version checks, outdated service detection, with full scoring and rich recommendations",
    {
      domain: z.string().describe("Root domain to enumerate and analyze"),
    },
    async ({ domain }) =>
      callApi(`https://subdomain-exposure-ranking.apimesh.xyz/check${qs({ domain })}`),
  );

  server.tool(
    "ssl_tls_hardening_forecast",
    "Analyze SSL/TLS info and forecast renewal and security outlook with detailed alerts and recommendations",
    {
      host: z.string().describe("Hostname to analyze (no scheme)"),
    },
    async ({ host }) =>
      callApi(`https://ssl-tls-hardening-forecast.apimesh.xyz/forecast${qs({ host })}`),
  );

  server.tool(
    "subdomain_exposure_rankings",
    "Paid, comprehensive analysis of subdomain exposure and security ranking",
    {
      domain: z.string().describe("Root domain to enumerate and analyze"),
    },
    async ({ domain }) =>
      callApi(`https://subdomain-exposure-rankings.apimesh.xyz/check${qs({ domain })}`),
  );

  server.tool(
    "ssl_tls_expiry_forecast",
    "Comprehensive SSL/TLS certificate and protocol expiry forecast for multiple domains",
    {
      domains: z.string().describe("Comma separated domains to analyze (required, max 10 domains)"),
    },
    async ({ domains }) =>
      callApi(`https://ssl-tls-expiry-forecast.apimesh.xyz/forecast${qs({ domains })}`),
  );

  server.tool(
    "network_route_mapper",
    "Paid comprehensive analysis of network routing paths including ASN hops, geolocation, latency, suspicion scoring, and remediation",
    {
      target: z.string().describe("Target IP address or domain name to analyze"),
    },
    async ({ target }) =>
      callApi(`https://network-route-mapper.apimesh.xyz/route${qs({ target })}`),
  );

  server.tool(
    "subdomain_exposure_heatmap",
    "Exhaustive subdomain enumeration from multiple sources, risk analysis, exposure scoring, recommendations and heatmap report",
    {
      domain: z.string().describe("Root domain to audit (e.g. example.com)"),
    },
    async ({ domain }) =>
      callApi(`https://subdomain-exposure-heatmap.apimesh.xyz/heatmap${qs({ domain })}`),
  );

  server.tool(
    "dns_propagation_simulator",
    "Simulate DNS record propagation across multiple DNS resolvers with delay estimation and misconfiguration detection",
    {
      domain: z.string().describe("Domain name to check (e.g. example.com)"),
      recordType: z.string().optional().describe("DNS record type to query (A, AAAA, CNAME, TXT, etc.). Defaults to A."),
    },
    async ({ domain, recordType }) =>
      callApi(`https://dns-propagation-simulator.apimesh.xyz/simulate${qs({ domain, recordType })}`),
  );

  server.tool(
    "ssl_tls_configuration_ranker",
    "Perform a deep, comprehensive SSL/TLS configuration audit of a target site",
    {
      url: z.string().describe("URL of the target site (https://...)"),
    },
    async ({ url }) =>
      callApi(`https://ssl-tls-configuration-ranker.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "privacy_policy_enricher",
    "Fetch and analyze a privacy policy URL, combining multiple signals for GDPR and CCPA compliance, data sharing practices, and privacy features",
    {
      url: z.string().describe("Public URL of privacy policy page to analyze (HTTP or HTTPS)"),
    },
    async ({ url }) =>
      callApi(`https://privacy-policy-enricher.apimesh.xyz/enrich${qs({ url })}`),
  );

  server.tool(
    "privacy_risk_score",
    "Comprehensive privacy risk analysis of a domain's publicly available privacy policies and disclosures",
    {
      url: z.string().describe("Public URL of the domain's homepage or privacy policy"),
    },
    async ({ url }) =>
      callApi(`https://privacy-risk-score.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "http_method_enumeration",
    "Full enumeration of HTTP methods supported by a target URL with scoring and analysis",
    {
      url: z.string().describe("Target URL (must be a valid HTTP or HTTPS URL, max 2048 characters)"),
    },
    async ({ url }) =>
      callApi(`https://http-method-enumeration.apimesh.xyz/enumerate${qs({ url })}`),
  );

  server.tool(
    "web_misconfiguration_scan",
    "Run a comprehensive security misconfiguration scan against the specified URL",
    {
      url: z.string().describe("Target URL to scan (http or https)"),
    },
    async ({ url }) =>
      callApi(`https://web-misconfiguration-scan.apimesh.xyz/scan${qs({ url })}`),
  );

  server.tool(
    "dependency_license_audit",
    "Comprehensive license audit across multiple project manifests and license databases with risk scoring",
    {
      manifest_urls: z.string().describe("Comma-separated list of public URLs to project manifest files (package.json, requirements.txt, pom.xml, etc.)"),
      includeDev: z.boolean().optional().describe("Optional flag to include devDependencies or test dependencies"),
    },
    async ({ manifest_urls, includeDev }) =>
      callApi(`https://dependency-license-audit.apimesh.xyz/audit${qs({ manifest_urls, includeDev })}`),
  );

  server.tool(
    "ssl_tls_configuration_forecast",
    "Comprehensive paid SSL/TLS configuration forecast and security score for a domain",
    {
      domain: z.string().describe("Domain name to analyze (e.g. example.com)"),
    },
    async ({ domain }) =>
      callApi(`https://ssl-tls-configuration-forecast.apimesh.xyz/check${qs({ domain })}`),
  );

  server.tool(
    "subdomain_risk_ranking",
    "Perform a deep, comprehensive subdomain enumeration and risk ranking audit",
    {
      domain: z.string().describe("The root domain to enumerate subdomains for (e.g. example.com)"),
    },
    async ({ domain }) =>
      callApi(`https://subdomain-risk-ranking.apimesh.xyz/rank${qs({ domain })}`),
  );

  server.tool(
    "content_shuffle_detector",
    "Paid comprehensive audit with multiple fetches, deep NLP content variation analysis, content diffing, and scoring to detect content shuffling and obfuscation",
    {
      url: z.string().describe("The target URL (http(s)://...)"),
    },
    async ({ url }) =>
      callApi(`https://content-shuffle-detector.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "api_schema_diff",
    "Compare multiple API schema versions (REST or GraphQL) to highlight differences and score compatibility",
    {
      schemas: z.string().describe("List of schema URLs and version labels to compare"),
    },
    async ({ schemas }) =>
      callApi(`https://api-schema-diff.apimesh.xyz/compare${qs({ schemas })}`),
  );

  server.tool(
    "api_linting",
    "Run a comprehensive linting and validation on provided OpenAPI spec and implementation URLs",
    {
      spec_url: z.string().describe("URL to the OpenAPI specification document (JSON or YAML)."),
      impl_url: z.string().describe("URL to the live API endpoint to test actual implementation."),
    },
    async ({ spec_url, impl_url }) =>
      callApi(`https://api-linting.apimesh.xyz/lint${qs({ spec_url, impl_url })}`),
  );

  server.tool(
    "port_scanner_aggregate",
    "Deep scan of a list of IP addresses or CIDR ranges with multi-source aggregation and vulnerability scoring",
    {
      targets: z.string().describe("List of IP addresses (IPv4 or v6) or CIDR ranges to scan."),
      maxPorts: z.number().optional().describe("Optional limit on number of top common ports to scan per host (default 100)."),
    },
    async ({ targets, maxPorts }) =>
      callApi(`https://port-scanner-aggregate.apimesh.xyz/scan${qs({ targets, maxPorts })}`),
  );

  server.tool(
    "cdn_infrastructure_enricher",
    "Comprehensive paid audit integrating DNS, HTTP headers, IP and regional info with detailed scoring and recommendations",
    {
      url: z.string().describe("Target website URL (http(s)://...) to deeply analyze."),
    },
    async ({ url }) =>
      callApi(`https://cdn-infrastructure-enricher.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "web_configuration_audit",
    "Comprehensive paid audit with detailed scoring, grade, meta tags, and .env leak detection",
    {
      url: z.string().describe("URL to audit (http(s)://...)"),
    },
    async ({ url }) =>
      callApi(`https://web-configuration-audit.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "subdomain_vulnerability_ranker",
    "Exhaustive subdomain enumeration, vulnerability inference, scoring, and recommendations",
    {
      domain: z.string().describe("Target root domain (e.g. example.com)"),
    },
    async ({ domain }) =>
      callApi(`https://subdomain-vulnerability-ranker.apimesh.xyz/scan${qs({ domain })}`),
  );

  server.tool(
    "ssl_tls_inception_score",
    "Comprehensive SSL/TLS certificate and protocol audit for the specified hostname or URL",
    {
      hostname: z.string().describe("Hostname or URL (http(s):// or plain hostname) to analyze SSL/TLS for"),
    },
    async ({ hostname }) =>
      callApi(`https://ssl-tls-inception-score.apimesh.xyz/check${qs({ hostname })}`),
  );

  server.tool(
    "dns_propagation_heatmap",
    "Paid comprehensive DNS propagation audit across multiple resolver types, including scoring and actionable recommendations",
    {
      record: z.string().describe("DNS record full domain name"),
      type: z.string().describe("DNS record type to query"),
    },
    async ({ record, type }) =>
      callApi(`https://dns-propagation-heatmap.apimesh.xyz/check${qs({ record, type })}`),
  );

  server.tool(
    "api_schema_delta",
    "Compare multiple API schemas from given URLs and return detailed diff and evolution analysis",
    {
      urls: z.string().describe("Array of schema URLs to fetch and compare"),
      type: z.string().describe("Type of schema, either REST JSON Schema or GraphQL SDL"),
    },
    async ({ urls, type }) =>
      callApi(`https://api-schema-delta.apimesh.xyz/compare${qs({ urls, type })}`),
  );

  server.tool(
    "port_scanner",
    "Perform a deep port scan on a target IP or hostname",
    {
      target: z.string().describe("Target IP or hostname to scan"),
    },
    async ({ target }) =>
      callApi(`https://port-scanner.apimesh.xyz/scan${qs({ target })}`),
  );

  server.tool(
    "ssl_tls_hardening_assessor",
    "Get a comprehensive SSL/TLS and DNS record security assessment for a hostname",
    {
      host: z.string().describe("Hostname to analyze, e.g. example.com"),
    },
    async ({ host }) =>
      callApi(`https://ssl-tls-hardening-assessor.apimesh.xyz/check${qs({ host })}`),
  );

  server.tool(
    "api_endpoint_discovery",
    "Comprehensively crawl and analyze API endpoints on the specified domain",
    {
      domain: z.string().describe("Target domain to scan, e.g., example.com"),
    },
    async ({ domain }) =>
      callApi(`https://api-endpoint-discovery.apimesh.xyz/discover${qs({ domain })}`),
  );

  server.tool(
    "api_response_heuristics",
    "Comprehensive API response heuristic analysis with scoring and recommendations",
    {
      url: z.string().describe("URL of the API endpoint to analyze"),
    },
    async ({ url }) =>
      callApi(`https://api-response-heuristics.apimesh.xyz/analyze${qs({ url })}`),
  );

  server.tool(
    "api_standard_compliance",
    "Perform a comprehensive API standard compliance analysis on the target API response URL",
    {
      url: z.string().describe("HTTP or HTTPS URL of the API endpoint to analyze"),
    },
    async ({ url }) =>
      callApi(`https://api-standard-compliance.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "content_security_policy_check",
    "Perform a comprehensive security header and content security policy audit",
    {
      url: z.string().describe("The full HTTPS or HTTP URL of the site to analyze"),
    },
    async ({ url }) =>
      callApi(`https://content-security-policy-check.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "cross_origin_resource_policymapper",
    "Perform comprehensive CORS headers audit across multiple endpoints",
    {
      baseUrl: z.string().describe("Base URL or domain to analyze (e.g. https://example.com)"),
      endpoints: z.string().optional().describe("Optional comma-separated list of endpoint paths to analyze (e.g. /api,/auth)"),
    },
    async ({ baseUrl, endpoints }) =>
      callApi(`https://cross-origin-resource-policymapper.apimesh.xyz/check${qs({ baseUrl, endpoints })}`),
  );

  server.tool(
    "dns_propagation_inspector",
    "Comprehensive DNS propagation audit across global resolvers with detailed result analysis",
    {
      domain: z.string().describe("Domain name to check DNS propagation for"),
      recordType: z.string().describe("DNS record type to query, e.g., A, AAAA, CNAME, TXT"),
    },
    async ({ domain, recordType }) =>
      callApi(`https://dns-propagation-inspector.apimesh.xyz/check${qs({ domain, recordType })}`),
  );

  server.tool(
    "performance_security_compliance_report",
    "Comprehensive payable audit combining performance metrics, security headers, SSL cert and DNS analysis with scoring and prioritized fix suggestions",
    {
      url: z.string().describe("Target URL (http(s)://...) to scan."),
    },
    async ({ url }) =>
      callApi(`https://performance-security-compliance-report.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "site_security_baseline",
    "Comprehensive baseline audit with combined security headers, SSL, and configuration checks",
    {
      url: z.string().describe("Target website URL to analyze"),
    },
    async ({ url }) =>
      callApi(`https://site-security-baseline.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "ssl_expiry_forecast",
    "Paid endpoint combining certificate transparency logs, DNS, SSL cert data to forecast expiry across multiple domains",
    {
      domains: z.string().describe("Comma-separated list of domain names to check (max 10 domains)."),
    },
    async ({ domains }) =>
      callApi(`https://ssl-expiry-forecast.apimesh.xyz/check${qs({ domains })}`),
  );

  return server;
}
