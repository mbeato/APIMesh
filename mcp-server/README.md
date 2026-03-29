# APIMesh MCP Server

23 pay-per-call web analysis APIs as MCP tools for Claude, Cursor, Windsurf, Cline, and any MCP-compatible client.

## Install

```bash
npx @mbeato/apimesh-mcp-server
```

Or add to your MCP config:

```json
{
  "mcpServers": {
    "apimesh": {
      "command": "npx",
      "args": ["@mbeato/apimesh-mcp-server"]
    }
  }
}
```

## Tools (19)

| Tool | Description |
|------|-------------|
| `core_web_vitals` | Google PageSpeed Insights — Lighthouse scores, LCP, CLS, INP |
| `security_headers` | Audit 10 HTTP security headers with A+ to F grading |
| `seo_audit` | On-page SEO analysis with 0-100 score |
| `email_security` | SPF, DKIM, DMARC, MX records with provider detection |
| `brand_assets` | Extract logos, favicons, colors, OG images from any domain |
| `redirect_chain` | Trace full redirect chain with per-hop latency |
| `indexability_check` | Robots.txt, HTTP status, meta robots, X-Robots-Tag, canonical |
| `web_checker` | Brand name availability across 5 TLDs, GitHub, npm, PyPI, Reddit |
| `email_verify` | Syntax, MX, disposable domain, role-address, deliverability |
| `tech_stack` | Detect CMS, frameworks, analytics, CDN, hosting from headers + HTML |
| `http_status` | Live HTTP status check |
| `favicon_check` | Check favicon existence, URL, and format |
| `health_check` | Parallel health check for up to 10 URLs |
| `robots_txt_parse` | Parse robots.txt into structured rules and sitemaps |
| `user_agent_analyze` | Parse user agent strings into browser, OS, device info |
| `status_code_lookup` | HTTP status code meaning and usage |
| `web_resource_validator` | Validate robots.txt, sitemap.xml, openapi.json presence |
| `website_security_header_info` | Analyze security HTTP headers (CSP, HSTS, etc.) |
| `website_vulnerability_scan` | Comprehensive security audit — SSL, headers, cookies, CSP |

## Payment

All tools use free preview data by default. For full analysis, endpoints support:
- **x402** — USDC micropayments on Base
- **MPP** — Stripe Machine Payments Protocol
- **API key** — traditional auth via [apimesh.xyz/signup](https://apimesh.xyz/signup)

## Links

- [Live Site](https://apimesh.xyz)
- [npm](https://www.npmjs.com/package/@mbeato/apimesh-mcp-server)
- [GitHub](https://github.com/mbeato/conway)

## License

MIT
