# APIMesh

20 x402-payable API tools for AI agents. Pay per call with USDC on Base.

## What is this?

APIMesh is a collection of web analysis APIs designed for AI agents. Every endpoint uses the [x402 payment protocol](https://www.x402.org/) — agents pay per call with USDC on Base (no API keys, no subscriptions, no accounts).

Most tools have **free `/preview` endpoints** so agents can verify the API works before paying.

## Tools

| Tool | Endpoint | Price | What it does |
|------|----------|-------|-------------|
| **Core Web Vitals** | `GET /check?url=` | $0.005 | Lighthouse scores, LCP, CLS, INP field data |
| **Security Headers** | `GET /check?url=` | $0.005 | Audit 10 HTTP security headers with A+ to F grading |
| **SEO Audit** | `GET /check?url=` | $0.003 | On-page SEO analysis with 0-100 score |
| **Email Security** | `GET /check?domain=` | $0.01 | SPF, DKIM, DMARC, MX records with provider detection |
| **Brand Assets** | `GET /check?domain=` | $0.002 | Extract logos, favicons, colors, OG images from any domain |
| **Redirect Chain** | `GET /check?url=` | $0.001 | Trace full redirect chain with per-hop latency |
| **Indexability** | `GET /check?url=` | $0.001 | 5-layer analysis: robots.txt, HTTP status, meta robots, X-Robots-Tag, canonical |
| **Web Checker** | `GET /check?name=` | $0.005 | Brand name availability across 5 TLDs, GitHub, npm, PyPI, Reddit |
| **HTTP Status** | `GET /check?url=` | $0.001 | Live HTTP status check with optional expected code |
| **Favicon Checker** | `GET /check?url=` | $0.001 | Check favicon existence, URL, format |
| **Health Check** | `POST /check` | $0.003 | Parallel health check for up to 10 service URLs |
| **Robots.txt Parser** | `GET /analyze?url=` | $0.001 | Parse robots.txt into structured rules and sitemaps |
| **Email Verify** | `GET /check?email=` | $0.001 | Syntax, MX, disposable domain, role-address, deliverability |
| **Tech Stack** | `GET /check?url=` | $0.003 | Detect CMS, frameworks, analytics, CDN, hosting from headers and HTML |

Plus 6 utility APIs (regex builder, YAML validator, JWT generator, UA analyzer, status codes, Swagger docs).

Each tool lives on its own subdomain: `https://{tool-name}.apimesh.xyz`

## Quick Start

### Try a free preview (no payment needed)

```bash
curl https://core-web-vitals.apimesh.xyz/preview?url=https://example.com
curl https://security-headers.apimesh.xyz/preview?url=https://example.com
curl https://check.apimesh.xyz/preview?name=myapp
```

### Use via MCP (Claude, Cursor, etc.)

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

### Direct API usage

```bash
# Hit any paid endpoint — get a 402 with payment details
curl https://core-web-vitals.apimesh.xyz/check?url=https://example.com

# Include x402 payment header — get the response
curl -H "X-PAYMENT: ..." https://core-web-vitals.apimesh.xyz/check?url=https://example.com
```

## Discovery

- **MCP Registry**: [`io.github.mbeato/apimesh`](https://registry.modelcontextprotocol.io)
- **x402 Discovery**: `https://apimesh.xyz/.well-known/x402`
- **AI Docs**: `https://apimesh.xyz/llms.txt`
- **x402scan**: [apimesh on x402scan](https://www.x402scan.com/server/4ee5dce3-d33c-40c1-91b0-c39891936b2c)
- **npm**: [`@mbeato/apimesh-mcp-server`](https://www.npmjs.com/package/@mbeato/apimesh-mcp-server)

## How x402 Works

1. Agent sends a request to any paid endpoint
2. Server returns `402 Payment Required` with payment details (price, wallet, network)
3. Agent signs a USDC payment on Base and includes it in the `X-PAYMENT` header
4. Server verifies payment via Coinbase CDP facilitator and returns the response

No API keys. No accounts. No subscriptions. Just pay and use.

## Tech Stack

- [Bun](https://bun.sh) runtime
- [Hono](https://hono.dev) web framework
- [x402](https://www.x402.org/) payment protocol
- [Caddy](https://caddyserver.com) reverse proxy with automatic HTTPS
- SQLite for analytics

## License

MIT
