<p align="center">
  <a href="https://apimesh.xyz">
    <img src="public/logo-nav.svg" alt="APIMesh" width="80" height="80" />
  </a>
</p>
<h1 align="center">APIMesh</h1>

[![npm version](https://img.shields.io/npm/v/@mbeato/apimesh-mcp-server)](https://www.npmjs.com/package/@mbeato/apimesh-mcp-server)
[![npm downloads](https://img.shields.io/npm/dm/@mbeato/apimesh-mcp-server)](https://www.npmjs.com/package/@mbeato/apimesh-mcp-server)
[![APIs](https://img.shields.io/badge/APIs-97-brightgreen)](https://apimesh.xyz)
[![MCP Tools](https://img.shields.io/badge/MCP%20tools-67-blue)](https://www.npmjs.com/package/@mbeato/apimesh-mcp-server)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)
[![Payments](https://img.shields.io/badge/payments-x402%20%7C%20MPP%20%7C%20API%20key-orange)](#payment-methods)
[![SafeSkill 20/100](https://img.shields.io/badge/SafeSkill-20%2F100_Blocked-red)](https://safeskill.dev/scan/mbeato-apimesh)

**Pay-per-call web analysis APIs for AI agents and developers.** Security audits, performance monitoring, SEO analysis, email verification, tech stack detection, and more -- no signup required, just pay with USDC on Base and get your response.

APIMesh is a collection of 97 focused web analysis APIs, each on its own subdomain, with a 67-tool MCP server for direct use in Claude, Cursor, Windsurf, Cline, and any MCP-compatible client. Every endpoint supports three payment methods: crypto micropayments via [x402](https://www.x402.org/), card payments via [Stripe MPP](https://mpp.dev), and traditional API keys via [Stripe checkout](https://apimesh.xyz/signup).

[**Live Site**](https://apimesh.xyz) -- [**Dashboard**](https://apimesh.xyz/dashboard) -- [**npm**](https://www.npmjs.com/package/@mbeato/apimesh-mcp-server) -- [**MCP Registry**](https://registry.modelcontextprotocol.io) -- [**Smithery**](https://smithery.ai/servers/apimesh/apimesh-mcp-server)

---

## Quick Start

### Try free previews (no payment, no signup)

```bash
curl https://core-web-vitals.apimesh.xyz/preview?url=https://example.com
curl https://security-headers.apimesh.xyz/preview?url=https://example.com
curl https://seo-audit.apimesh.xyz/preview?url=https://example.com
curl https://check.apimesh.xyz/preview?name=myapp
```

### Install the MCP server

One command to add all 67 tools to your AI coding assistant:

```bash
npx @mbeato/apimesh-mcp-server
```

Or add to your MCP client config (`claude_desktop_config.json`, `.cursor/mcp.json`, etc.):

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
# 1. Hit any paid endpoint -- returns 402 with payment details
curl https://core-web-vitals.apimesh.xyz/check?url=https://example.com

# 2. Include x402 payment header -- returns the full response
curl -H "X-PAYMENT: <signed-usdc-payment>" \
  https://core-web-vitals.apimesh.xyz/check?url=https://example.com
```

---

## All APIs

Every API lives on its own subdomain: `https://{api-name}.apimesh.xyz`

### Web Analysis APIs

| API | Endpoint | Price | Description |
|-----|----------|-------|-------------|
| **Core Web Vitals** | `GET /check?url=` | $0.005 | Lighthouse scores, LCP, CLS, INP field data, performance/accessibility/SEO grades |
| **Security Headers** | `GET /check?url=` | $0.005 | Audit 10 HTTP security headers with A+ to F grading and remediation tips |
| **SEO Audit** | `GET /check?url=` | $0.003 | On-page SEO analysis: title, meta, headings, images, links, OG tags, JSON-LD (0-100 score) |
| **Email Security** | `GET /check?domain=` | $0.01 | SPF, DKIM (probes 10 selectors), DMARC, MX records with provider detection |
| **Brand Assets** | `GET /check?domain=` | $0.002 | Extract logos, favicons, theme colors, OG images, site name from any domain |
| **Redirect Chain** | `GET /check?url=` | $0.001 | Trace full redirect chain with per-hop status codes, latency, and loop detection |
| **Indexability** | `GET /check?url=` | $0.001 | 5-layer analysis: robots.txt, HTTP status, meta robots, X-Robots-Tag, canonical |
| **Web Checker** | `GET /check?name=` | $0.005 | Brand name availability across 5 TLDs, GitHub, npm, PyPI, Reddit |
| **HTTP Status** | `GET /check?url=` | $0.001 | Live HTTP status check with optional expected status code |
| **Favicon Checker** | `GET /check?url=` | $0.001 | Check favicon existence, URL, and format |
| **Health Check** | `POST /check` | $0.003 | Parallel health check for up to 10 service URLs |
| **Robots.txt Parser** | `GET /analyze?url=` | $0.001 | Parse robots.txt into structured rules, sitemaps, and crawl directives |
| **Email Verify** | `GET /check?email=` | $0.001 | Syntax validation, MX check, disposable domain detection, role-address, deliverability |
| **Tech Stack** | `GET /check?url=` | $0.003 | Detect CMS, frameworks, analytics, CDN, hosting, JS libraries from headers + HTML |

### Developer Utility APIs

| API | Endpoint | Price | Description |
|-----|----------|-------|-------------|
| **Regex Builder** | `POST /build` | $0.002 | Generate and test regex patterns from natural language descriptions |
| **YAML Validator** | `POST /validate` | $0.002 | Validate YAML syntax and structure |
| **Mock JWT Generator** | `POST /generate` | $0.001 | Generate test JWTs with custom claims and expiry |
| **User Agent Analyzer** | `GET /analyze?ua=` | $0.002 | Parse user agent strings into browser, OS, device, and bot info |
| **Status Code Checker** | `GET /check?code=` | $0.001 | Lookup HTTP status code meaning and usage |
| **Swagger Docs Creator** | `POST /generate` | $0.002 | Generate OpenAPI 3.0 documentation for your API endpoints |

### Autonomously Built APIs

These APIs were built, tested, and deployed by APIMesh's autonomous brain loop — no human wrote the code:

| API | Endpoint | Price | Description |
|-----|----------|-------|-------------|
| **Web Resource Validator** | `GET /validate?resource=` | $0.005 | Validate presence of robots.txt, sitemap.xml, openapi.json, agent.json |
| **Website Security Header Info** | `GET /check?url=` | $0.01 | Analyze security-related HTTP headers (CSP, HSTS, X-Frame-Options, etc.) |
| **Website Vulnerability Scan** | `GET /scan?url=` | $0.01 | Comprehensive security audit combining SSL, headers, cookies, and CSP analysis |
| **SEO Health Analyzer** | `GET /check?url=` | $0.005 | 5-layer indexability analysis with robots.txt, meta robots, and canonical checks |
| **Comprehensive Site Audit** | `GET /check?url=` | $0.01 | Multi-signal website audit combining health, security, performance, and tech stack |
| **Performance Structure Report** | `GET /check?url=` | $0.01 | Deep performance audit with network tracing, asset analysis, and server headers |
| **Domain Authenticity Verify** | `GET /check?domain=` | $0.005 | Multi-signal domain legitimacy verification via WHOIS, DNS, SSL, and web presence |
| **Performance and Availability Report** | `GET /check?url=` | $0.005 | Website performance metrics, uptime history from DNS and server response analysis |
| **Domain Intelligence Aggregator** | `GET /check?domain=` | $0.005 | WHOIS, DNS records, SSL certificates, and historical analysis in a single report |

New APIs are added automatically as the brain discovers demand and builds solutions. See [How the Brain Works](#the-autonomous-brain) below.

### Wallet & Spend Tracking (free, no auth)

| Endpoint | Description |
|----------|-------------|
| `GET /wallet/{address}` | Spend summary (daily/7d/30d), active spend cap, recent requests |
| `GET /wallet/{address}/history` | Paginated transaction history, filterable by API |
| `PUT /wallet/{address}/cap` | Set daily/monthly spend caps on your wallet |

---

## Payment Methods

APIMesh supports three ways to pay:

### 1. x402 -- crypto micropayments (default)

```
Agent request --> 402 Payment Required (price, wallet, network)
                  Agent signs USDC on Base --> includes X-PAYMENT header
                  Server verifies via Coinbase CDP --> returns response
```

No accounts. No API keys. No subscriptions. The agent handles payment autonomously.

- **Protocol:** [x402](https://www.x402.org/) (open standard)
- **Currency:** USDC on Base (chain ID 8453)
- **Facilitator:** Coinbase CDP

### 2. MPP -- Stripe Machine Payments Protocol

[Stripe MPP](https://mpp.dev) enables AI agents to pay with cards or stablecoins through Stripe's infrastructure.

### 3. API key + credits

Traditional auth for developers who prefer it. Purchase credits via [Stripe checkout](https://apimesh.xyz/signup) and include your API key in requests.

---

## Discovery & Integration

| Channel | Link |
|---------|------|
| **npm** | [`@mbeato/apimesh-mcp-server`](https://www.npmjs.com/package/@mbeato/apimesh-mcp-server) |
| **MCP Registry** | [`io.github.mbeato/apimesh`](https://registry.modelcontextprotocol.io) |
| **Smithery** | [apimesh-mcp-server](https://smithery.ai/servers/apimesh/apimesh-mcp-server) |
| **x402scan** | [apimesh](https://www.x402scan.com/server/4ee5dce3-d33c-40c1-91b0-c39891936b2c) |
| **x402 discovery** | `https://apimesh.xyz/.well-known/x402` |
| **AI docs** | `https://apimesh.xyz/llms.txt` |
| **AI plugin** | `https://apimesh.xyz/.well-known/ai-plugin.json` |

Most APIs offer free `/preview` endpoints so agents can verify functionality before paying. Every API has free `/health` and `/` info endpoints.

---

## The Autonomous Brain

APIMesh has an autonomous build loop that runs daily on the server. It discovers demand, generates APIs, tests them, and deploys to production — no human in the loop. It also maintains the [awesome-mpp](https://github.com/mbeato/awesome-mpp) ecosystem directory.

```
Monitor → Scanner → Scout → Build → Security Audit → Staging → Prod
  │         │        │          │              │        │
  │         │        │          │              │        └─ verify health
  ��         │        │          │              └─ deploy + test endpoints
  │         │        │          └─ static analysis (secrets, SSRF, eval, etc.)
  │         │        └─ LLM generates multi-file Hono API (up to 6 retries)
  │         └─ gather market signals, score opportunities with LLM
  └─ check API health, revenue, error rates
```

**Hardened against prompt injection:** external signal data is sanitized, LLM prompts use system-role security rules, generated code is audited for 14+ vulnerability patterns, and the test environment is sandboxed with `.env` isolation.

The brain currently uses OpenAI (`gpt-4.1-mini`) for code generation and scores opportunities based on demand, implementation depth, and competitive differentiation.

---

## Tech Stack

- [Bun](https://bun.sh) -- runtime and bundler
- [Hono](https://hono.dev) -- web framework
- [x402](https://www.x402.org/) + [MPP](https://mpp.dev) -- payment protocols
- [Caddy](https://caddyserver.com) -- reverse proxy with automatic HTTPS
- SQLite -- analytics and usage tracking
- OpenAI -- autonomous API generation

---

## Related

- [awesome-mpp](https://github.com/mbeato/awesome-mpp) -- the MPP ecosystem registry (100+ projects)

---

## Contributing

Contributions are welcome. If you find a bug or want to suggest a new API tool, [open an issue](https://github.com/mbeato/APIMesh/issues) or [start a discussion](https://github.com/mbeato/APIMesh/discussions).

To run locally:

```bash
git clone https://github.com/mbeato/APIMesh.git
cd conway
bun install
bun --hot apis/router.ts
```

---

## License

[MIT](LICENSE)
