# Retired APIs

This file is the gravestone for the marketplace-era APIs that lived under
`apis/*` from early 2026 through May 2026. None of them survived the pivot.
Their code lives forever in git history and on the archive branch
[`archive/marketplace-2026-04-pre-prune`](https://github.com/mbeato/conway/tree/archive/marketplace-2026-04-pre-prune).

## What was built

100 single-purpose web-analysis APIs, served as Hono sub-apps behind Caddy with
wildcard `*.apimesh.xyz` DNS and wildcard TLS via Cloudflare DNS-01. Each API
lived on its own subdomain (`<name>.apimesh.xyz`), had its own `index.ts` and
its own paid route definition for `.well-known/x402` discovery.

Three payment rails were wired end-to-end so agents and humans could pay
without signup:

- **x402** — USDC on Base mainnet via Coinbase CDP. HTTP 402 challenge with
  price + wallet + network, signed `X-PAYMENT` header on retry, CDP verifies,
  response served.
- **MPP** — Stripe Machine Payments via the `mppx` SDK. First-party listing
  alongside Browserbase and Dune at launch.
- **API-key credits** — hand-rolled Stripe Checkout flow + webhook signature
  verify against the live secret. Atomic credit deduction before each call so
  failed requests cost nothing.

A self-hosted MCP HTTP server at `mcp.apimesh.xyz` plus a distributed
[`@mbeato/apimesh-mcp-server`](https://www.npmjs.com/package/@mbeato/apimesh-mcp-server)
npm package exposed every registered API as an MCP tool, plus 2
wallet-management tools, for clients like Claude Desktop / Cursor / Continue.

## The autonomous brain

Under `scripts/brain/` (still in the repo, currently off) ran a systemd-timer
pipeline that built APIs without human involvement:

```
monitor → scout → build → market → distribute
```

- **scout** — npm-signal mining for API opportunities, OpenAI scoring against
  a 4-dimension quality rubric calibrated on real APIs
- **build** — multi-file code generation with gpt-4.1-mini, sandboxed
  subprocess testing on a stripped-env port-3099 instance, 6-retry loop, 14
  security-audit rules (prompt injection, .env isolation, SSRF defenses, input
  size caps) before any code reached the registry
- **market** — generated tweet drafts, dev.to articles, SEO landing pages,
  sitemap.xml, changelog entries
- **distribute** — directory submissions, MCP-client monitor, GitHub starring,
  awesome-mpp ecosystem registry updates

At its peak the brain shipped 9 APIs autonomously with prod-health rollback,
zero human merges.

## Why it was retired

The marketplace framing did not convert. Across the platform:

- **Total paid calls: 0** (across every payment rail)
- **Total unique paid users: 0**
- **Total revenue: $0.00**

Two underlying reasons:

1. **Wrong buyer assumption.** The pitch assumed agents would be the primary
   buyers — every API was sized, priced, and documented for an LLM client. In
   practice the actual visitors were human devs who wanted flat-rate
   subscriptions on focused tools, not per-call micropayments on a hundred
   half-built endpoints.
2. **Breadth without signal.** The autonomous build loop optimized for *number
   of APIs shipped* rather than *whether any single API had a paying user*.
   90% of brain-generated APIs got 0 organic clicks and 100% scanner traffic.
   The 4-dimension quality rubric measured code quality, not market fit.

The pivot — single-pain wedge products with their own subdomains, own SEO
terms, own demos, optional flat pricing — is documented in the apimesh case
study on [mbeato.dev/work/apimesh](https://mbeato.dev/work/apimesh) and lives
on under `apis/agentcontext/` (agentsmd) and `apis/sigdebug/` (stripesig).

## What's preserved on the archive branch

Everything. `git checkout archive/marketplace-2026-04-pre-prune` restores the
full registry, every API directory, every test, every brain-state JSON. The
deploy pipeline still works against that branch. Nothing about the marketplace
is unrecoverable.

## Lessons worth keeping

- Autonomous breadth needs a market-fit signal in the scoring rubric, not just
  a code-quality one. The brain shipped clean code that nobody wanted.
- Free `/preview` endpoints did not produce paid follow-throughs. The
  conversion gap wasn't trust — it was that the underlying tool wasn't
  worth paying for. No amount of preview-tier optimization fixes a
  commoditized core.
- "$0.001 per call" pricing trains agents to be price-sensitive but trains
  humans to wonder if it's serious. Flat per-month is the path with humans;
  per-call is the path with agents, and the agent-buyer market in 2026 is
  smaller than the press releases suggest.
- Per-subdomain DNS + Caddy + wildcard TLS scales to 100+ services for $4/mo
  on a CAX11. The infra was never the bottleneck.
