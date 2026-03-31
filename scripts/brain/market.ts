import db, { getActiveApis } from "../../shared/db";
import { chatJson } from "../../shared/llm";
import { join } from "path";

const DRAFTS_DIR = join(import.meta.dir, "..", "..", "data", "drafts");
const APIS_DIR = join(import.meta.dir, "..", "..", "apis");

interface MarketingDraft {
  tweet: string;
  devto_title: string;
  devto_body: string;
  use_cases: string[];
  curl_example: string;
}

interface ApiInfo {
  name: string;
  description: string;
  subdomain: string;
  price: string;
  endpoint: string;
}

// ---------------------------------------------------------------------------
// Gather API details for marketing
// ---------------------------------------------------------------------------

function getUnmarketedApis(): ApiInfo[] {
  // Find APIs that haven't been marketed yet
  const rows = db.query(`
    SELECT ar.name, ar.subdomain
    FROM api_registry ar
    WHERE ar.status = 'active'
      AND NOT EXISTS (
        SELECT 1 FROM promotions p
        WHERE p.api_name = ar.name AND p.channel = 'social-drafts'
      )
  `).all() as { name: string; subdomain: string }[];

  if (rows.length === 0) return [];

  const result: ApiInfo[] = [];
  for (const row of rows) {
    const info = getApiInfo(row.name, row.subdomain);
    if (info) result.push(info);
  }
  return result;
}

function getApiInfo(name: string, subdomain: string): ApiInfo | null {
  // Get description from backlog or source
  let description = "";
  const backlog = db.query("SELECT description FROM backlog WHERE name = ?").get(name) as { description: string } | null;
  if (backlog?.description) {
    description = backlog.description;
  }

  // Try to extract endpoint and price from source
  let price = "$0.005";
  let endpoint = "GET /check";
  const indexPath = join(APIS_DIR, name, "index.ts");
  try {
    const src = Bun.file(indexPath).textSync?.() ?? "";
    const priceMatch = src.match(/paidRoute(?:WithDiscovery)?\(\s*["'](\$[\d.]+)["']/);
    if (priceMatch) price = priceMatch[1];
    const loggerMatch = src.match(/apiLogger\(\s*\w+\s*,\s*([\d.]+)\s*\)/);
    if (!priceMatch && loggerMatch) price = `$${loggerMatch[1]}`;

    // Extract main endpoint
    const routeMatch = src.match(/app\.(get|post)\(\s*["'](\/\w+)["']/);
    if (routeMatch) endpoint = `${routeMatch[1].toUpperCase()} ${routeMatch[2]}`;
  } catch {}

  if (!description) description = `${name} API`;

  return {
    name,
    description,
    subdomain,
    price,
    endpoint,
  };
}

function logPromotion(apiName: string, channel: string, status: string, url?: string) {
  db.run(
    `INSERT INTO promotions (api_name, channel, status, url)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(api_name, channel) DO UPDATE SET
       status = excluded.status,
       url = COALESCE(excluded.url, promotions.url),
       created_at = datetime('now')`,
    [apiName, channel, status, url ?? null]
  );
}

// ---------------------------------------------------------------------------
// Generate marketing content via LLM
// ---------------------------------------------------------------------------

async function generateMarketingContent(api: ApiInfo): Promise<MarketingDraft | null> {
  if (!process.env.OPENAI_API_KEY) return null;

  const url = `https://${api.subdomain}.apimesh.xyz`;

  const prompt = `Generate marketing content for this API. Write in a direct, lowercase, developer-friendly voice — no corporate buzzwords, no exclamation marks, no emojis.

API: ${api.name}
Description: ${api.description}
URL: ${url}
Endpoint: ${api.endpoint}
Price: ${api.price} per call

Generate:

1. A tweet (max 280 chars). Format: problem statement → what the api does → curl example or link. Lowercase, casual but technical. Include the URL. Do NOT use hashtags.

2. A Dev.to article title (compelling, specific, SEO-friendly — think "How to X without Y" or "I built a Z because W")

3. A Dev.to article body in markdown. Structure:
   - Open with the PROBLEM (2-3 sentences about why this is annoying)
   - Show the SOLUTION (what the API does, curl example with real output shape)
   - Explain HOW IT WORKS (brief technical detail)
   - End with a TRY IT section (free preview link if applicable, pricing)
   - Keep it under 800 words. Be genuine, not salesy.

4. Three specific use cases (each 1 sentence, describing a real scenario)

5. A curl example command that someone could actually run (use the preview endpoint if available: GET ${url}/preview?...)

CRITICAL: Your response must be valid JSON. In the devto_body field, use standard markdown but escape any backticks inside code blocks as \\u0060 so the JSON parses correctly. Use fenced code blocks with the \\u0060\\u0060\\u0060 escape sequence.

Return JSON: { tweet, devto_title, devto_body, use_cases: string[], curl_example }`;

  try {
    return await chatJson<MarketingDraft>(prompt);
  } catch (err) {
    console.error(`[market] LLM generation failed for ${api.name}:`, err);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Generate SEO tool page HTML
// ---------------------------------------------------------------------------

function generateToolPageHtml(api: ApiInfo, draft: MarketingDraft | null): string {
  const url = `https://${api.subdomain}.apimesh.xyz`;
  const curlCmd = draft?.curl_example ?? `curl ${url}/health`;
  const useCases = draft?.use_cases ?? [`Use ${api.name} in your development workflow`];
  const title = `${api.name.split("-").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ")} API — APIMesh`;
  const desc = api.description;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <meta name="description" content="${desc}">
  <meta name="robots" content="index, follow">
  <link rel="icon" type="image/svg+xml" href="/logo-nav.svg">
  <link rel="canonical" href="https://apimesh.xyz/tools/${api.name}">
  <meta property="og:title" content="${title}">
  <meta property="og:description" content="${desc}">
  <meta property="og:url" content="https://apimesh.xyz/tools/${api.name}">
  <meta property="og:type" content="website">
  <meta name="twitter:card" content="summary">
  <meta name="twitter:title" content="${title}">
  <meta name="twitter:description" content="${desc}">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Inter', sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }
    .container { max-width: 720px; margin: 0 auto; padding: 48px 24px; }
    a { color: #60a5fa; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .breadcrumb { font-size: 14px; color: #888; margin-bottom: 32px; }
    h1 { font-size: 32px; font-weight: 700; color: #fff; margin-bottom: 8px; }
    .subtitle { font-size: 18px; color: #aaa; margin-bottom: 32px; }
    .meta { display: flex; gap: 24px; margin-bottom: 40px; flex-wrap: wrap; }
    .meta-item { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 8px; padding: 12px 16px; }
    .meta-label { font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 0.5px; }
    .meta-value { font-size: 16px; color: #fff; font-weight: 500; font-family: 'JetBrains Mono', monospace; }
    h2 { font-size: 20px; font-weight: 600; color: #fff; margin: 40px 0 16px; }
    .code-block { background: #111; border: 1px solid #2a2a2a; border-radius: 8px; padding: 16px; overflow-x: auto; margin: 16px 0; }
    .code-block code { font-family: 'JetBrains Mono', monospace; font-size: 14px; color: #a5d6ff; white-space: pre; }
    .use-cases { list-style: none; }
    .use-cases li { padding: 12px 0; border-bottom: 1px solid #1a1a1a; color: #ccc; }
    .use-cases li:last-child { border-bottom: none; }
    .use-cases li::before { content: "→ "; color: #60a5fa; }
    .cta { margin-top: 48px; padding: 24px; background: #111; border: 1px solid #2a2a2a; border-radius: 12px; text-align: center; }
    .cta-btn { display: inline-block; background: #60a5fa; color: #000; font-weight: 600; padding: 12px 24px; border-radius: 8px; margin-top: 12px; }
    .cta-btn:hover { background: #93c5fd; text-decoration: none; }
    .footer { margin-top: 64px; padding-top: 24px; border-top: 1px solid #1a1a1a; font-size: 14px; color: #666; text-align: center; }
    @media (max-width: 480px) { .meta { flex-direction: column; } h1 { font-size: 24px; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="breadcrumb"><a href="/"><img src="/logo.svg" alt="" width="16" height="16" style="border-radius:3px;vertical-align:middle;margin-right:4px">APIMesh</a> / <a href="/tools">Tools</a> / ${api.name}</div>

    <h1>${api.name.split("-").map((w: string) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ")}</h1>
    <p class="subtitle">${desc}</p>

    <div class="meta">
      <div class="meta-item">
        <div class="meta-label">Price</div>
        <div class="meta-value">${api.price}/call</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Endpoint</div>
        <div class="meta-value">${api.endpoint}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Base URL</div>
        <div class="meta-value">${url}</div>
      </div>
    </div>

    <h2>Try it</h2>
    <div class="code-block"><code>${curlCmd.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</code></div>

    <h2>Use cases</h2>
    <ul class="use-cases">
      ${useCases.map(uc => `<li>${uc}</li>`).join("\n      ")}
    </ul>

    <h2>Payment methods</h2>
    <p>Every endpoint supports three payment methods:</p>
    <ul class="use-cases">
      <li><strong>x402</strong> — pay per call with USDC on Base. No signup needed.</li>
      <li><strong>MPP</strong> — Stripe Machine Payments Protocol. Cards + stablecoins.</li>
      <li><strong>API key</strong> — traditional auth. <a href="/signup">Sign up</a> and buy credits.</li>
    </ul>

    <h2>MCP integration</h2>
    <div class="code-block"><code>npx @mbeato/apimesh-mcp-server</code></div>
    <p>Adds all APIMesh tools to Claude, Cursor, Windsurf, or any MCP client.</p>

    <div class="cta">
      <p>Ready to integrate?</p>
      <a class="cta-btn" href="${url}/health">Check API health</a>
    </div>

    <div class="footer">
      <a href="/"><img src="/logo.svg" alt="" width="14" height="14" style="border-radius:3px;vertical-align:middle;margin-right:4px">APIMesh</a> · <a href="/dashboard">Dashboard</a> · <a href="https://github.com/mbeato/conway">GitHub</a>
    </div>
  </div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Generate tools index page
// ---------------------------------------------------------------------------

function generateToolsIndexHtml(apis: ApiInfo[]): string {
  const cards = apis.map(api => {
    const url = `https://${api.subdomain}.apimesh.xyz`;
    const title = api.name.split("-").map((w: string) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
    return `      <a href="/tools/${api.name}" class="card">
        <div class="card-name">${title}</div>
        <div class="card-desc">${api.description.slice(0, 120)}${api.description.length > 120 ? "..." : ""}</div>
        <div class="card-meta"><span>${api.price}/call</span><span>${api.endpoint}</span></div>
      </a>`;
  }).join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>All APIs — APIMesh</title>
  <meta name="description" content="${apis.length} pay-per-call APIs for developers and AI agents. Security, performance, SEO, DevOps, and more.">
  <meta name="robots" content="index, follow">
  <link rel="icon" type="image/svg+xml" href="/logo-nav.svg">
  <link rel="canonical" href="https://apimesh.xyz/tools">
  <meta property="og:title" content="All APIs — APIMesh">
  <meta property="og:description" content="${apis.length} pay-per-call APIs for developers and AI agents.">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Inter', sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }
    .container { max-width: 960px; margin: 0 auto; padding: 48px 24px; }
    a { color: #60a5fa; text-decoration: none; }
    .breadcrumb { font-size: 14px; color: #888; margin-bottom: 32px; }
    h1 { font-size: 32px; font-weight: 700; color: #fff; margin-bottom: 8px; }
    .subtitle { font-size: 18px; color: #aaa; margin-bottom: 40px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px; }
    .card { display: block; background: #111; border: 1px solid #2a2a2a; border-radius: 12px; padding: 20px; transition: border-color 0.2s; }
    .card:hover { border-color: #60a5fa; text-decoration: none; }
    .card-name { font-size: 16px; font-weight: 600; color: #fff; margin-bottom: 8px; }
    .card-desc { font-size: 14px; color: #999; margin-bottom: 12px; min-height: 40px; }
    .card-meta { font-size: 12px; font-family: 'JetBrains Mono', monospace; color: #666; display: flex; justify-content: space-between; }
    .footer { margin-top: 64px; padding-top: 24px; border-top: 1px solid #1a1a1a; font-size: 14px; color: #666; text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <div class="breadcrumb"><a href="/"><img src="/logo.svg" alt="" width="16" height="16" style="border-radius:3px;vertical-align:middle;margin-right:4px">APIMesh</a> / Tools</div>
    <h1>All APIs</h1>
    <p class="subtitle">${apis.length} pay-per-call APIs for developers and AI agents</p>
    <div class="grid">
${cards}
    </div>
    <div class="footer">
      <a href="/"><img src="/logo.svg" alt="" width="14" height="14" style="border-radius:3px;vertical-align:middle;margin-right:4px">APIMesh</a> · <a href="/dashboard">Dashboard</a> · <a href="https://github.com/mbeato/conway">GitHub</a>
    </div>
  </div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Write drafts to filesystem
// ---------------------------------------------------------------------------

async function saveDraft(api: ApiInfo, draft: MarketingDraft): Promise<void> {
  const dir = join(DRAFTS_DIR, api.name);
  await Bun.spawn(["mkdir", "-p", dir]).exited;

  // Tweet draft
  await Bun.write(join(dir, "tweet.txt"), draft.tweet);

  // Dev.to article
  const devtoMd = `---
title: "${draft.devto_title}"
published: false
tags: api, webdev, devtools, opensource
---

${draft.devto_body}
`;
  await Bun.write(join(dir, "devto.md"), devtoMd);

  // Use cases
  await Bun.write(join(dir, "use-cases.json"), JSON.stringify(draft.use_cases, null, 2));

  // Curl example
  await Bun.write(join(dir, "curl-example.txt"), draft.curl_example);

  console.log(`[market] Saved drafts to data/drafts/${api.name}/`);
}

// ---------------------------------------------------------------------------
// Generate tool pages for all active APIs
// ---------------------------------------------------------------------------

async function generateToolPages(): Promise<number> {
  const TOOLS_DIR = join(APIS_DIR, "landing", "tools");
  await Bun.spawn(["mkdir", "-p", TOOLS_DIR]).exited;

  const active = getActiveApis();
  const allApis: ApiInfo[] = [];

  // Also scan apis/ directory for APIs not in DB
  const SKIP = new Set(["dashboard", "landing"]);
  try {
    const entries = require("fs").readdirSync(APIS_DIR, { withFileTypes: true });
    const dbNames = new Set(active.map(a => a.name));
    for (const entry of entries) {
      if (!entry.isDirectory() || SKIP.has(entry.name)) continue;
      if (!dbNames.has(entry.name)) {
        // Not in DB but exists on disk — include with default subdomain
        const info = getApiInfo(entry.name, entry.name);
        if (info) allApis.push(info);
      }
    }
  } catch {}

  // Add DB-registered APIs
  for (const api of active) {
    const info = getApiInfo(api.name, api.subdomain);
    if (info) allApis.push(info);
  }

  // Dedupe
  const seen = new Set<string>();
  const uniqueApis = allApis.filter(a => {
    if (seen.has(a.name)) return false;
    seen.add(a.name);
    return true;
  });

  // Generate individual tool pages
  let generated = 0;
  for (const api of uniqueApis) {
    // Check if we have marketing drafts for richer content
    let draft: MarketingDraft | null = null;
    try {
      const draftPath = join(DRAFTS_DIR, api.name, "use-cases.json");
      const curlPath = join(DRAFTS_DIR, api.name, "curl-example.txt");
      if (await Bun.file(draftPath).exists()) {
        const useCases = JSON.parse(await Bun.file(draftPath).text());
        const curlExample = await Bun.file(curlPath).exists() ? await Bun.file(curlPath).text() : "";
        draft = { tweet: "", devto_title: "", devto_body: "", use_cases: useCases, curl_example: curlExample };
      }
    } catch {}

    const html = generateToolPageHtml(api, draft);
    await Bun.write(join(TOOLS_DIR, `${api.name}.html`), html);
    generated++;
  }

  // Generate tools index page
  const indexHtml = generateToolsIndexHtml(uniqueApis);
  await Bun.write(join(TOOLS_DIR, "index.html"), indexHtml);

  console.log(`[market] Generated ${generated} tool pages + index at apis/landing/tools/`);
  return generated;
}

// ---------------------------------------------------------------------------
// Update README tool table
// ---------------------------------------------------------------------------

async function updateReadme(allApis: ApiInfo[]): Promise<void> {
  const readmePath = join(import.meta.dir, "..", "..", "README.md");
  try {
    let readme = await Bun.file(readmePath).text();

    // Update API count badges
    const totalCount = String(allApis.length);
    readme = readme.replace(/APIs-\d+-brightgreen/, `APIs-${totalCount}-brightgreen`);
    readme = readme.replace(/collection of \d+ focused/, `collection of ${totalCount} focused`);

    await Bun.write(readmePath, readme);
    console.log(`[market] Updated README badge count to ${totalCount}`);
  } catch (err) {
    console.error(`[market] README update failed:`, err);
  }
}

// ---------------------------------------------------------------------------
// Main market function
// ---------------------------------------------------------------------------

export async function market(): Promise<void> {
  console.log("[market] Starting marketing pipeline");

  await Bun.spawn(["mkdir", "-p", DRAFTS_DIR]).exited;

  // 1. Find APIs without marketing drafts
  const unmarketedApis = getUnmarketedApis();
  console.log(`[market] Found ${unmarketedApis.length} APIs needing marketing content`);

  // 2. Generate marketing drafts for new APIs (max 3 per run to control LLM costs)
  const MAX_DRAFTS = 10;
  let draftsGenerated = 0;
  for (const api of unmarketedApis.slice(0, MAX_DRAFTS)) {
    console.log(`[market] Generating content for: ${api.name}`);
    const draft = await generateMarketingContent(api);
    if (draft) {
      await saveDraft(api, draft);
      logPromotion(api.name, "social-drafts", "drafted");
      draftsGenerated++;

      // Log the tweet for quick review
      console.log(`[market] Tweet draft for ${api.name}:`);
      console.log(`  ${draft.tweet}`);
    } else {
      logPromotion(api.name, "social-drafts", "failed");
    }
  }
  console.log(`[market] Generated ${draftsGenerated} marketing draft sets`);

  // 3. Generate/update all tool pages (always runs — picks up new APIs)
  await generateToolPages();

  // 4. Update README counts
  const allApis: ApiInfo[] = [];
  const active = getActiveApis();
  for (const api of active) {
    const info = getApiInfo(api.name, api.subdomain);
    if (info) allApis.push(info);
  }
  // Also count apis/ directory
  try {
    const SKIP = new Set(["dashboard", "landing"]);
    const entries = require("fs").readdirSync(APIS_DIR, { withFileTypes: true });
    const dbNames = new Set(active.map(a => a.name));
    for (const entry of entries) {
      if (!entry.isDirectory() || SKIP.has(entry.name) || dbNames.has(entry.name)) continue;
      const info = getApiInfo(entry.name, entry.name);
      if (info) allApis.push(info);
    }
  } catch {}
  await updateReadme(allApis);

  console.log("[market] Done");
}

// Run directly
if (import.meta.main) {
  await market();
}
