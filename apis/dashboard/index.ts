import { Hono } from "hono";
import { cors } from "hono/cors";
import { bearerAuth } from "hono/bearer-auth";
import { setCookie, getCookie, deleteCookie } from "hono/cookie";
import { resolve, join } from "path";
import db, { getRevenueByApi, getTotalRevenue, getRequestCount, getErrorRate, getApiRevenue, getRecentRequests, getActiveApis, getDailyRevenue, getDailyRequests, getHourlyRequests, getAuditLog, getWalletSummaries, getAllSpendCaps, upsertSpendCap, deleteSpendCap, getWalletSpend, getSpendCap, getApiDetailedStats, getApiRequests, getApiErrors, getApiStatusBreakdown, getSignupNotificationCounts, getRecentSignupNotifications, getEventCounts } from "../../shared/db";
import { WALLET_ADDRESS } from "../../shared/x402";
import { rateLimit } from "../../shared/rate-limit";
import { hashPassword, verifyPassword, createSession, getSession, deleteSession, deleteUserSessions, refreshSessionExpiry, logAuthEvent } from "../../shared/auth";
import { normalizeEmail, validateEmail, validatePassword } from "../../shared/validation";
import { sendVerificationCode, sendPasswordResetCode } from "../../shared/email";
import { initBalance, getBalance, addCredits, getTransactions } from "../../shared/credits";
import { createCheckoutSession, CREDIT_TIERS, verifyWebhookSignature, STRIPE_WEBHOOK_SECRET } from "../../shared/stripe";
import { checkAuthRateLimit } from "../../shared/auth-rate-limit";
import { isPasswordBreached } from "../../shared/hibp";
import { createApiKey, getUserKeys, revokeApiKey } from "../../shared/api-key";

const app = new Hono();

function resolvePort(envVar: string, defaultPort: number): number {
  const raw = process.env[envVar];
  if (!raw) return defaultPort;
  const port = parseInt(raw, 10);
  if (isNaN(port) || port < 1024 || port > 65535) {
    console.error(`FATAL: ${envVar}=${raw} is not a valid port (1024-65535)`);
    process.exit(1);
  }
  return port;
}

const PORT = resolvePort("DASHBOARD_PORT", 3000);

const DASHBOARD_TOKEN = process.env.DASHBOARD_TOKEN;
if (!DASHBOARD_TOKEN) {
  console.error("FATAL: DASHBOARD_TOKEN env var not set");
  process.exit(1);
}
if (DASHBOARD_TOKEN.length < 32) {
  console.error("FATAL: DASHBOARD_TOKEN must be at least 32 characters (use: openssl rand -hex 24)");
  process.exit(1);
}

// Pre-compute dummy hash at startup for constant-time login (no first-request penalty)
const DUMMY_HASH_PROMISE = hashPassword("dummy-password-for-constant-time-login");

// Registration gate — set REGISTRATION_ENABLED=false on staging to block new signups
const REGISTRATION_ENABLED = process.env.REGISTRATION_ENABLED !== "false";

// Rate limit for public routes (higher limit, still bounded)
const publicLimit = rateLimit("dashboard-public", 120, 60_000);
const webhookLimit = rateLimit("billing-webhook", 30, 60_000);

// Health check — no rate limit, must work from localhost monitoring
app.get("/health", (c) => c.json({ status: "ok" }));

// --- Stripe webhook (MUST be early — needs raw body, no CSP, no auth) ---
app.post("/billing/webhook", webhookLimit, async (c) => {
  if (!STRIPE_WEBHOOK_SECRET) {
    console.error("[billing] Webhook received but STRIPE_WEBHOOK_SECRET not configured");
    return c.json({ error: "Webhook not configured" }, 500);
  }

  const signature = c.req.header("stripe-signature");
  if (!signature) {
    return c.json({ error: "Missing Stripe-Signature header" }, 400);
  }

  // Read raw body for signature verification — BEFORE any JSON parsing
  const rawBody = await c.req.text();

  if (!verifyWebhookSignature(rawBody, signature, STRIPE_WEBHOOK_SECRET)) {
    console.error("[billing] Webhook signature verification failed");
    return c.json({ error: "Invalid signature" }, 400);
  }

  // Signature verified — now parse the event
  let event: any;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data?.object;
    if (!session) {
      console.error("[billing] Webhook checkout.session.completed missing data.object");
      return c.json({ received: true }, 200);
    }

    const userId = session.metadata?.user_id;
    const tier = session.metadata?.tier;
    const paymentIntent = session.payment_intent;

    // Derive credits from server-side tier config, not from metadata
    const tierConfig = tier ? CREDIT_TIERS[tier] : null;
    if (!userId || !tierConfig || !paymentIntent) {
      console.error("[billing] Webhook missing required metadata:", { userId, tier, paymentIntent });
      return c.json({ received: true }, 200);
    }
    const creditsAmount = tierConfig.credits;

    // Verify user exists
    const user = db.query("SELECT id FROM users WHERE id = ?").get(userId) as { id: string } | null;
    if (!user) {
      console.error(`[billing] Webhook user_id ${userId} not found in database`);
      return c.json({ received: true }, 200);
    }

    // Grant credits (idempotent — addCredits handles duplicate stripe_payment_intent)
    const result = addCredits(db, userId, creditsAmount, `${tier} tier purchase`, paymentIntent);

    if (result.success) {
      logAuthEvent(db, userId, "credit_purchase", "", "", {
        tier,
        credits: creditsAmount,
        payment_intent: paymentIntent,
        new_balance: result.newBalance,
      });
      console.log(`[billing] Granted ${creditsAmount} credits to user ${userId} (${tier} tier, pi: ${paymentIntent})`);
    } else if (result.error === "duplicate") {
      console.log(`[billing] Duplicate webhook for payment_intent ${paymentIntent}, skipping`);
    } else {
      console.error(`[billing] Failed to grant credits for ${paymentIntent}:`, result);
    }
  }

  // Always return 200 to acknowledge receipt (even for unhandled event types)
  return c.json({ received: true }, 200);
});

// Serve discovery files at root (Caddy proxies apimesh.xyz to dashboard)
app.get("/llms.txt", publicLimit, async (c) => {
  const file = Bun.file("public/llms.txt");
  if (await file.exists()) return c.text(await file.text());
  return c.text("# apimesh.xyz\nNo llms.txt generated yet.\n", 404);
});

// robots.txt — fully public, tells crawlers they're welcome
app.get("/robots.txt", publicLimit, (c) => {
  const body = [
    "User-agent: *",
    "Allow: /",
    "Disallow: /auth/",
    "Disallow: /account/",
    "Disallow: /billing/",
    "",
    "Sitemap: https://apimesh.xyz/sitemap.xml",
    "",
  ].join("\n");
  return c.text(body, 200, { "Content-Type": "text/plain; charset=utf-8" });
});

// Platform-level MPP manifest — JSON for MPP/agent-ecosystem crawlers.
// Mirrors per-subdomain /.well-known/mpp but aggregates all APIs.
app.get("/.well-known/mpp", publicLimit, async (c) => {
  const { buildPlatformManifest } = await import("../../shared/mpp-manifest");
  const host = c.req.header("host") ?? "apimesh.xyz";
  return c.json(buildPlatformManifest(host));
});

// /openapi.json — minimal aggregate: links to per-API OpenAPI under each subdomain.
// Full aggregate spec is a later improvement; crawlers probing this path should
// get a valid 200 with actionable pointers rather than a 401.
app.get("/openapi.json", publicLimit, async (c) => {
  const { buildPlatformManifest } = await import("../../shared/mpp-manifest");
  const host = c.req.header("host") ?? "apimesh.xyz";
  const manifest = buildPlatformManifest(host);
  return c.json({
    openapi: "3.1.0",
    info: {
      title: "APIMesh",
      version: "1.0.0",
      description: manifest.description,
      contact: { email: manifest.provider.contact, url: manifest.provider.url },
    },
    servers: manifest.apis.map(a => ({ url: a.endpoint.replace(/\/[^/]*$/, ""), description: a.name })),
    paths: {},
    "x-apimesh-apis": manifest.apis,
    "x-discovery": manifest.discovery,
  });
});

app.get("/.well-known/*", publicLimit, async (c) => {
  // Path traversal protection: resolve and validate containment
  const baseDir = resolve("public/.well-known");
  const decoded = decodeURIComponent(c.req.path);
  const filePath = resolve(join("public", decoded));

  if (!filePath.startsWith(baseDir + "/") && filePath !== baseDir) {
    return c.json({ error: "Not found" }, 404);
  }

  const file = Bun.file(filePath);
  if (await file.exists()) {
    const ext = filePath.split(".").pop();
    const ct = ext === "json" ? "application/json" : "text/plain";
    return c.text(await file.text(), 200, { "Content-Type": ct });
  }
  return c.json({ error: "Not found" }, 404);
});

// Legal pages — static, publicly cached
const LEGAL_PAGES = ["terms", "privacy", "acceptable-use", "refund", "cookies", "abuse"];
for (const page of LEGAL_PAGES) {
  app.get(`/legal/${page}`, publicLimit, async (c) => {
    const file = Bun.file(join(import.meta.dir, `../landing/legal/${page}.html`));
    if (await file.exists()) {
      return new Response(await file.text(), {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'",
          "X-Content-Type-Options": "nosniff",
          "Cache-Control": "public, max-age=86400",
        },
      });
    }
    return c.text("Page not found", 404);
  });
}

// Landing page — public, no auth (served at apimesh.xyz root)
app.get("/", publicLimit, async (c) => {
  const file = Bun.file(join(import.meta.dir, "../landing/landing.html"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
      },
    });
  }
  return c.text("Landing page not found", 404);
});

// Dashboard UI — public, no auth
app.get("/dashboard", publicLimit, async (c) => {
  const file = Bun.file(join(import.meta.dir, "dashboard.html"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
      },
    });
  }
  return c.text("Dashboard not found", 404);
});

// Dashboard JS — external script (CSP: script-src 'self')
app.get("/dashboard.js", publicLimit, async (c) => {
  const file = Bun.file(join(import.meta.dir, "dashboard.js"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "application/javascript; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-cache",
      },
    });
  }
  return c.text("Not found", 404);
});

// Tools index page — SEO landing pages for all APIs
app.get("/tools", publicLimit, async (c) => {
  const file = Bun.file(join(import.meta.dir, "../landing/tools/index.html"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "public, max-age=3600",
      },
    });
  }
  return c.text("Page not found", 404);
});

// Individual tool page — SEO landing page per API
app.get("/tools/:name", publicLimit, async (c) => {
  const name = c.req.param("name").replace(/[^a-z0-9-]/g, "");
  const file = Bun.file(join(import.meta.dir, `../landing/tools/${name}.html`));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "public, max-age=3600",
      },
    });
  }
  return c.text("Tool not found", 404);
});

// Signup page — public, no auth (blocked when registration disabled)
app.get("/signup", publicLimit, async (c) => {
  if (!REGISTRATION_ENABLED) return c.redirect("/login");
  const file = Bun.file(join(import.meta.dir, "../landing/signup.html"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
      },
    });
  }
  return c.text("Page not found", 404);
});

// Login page — public, no auth
app.get("/login", publicLimit, async (c) => {
  const file = Bun.file(join(import.meta.dir, "../landing/login.html"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
      },
    });
  }
  return c.text("Page not found", 404);
});

// Verify page — public, no auth (blocked when registration disabled)
app.get("/verify", publicLimit, async (c) => {
  if (!REGISTRATION_ENABLED) return c.redirect("/login");
  const file = Bun.file(join(import.meta.dir, "../landing/verify.html"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
      },
    });
  }
  return c.text("Page not found", 404);
});

// Forgot password page — public, no auth
app.get("/forgot-password", publicLimit, async (c) => {
  const file = Bun.file(join(import.meta.dir, "../landing/forgot-password.html"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
      },
    });
  }
  return c.text("Page not found", 404);
});

// Landing JS — external script (CSP: script-src 'self')
app.get("/landing.js", publicLimit, async (c) => {
  const file = Bun.file(join(import.meta.dir, "../landing/landing.js"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "application/javascript; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-cache",
      },
    });
  }
  return c.text("Not found", 404);
});

// --- Public tools endpoint for landing page (no auth) ---
const TOOL_DESCRIPTIONS: Record<string, { desc: string; price: string }> = {
  "web-checker": { desc: "Check brand/product name availability across 5 TLDs, GitHub, npm, PyPI, and Reddit in one call.", price: "$0.005" },
  "core-web-vitals": { desc: "Google PageSpeed Insights — Lighthouse performance, accessibility, SEO scores plus LCP, CLS, INP field data.", price: "$0.005" },
  "security-headers": { desc: "Audit 10 HTTP security headers with A+ to F grading and remediation suggestions.", price: "$0.005" },
  "redirect-chain": { desc: "Trace the full HTTP redirect chain with per-hop status codes, latency, and loop detection.", price: "$0.001" },
  "email-security": { desc: "Validate SPF, DKIM, and DMARC records. Detects email provider and grades overall email security.", price: "$0.01" },
  "seo-audit": { desc: "On-page SEO analysis — title, meta, headings, images, links, OG tags, JSON-LD with a 0-100 score.", price: "$0.003" },
  "indexability": { desc: "5-layer indexability analysis — robots.txt, HTTP status, meta robots, X-Robots-Tag, and canonical.", price: "$0.001" },
  "indexability-checker": { desc: "5-layer indexability analysis — robots.txt, HTTP status, meta robots, X-Robots-Tag, and canonical.", price: "$0.001" },
  "brand-assets": { desc: "Extract brand assets from any domain — logo URL, favicon, theme colors, OG image, and site name.", price: "$0.002" },
  "email-verify": { desc: "Verify email addresses — syntax, MX record, disposable domain, role-address, and deliverability.", price: "$0.001" },
  "tech-stack": { desc: "Detect website technology stack — CMS, frameworks, analytics, CDN, hosting, JS libs from headers and HTML.", price: "$0.003" },
  "http-status-checker": { desc: "Check the live HTTP status of any URL with optional expected status code validation.", price: "$0.002" },
  "favicon-checker": { desc: "Check whether a website has a favicon and returns its URL, format, and status.", price: "$0.002" },
  "microservice-health-check": { desc: "Check health and response times of up to 10 service URLs in parallel.", price: "$0.003" },
  "robots-txt-parser": { desc: "Parse robots.txt into structured rules, sitemaps, and crawl directives.", price: "$0.002" },
  "status-code-checker": { desc: "Look up HTTP status code meaning and usage.", price: "$0.001" },
  "regex-builder": { desc: "Generate and test regex patterns from natural language descriptions.", price: "$0.002" },
  "user-agent-analyzer": { desc: "Parse user agent strings into browser, OS, device, and bot info.", price: "$0.002" },
  "mock-jwt-generator": { desc: "Generate test JWTs with custom claims and expiry for local development.", price: "$0.001" },
  "yaml-validator": { desc: "Validate YAML syntax and structure.", price: "$0.002" },
  "swagger-docs-creator": { desc: "Generate OpenAPI 3.0 documentation for your API endpoints.", price: "$0.002" },
  "web-resource-validator": { desc: "Validate presence and correctness of common web resources (robots.txt, sitemap.xml, openapi.json, agent.json) for any domain.", price: "$0.002" },
  "website-security-header-info": { desc: "Analyze security-related HTTP headers — CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy — with issue detection.", price: "$0.002" },
  "website-vulnerability-scan": { desc: "Comprehensive website security audit: hostname, SSL, headers, cookies, and CSP analysis with a 0-100 score and actionable recommendations.", price: "$0.005" },
  "seo-health-analyzer": { desc: "5-layer indexability analysis — robots.txt, HTTP status, meta robots, X-Robots-Tag, and canonical.", price: "$0.001" },
};

app.get("/api/tools", publicLimit, (c) => {
  const apis = getActiveApis();
  const tools = apis.map((api) => {
    const detail = getApiDetailedStats(api.name);
    const override = TOOL_DESCRIPTIONS[api.name];
    let price = override?.price ?? "$0.005";
    let description = override?.desc ?? "";
    // Fallback to backlog for brain-built APIs
    if (!description) {
      const backlog = db.query("SELECT description FROM backlog WHERE name = ?").get(api.name) as { description: string } | null;
      description = backlog?.description ?? `${api.name} API`;
    }
    return {
      name: api.name,
      subdomain: api.subdomain,
      price,
      description,
      total_requests: detail.total_requests,
      created_at: api.created_at,
    };
  });
  return c.json({ tools, count: tools.length });
});

// --- Public wallet endpoints (no auth, rate-limited) ---
const walletLimit = rateLimit("dashboard-wallet", 30, 60_000);
const WALLET_RE = /^0x[0-9a-fA-F]{40}$/;

app.get("/wallet/:address", walletLimit, (c) => {
  const addr = c.req.param("address");
  if (!addr || !WALLET_RE.test(addr)) {
    return c.json({ error: "Invalid wallet address" }, 400);
  }
  const wallet = addr.toLowerCase();
  const spend1d = getWalletSpend(wallet, 1);
  const spend7d = getWalletSpend(wallet, 7);
  const spend30d = getWalletSpend(wallet, 30);
  const cap = getSpendCap(wallet);
  const recent = getAuditLog(wallet, undefined, 10, 0);

  return c.json({
    wallet,
    spend: { daily: spend1d, last_7d: spend7d, last_30d: spend30d },
    cap: cap ? {
      daily_limit_usd: cap.daily_limit_usd,
      monthly_limit_usd: cap.monthly_limit_usd,
      daily_remaining: cap.daily_limit_usd !== null ? Math.max(0, cap.daily_limit_usd - spend1d) : null,
      monthly_remaining: cap.monthly_limit_usd !== null ? Math.max(0, cap.monthly_limit_usd - spend30d) : null,
    } : null,
    recent_requests: recent.rows,
    total_requests: recent.total,
  });
});

app.get("/wallet/:address/history", walletLimit, (c) => {
  const addr = c.req.param("address");
  if (!addr || !WALLET_RE.test(addr)) {
    return c.json({ error: "Invalid wallet address" }, 400);
  }
  const wallet = addr.toLowerCase();
  const limit = Math.max(1, Math.min(100, parseInt(c.req.query("limit") || "50", 10) || 50));
  const offset = Math.max(0, parseInt(c.req.query("offset") || "0", 10) || 0);
  const apiFilter = c.req.query("api") || undefined;
  if (apiFilter && apiFilter.length > 64) {
    return c.json({ error: "Invalid api name" }, 400);
  }

  const result = getAuditLog(wallet, apiFilter, limit, offset);
  return c.json({
    wallet,
    rows: result.rows,
    total: result.total,
    limit,
    offset,
    has_more: offset + limit < result.total,
  });
});

app.put("/wallet/:address/cap", walletLimit, bearerAuth({ token: DASHBOARD_TOKEN }), async (c) => {
  const addr = c.req.param("address");
  if (!addr || !WALLET_RE.test(addr)) {
    return c.json({ error: "Invalid wallet address" }, 400);
  }
  const wallet = addr.toLowerCase();
  const MAX_BODY = 4096;
  const contentLength = parseInt(c.req.header("content-length") || "0", 10);
  if (contentLength > MAX_BODY) {
    return c.json({ error: "Request body too large" }, 413);
  }
  const rawBody = await c.req.arrayBuffer();
  if (rawBody.byteLength > MAX_BODY) {
    return c.json({ error: "Request body too large" }, 413);
  }
  let body: any;
  try {
    body = JSON.parse(new TextDecoder().decode(rawBody));
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }
  const { label, daily_limit_usd, monthly_limit_usd } = body;

  if (label !== undefined && label !== null) {
    if (typeof label !== "string") return c.json({ error: "Label must be a string or null" }, 400);
    if (label.length > 128) return c.json({ error: "Label must be 128 characters or fewer" }, 400);
  }
  if (daily_limit_usd !== undefined && daily_limit_usd !== null) {
    if (typeof daily_limit_usd !== "number" || !Number.isFinite(daily_limit_usd) || daily_limit_usd <= 0) {
      return c.json({ error: "daily_limit_usd must be a finite positive number or null" }, 400);
    }
  }
  if (monthly_limit_usd !== undefined && monthly_limit_usd !== null) {
    if (typeof monthly_limit_usd !== "number" || !Number.isFinite(monthly_limit_usd) || monthly_limit_usd <= 0) {
      return c.json({ error: "monthly_limit_usd must be a finite positive number or null" }, 400);
    }
  }

  upsertSpendCap(wallet, label ?? null, daily_limit_usd ?? null, monthly_limit_usd ?? null);
  return c.json({ ok: true, wallet });
});

// --- Verification code secret ---
const VERIFICATION_CODE_SECRET = process.env.VERIFICATION_CODE_SECRET || "dev-only-secret-change-in-production";
if (process.env.NODE_ENV === "production" && VERIFICATION_CODE_SECRET === "dev-only-secret-change-in-production") {
  console.error("FATAL: VERIFICATION_CODE_SECRET must be set in production");
  process.exit(1);
}

// --- Auth helper functions (private) ---

function generateVerificationCode(): string {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return String(arr[0] % 1000000).padStart(6, "0");
}

async function hashCode(code: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(VERIFICATION_CODE_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(code));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getIp(c: any): string {
  return c.req.header("x-real-ip") || "127.0.0.1";
}

function getUserAgent(c: any): string {
  return c.req.header("user-agent") || "";
}

// --- Progressive lockout thresholds (highest first, first match wins) ---
const LOCKOUT_THRESHOLDS = [
  { failures: 20, duration: '+24 hours' },
  { failures: 10, duration: '+1 hour' },
  { failures: 5, duration: '+15 minutes' },
];

// --- CSRF check: all mutating requests must come from our own JS ---
function csrfCheck(c: any): boolean {
  const xrw = c.req.header("x-requested-with");
  return xrw?.toLowerCase() === "xmlhttprequest";
}

// --- Auth routes (public, before bearerAuth) ---
const authLimit = rateLimit("dashboard-auth", 60, 60_000);

app.post("/auth/signup", authLimit, async (c) => {
  if (!REGISTRATION_ENABLED) return c.json({ error: "Registration is disabled on this environment" }, 403);
  if (!csrfCheck(c)) return c.json({ error: "Forbidden" }, 403);
  const ip = getIp(c);
  const userAgent = getUserAgent(c);

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  const { email, password, tos_agree, website } = body;

  // Honeypot: real form hides "website" with CSS; real users never fill it.
  // Bots that submit every field trip this and get a generic error.
  if (typeof website === "string" && website.length > 0) {
    logAuthEvent(db, null, "signup_honeypot", ip, userAgent);
    return c.json({ error: "Signup failed" }, 400);
  }

  if (!email || !password) {
    return c.json({ error: "Email and password are required" }, 400);
  }

  if (!tos_agree) {
    return c.json({ error: "You must agree to the Terms of Service and Privacy Policy" }, 400);
  }

  // Rate limit by IP
  const rl = checkAuthRateLimit(db, "signup", ip);
  if (!rl.allowed) {
    c.header("Retry-After", String(rl.retryAfter));
    return c.json({ error: "Too many signup attempts. Try again later." }, 429);
  }

  // Validate email
  const normalized = normalizeEmail(email);
  const emailCheck = validateEmail(normalized);
  if (!emailCheck.valid) {
    return c.json({ error: emailCheck.error }, 400);
  }

  // Validate password strength
  const pwCheck = validatePassword(password);
  if (!pwCheck.valid) {
    return c.json({ error: pwCheck.error, score: pwCheck.score }, 400);
  }

  // Check HIBP breach
  const breached = await isPasswordBreached(password);
  if (breached) {
    return c.json({ error: "This password has appeared in a data breach. Please choose a different password." }, 400);
  }

  // Check if email exists
  const existing = db.query("SELECT id, email_verified FROM users WHERE email = ?").get(normalized) as { id: string; email_verified: number } | null;
  if (existing && existing.email_verified) {
    return c.json({ error: "An account with this email already exists." }, 400);
  }
  if (existing && !existing.email_verified) {
    // Delete old unverified user and all referencing rows to allow re-signup
    db.run("DELETE FROM auth_events WHERE user_id = ?", [existing.id]);
    db.run("DELETE FROM sessions WHERE user_id = ?", [existing.id]);
    db.run("DELETE FROM api_keys WHERE user_id = ?", [existing.id]);
    db.run("DELETE FROM credit_transactions WHERE user_id = ?", [existing.id]);
    db.run("DELETE FROM credit_balances WHERE user_id = ?", [existing.id]);
    db.run("DELETE FROM verification_codes WHERE user_id = ?", [existing.id]);
    db.run("DELETE FROM users WHERE id = ?", [existing.id]);
  }

  // Create user
  const userId = crypto.randomUUID();
  const passwordHash = await hashPassword(password);
  db.run(
    "INSERT INTO users (id, email, password_hash, tos_accepted_at) VALUES (?, ?, ?, datetime('now'))",
    [userId, normalized, passwordHash]
  );

  // Init credit balance
  initBalance(db, userId);

  // Generate verification code
  const code = generateVerificationCode();
  const codeHash = await hashCode(code);
  const codeId = crypto.randomUUID();

  // Delete any prior verification codes for this user+purpose
  db.run("DELETE FROM verification_codes WHERE user_id = ? AND purpose = 'email_verification'", [userId]);

  // Insert new code with 10-minute expiry
  db.run(
    "INSERT INTO verification_codes (id, user_id, code_hash, purpose, expires_at) VALUES (?, ?, ?, 'email_verification', datetime('now', '+10 minutes'))",
    [codeId, userId, codeHash]
  );

  // Send verification email
  await sendVerificationCode(normalized, code);

  // Log auth event
  logAuthEvent(db, userId, "signup", ip, userAgent);

  return c.json({ success: true, redirect: `/verify?email=${encodeURIComponent(normalized)}` });
});

app.post("/auth/verify", authLimit, async (c) => {
  if (!REGISTRATION_ENABLED) return c.json({ error: "Registration is disabled on this environment" }, 403);
  if (!csrfCheck(c)) return c.json({ error: "Forbidden" }, 403);
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  const { email, code } = body;
  if (!email || !code) {
    return c.json({ error: "Email and code are required" }, 400);
  }

  const normalized = normalizeEmail(email);
  const ip = getIp(c);
  const userAgent = getUserAgent(c);

  // Rate limit by email
  const rl = checkAuthRateLimit(db, "verify-code", normalized);
  if (!rl.allowed) {
    c.header("Retry-After", String(rl.retryAfter));
    return c.json({ error: "Too many verification attempts. Request a new code." }, 429);
  }

  // Find user
  const user = db.query("SELECT id, email_verified FROM users WHERE email = ?").get(normalized) as { id: string; email_verified: number } | null;
  if (!user) {
    return c.json({ error: "Invalid email or verification code." }, 400);
  }

  if (user.email_verified) {
    return c.json({ error: "Email is already verified." }, 400);
  }

  // Find valid verification code
  const verCode = db.query(
    "SELECT id, code_hash, attempts FROM verification_codes WHERE user_id = ? AND purpose = 'email_verification' AND expires_at > datetime('now') ORDER BY created_at DESC LIMIT 1"
  ).get(user.id) as { id: string; code_hash: string; attempts: number } | null;

  if (!verCode) {
    return c.json({ error: "Verification code expired or not found." }, 400);
  }

  // Atomically increment attempts (only if < 3)
  const updateResult = db.run(
    "UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ? AND attempts < 3",
    [verCode.id]
  );

  if (updateResult.changes === 0) {
    return c.json({ error: "Too many attempts. Request a new code." }, 400);
  }

  // Hash submitted code and compare
  const submittedHash = await hashCode(String(code).trim());
  if (submittedHash !== verCode.code_hash) {
    return c.json({ error: "Invalid verification code." }, 400);
  }

  // Success: verify email, cleanup codes, auto-login
  db.run("UPDATE users SET email_verified = 1, updated_at = datetime('now') WHERE id = ?", [user.id]);
  db.run("DELETE FROM verification_codes WHERE user_id = ? AND purpose = 'email_verification'", [user.id]);

  // Create session so user is logged in immediately
  const sessionToken = createSession(db, user.id, ip, userAgent);
  setCookie(c, "session", sessionToken, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    maxAge: 30 * 24 * 60 * 60,
  });

  logAuthEvent(db, user.id, "email_verified", ip, userAgent);
  logAuthEvent(db, user.id, "login", ip, userAgent);

  return c.json({ success: true, redirect: "/account" });
});

app.post("/auth/resend-code", authLimit, async (c) => {
  if (!REGISTRATION_ENABLED) return c.json({ error: "Registration is disabled on this environment" }, 403);
  if (!csrfCheck(c)) return c.json({ error: "Forbidden" }, 403);
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  const { email } = body;
  if (!email) {
    return c.json({ error: "Email is required" }, 400);
  }

  const normalized = normalizeEmail(email);
  const ip = getIp(c);

  // Rate limit by email AND IP
  const rlEmail = checkAuthRateLimit(db, "resend-code-email", normalized);
  if (!rlEmail.allowed) {
    c.header("Retry-After", String(rlEmail.retryAfter));
    return c.json({ error: "Please wait before requesting another code." }, 429);
  }

  const rlIp = checkAuthRateLimit(db, "resend-code-ip", ip);
  if (!rlIp.allowed) {
    c.header("Retry-After", String(rlIp.retryAfter));
    return c.json({ error: "Too many resend requests. Try again later." }, 429);
  }

  // Find user — return generic success even if not found (prevent enumeration)
  const user = db.query("SELECT id, email_verified FROM users WHERE email = ?").get(normalized) as { id: string; email_verified: number } | null;
  if (!user || user.email_verified) {
    return c.json({ success: true });
  }

  // Delete existing codes, generate new one
  db.run("DELETE FROM verification_codes WHERE user_id = ? AND purpose = 'email_verification'", [user.id]);

  const code = generateVerificationCode();
  const codeHash = await hashCode(code);
  const codeId = crypto.randomUUID();

  db.run(
    "INSERT INTO verification_codes (id, user_id, code_hash, purpose, expires_at) VALUES (?, ?, ?, 'email_verification', datetime('now', '+10 minutes'))",
    [codeId, user.id, codeHash]
  );

  await sendVerificationCode(normalized, code);

  return c.json({ success: true });
});

// --- Login route ---
app.post("/auth/login", authLimit, async (c) => {
  if (!csrfCheck(c)) return c.json({ error: "Forbidden" }, 403);
  const ip = getIp(c);
  const userAgent = getUserAgent(c);

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  const { email, password } = body;
  if (!email || !password) {
    return c.json({ error: "Email and password are required" }, 400);
  }

  // Rate limit by IP
  const rl = checkAuthRateLimit(db, "login", ip);
  if (!rl.allowed) {
    c.header("Retry-After", String(rl.retryAfter));
    return c.json({ error: "Too many login attempts. Try again later." }, 429);
  }

  const normalized = normalizeEmail(email);

  // Look up user (includes lockout fields for progressive lockout)
  const user = db.query(
    "SELECT id, email, password_hash, email_verified, failed_logins, locked_until FROM users WHERE email = ?"
  ).get(normalized) as { id: string; email: string; password_hash: string; email_verified: number; failed_logins: number; locked_until: string | null } | null;

  if (!user) {
    // Constant-time: verify against dummy hash so timing is identical
    await verifyPassword(password, await DUMMY_HASH_PROMISE);
    logAuthEvent(db, null, "login_failed", ip, userAgent, { reason: "unknown_email" });
    return c.json({ error: "Invalid email or password." }, 401);
  }

  // Check lockout status (but always run verifyPassword for constant-time)
  const isLocked = user.locked_until && new Date(user.locked_until + "Z") > new Date();

  // Always verify password (even for locked/unverified users) to maintain constant timing
  const passwordValid = await verifyPassword(password, user.password_hash);

  if (isLocked) {
    // Account locked — return same generic error as wrong password (anti-enumeration)
    logAuthEvent(db, user.id, "login_failed", ip, userAgent, { reason: "account_locked" });
    return c.json({ error: "Invalid email or password." }, 401);
  }

  if (!passwordValid) {
    // Increment failed login counter
    db.run("UPDATE users SET failed_logins = failed_logins + 1, updated_at = datetime('now') WHERE id = ?", [user.id]);

    // Check if lockout threshold reached
    const updated = db.query("SELECT failed_logins FROM users WHERE id = ?").get(user.id) as { failed_logins: number };
    for (const threshold of LOCKOUT_THRESHOLDS) {
      if (updated.failed_logins >= threshold.failures) {
        db.run("UPDATE users SET locked_until = datetime('now', ?) WHERE id = ?", [threshold.duration, user.id]);
        logAuthEvent(db, user.id, "account_locked", ip, userAgent, { failed_logins: updated.failed_logins, duration: threshold.duration });
        break;
      }
    }

    logAuthEvent(db, user.id, "login_failed", ip, userAgent, { reason: "wrong_password" });
    return c.json({ error: "Invalid email or password." }, 401);
  }

  if (!user.email_verified) {
    // Only reveal unverified status if password is correct (anti-enumeration)
    return c.json({
      error: "email_not_verified",
      redirect: `/verify?email=${encodeURIComponent(normalized)}`,
    }, 401);
  }

  // Password valid, email verified — reset lockout counter and create session
  if (user.failed_logins > 0) {
    db.run("UPDATE users SET failed_logins = 0, locked_until = NULL, updated_at = datetime('now') WHERE id = ?", [user.id]);
  }
  const sessionId = createSession(db, user.id, ip, userAgent);

  setCookie(c, "session", sessionId, {
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    maxAge: 30 * 24 * 60 * 60, // 30 days
  });

  logAuthEvent(db, user.id, "login", ip, userAgent);

  return c.json({ success: true, redirect: "/account" });
});

// --- Logout route ---
app.post("/auth/logout", authLimit, async (c) => {
  if (!csrfCheck(c)) return c.json({ error: "Forbidden" }, 403);
  const ip = getIp(c);
  const userAgent = getUserAgent(c);
  const sessionId = getCookie(c, "session");

  if (sessionId) {
    const session = getSession(db, sessionId);
    if (session) {
      deleteSession(db, sessionId);
      logAuthEvent(db, session.user_id, "logout", ip, userAgent);
    }
  }

  deleteCookie(c, "session", { path: "/", httpOnly: true, secure: true, sameSite: "Lax" });

  return c.json({ success: true, redirect: "/login" });
});

// --- User-agent parser (session management) ---
function parseUserAgent(ua: string): { browser: string; os: string } {
  let browser = "Unknown";
  let os = "Unknown";
  if (/Edg\/(\d+)/.test(ua)) browser = "Edge " + RegExp.$1;
  else if (/Chrome\/(\d+)/.test(ua)) browser = "Chrome " + RegExp.$1;
  else if (/Firefox\/(\d+)/.test(ua)) browser = "Firefox " + RegExp.$1;
  else if (/Safari\/(\d+)/.test(ua) && /Version\/(\d+)/.test(ua)) browser = "Safari " + RegExp.$1;
  if (/Windows NT/.test(ua)) os = "Windows";
  else if (/Mac OS X/.test(ua)) os = /iPhone|iPad/.test(ua) ? "iOS" : "macOS";
  else if (/Android/.test(ua)) os = "Android";
  else if (/Linux/.test(ua)) os = "Linux";
  return { browser, os };
}

// --- Session helper (private function, Phase 3 will formalize as middleware) ---
async function getAuthenticatedUser(c: any): Promise<{ userId: string; sessionId: string } | null> {
  const sessionId = getCookie(c, "session");
  if (!sessionId) return null;
  const session = getSession(db, sessionId);
  if (!session) return null;
  refreshSessionExpiry(db, sessionId);
  return { userId: session.user_id, sessionId };
}

// --- Forgot Password route ---
app.post("/auth/forgot-password", authLimit, async (c) => {
  if (!csrfCheck(c)) return c.json({ error: "Forbidden" }, 403);
  const ip = getIp(c);
  const userAgent = getUserAgent(c);

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  const { email } = body;
  if (!email) {
    return c.json({ error: "Email is required" }, 400);
  }

  const normalized = normalizeEmail(email);
  const emailCheck = validateEmail(normalized);
  if (!emailCheck.valid) {
    return c.json({ error: emailCheck.error }, 400);
  }

  // Rate limit by IP and email
  const rlIp = checkAuthRateLimit(db, "password-reset-ip", ip);
  if (!rlIp.allowed) {
    c.header("Retry-After", String(rlIp.retryAfter));
    return c.json({ error: "Too many requests. Try again later." }, 429);
  }

  const rlEmail = checkAuthRateLimit(db, "password-reset-email", normalized);
  if (!rlEmail.allowed) {
    c.header("Retry-After", String(rlEmail.retryAfter));
    return c.json({ error: "Too many requests. Try again later." }, 429);
  }

  // Look up user — always return success regardless (anti-enumeration)
  const user = db.query("SELECT id, email_verified FROM users WHERE email = ?").get(normalized) as { id: string; email_verified: number } | null;

  if (user && user.email_verified) {
    // Delete old password reset codes
    db.run("DELETE FROM verification_codes WHERE user_id = ? AND purpose = 'password_reset'", [user.id]);

    // Generate and hash code
    const code = generateVerificationCode();
    const codeHash = await hashCode(code);
    const codeId = crypto.randomUUID();

    // Insert with 10-minute expiry
    db.run(
      "INSERT INTO verification_codes (id, user_id, code_hash, purpose, expires_at) VALUES (?, ?, ?, 'password_reset', datetime('now', '+10 minutes'))",
      [codeId, user.id, codeHash]
    );

    // Send reset code email
    await sendPasswordResetCode(normalized, code);
  }

  logAuthEvent(db, user?.id ?? null, "password_reset_requested", ip, userAgent);

  return c.json({ success: true });
});

// --- Reset Password route ---
app.post("/auth/reset-password", authLimit, async (c) => {
  if (!csrfCheck(c)) return c.json({ error: "Forbidden" }, 403);
  const ip = getIp(c);
  const userAgent = getUserAgent(c);

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  const { email, code, password } = body;
  if (!email || !code || !password) {
    return c.json({ error: "Email, code, and new password are required" }, 400);
  }

  // Rate limit by IP
  const rlIp = checkAuthRateLimit(db, "password-reset-ip", ip);
  if (!rlIp.allowed) {
    c.header("Retry-After", String(rlIp.retryAfter));
    return c.json({ error: "Too many requests. Try again later." }, 429);
  }

  // Rate limit by email
  const normalized = normalizeEmail(email);
  const rlEmail = checkAuthRateLimit(db, "password-reset-email", normalized);
  if (!rlEmail.allowed) {
    c.header("Retry-After", String(rlEmail.retryAfter));
    return c.json({ error: "Too many requests. Try again later." }, 429);
  }

  // Look up user
  const user = db.query("SELECT id, failed_logins FROM users WHERE email = ?").get(normalized) as { id: string; failed_logins: number } | null;
  if (!user) {
    return c.json({ error: "Invalid or expired code." }, 400);
  }

  // Look up valid verification code
  const verCode = db.query(
    "SELECT id, code_hash, attempts FROM verification_codes WHERE user_id = ? AND purpose = 'password_reset' AND expires_at > datetime('now') ORDER BY created_at DESC LIMIT 1"
  ).get(user.id) as { id: string; code_hash: string; attempts: number } | null;

  if (!verCode) {
    return c.json({ error: "Invalid or expired code." }, 400);
  }

  // Check max attempts
  if (verCode.attempts >= 3) {
    db.run("DELETE FROM verification_codes WHERE id = ?", [verCode.id]);
    return c.json({ error: "Too many attempts. Request a new code." }, 400);
  }

  // HMAC-verify the code
  const submittedHash = await hashCode(String(code).trim());
  if (submittedHash !== verCode.code_hash) {
    db.run("UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?", [verCode.id]);
    return c.json({ error: "Invalid or expired code." }, 400);
  }

  // Validate new password strength
  const pwCheck = validatePassword(password);
  if (!pwCheck.valid) {
    return c.json({ error: pwCheck.error, score: pwCheck.score }, 400);
  }

  // Check HIBP breach
  const breached = await isPasswordBreached(password);
  if (breached) {
    return c.json({ error: "This password has appeared in a data breach. Please choose a different password." }, 400);
  }

  // Hash new password and update user
  const passwordHash = await hashPassword(password);
  db.run(
    "UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = NULL, updated_at = datetime('now') WHERE id = ?",
    [passwordHash, user.id]
  );

  // Delete the verification code
  db.run("DELETE FROM verification_codes WHERE id = ?", [verCode.id]);

  // Delete ALL sessions
  deleteUserSessions(db, user.id);

  // Create fresh session (auto-login)
  const sessionToken = createSession(db, user.id, ip, userAgent);
  setCookie(c, "session", sessionToken, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    maxAge: 30 * 24 * 60 * 60,
  });

  logAuthEvent(db, user.id, "password_reset_completed", ip, userAgent);

  return c.json({ success: true, redirect: "/account" });
});

// --- Change Password route (session required) ---
app.post("/auth/change-password", authLimit, async (c) => {
  if (!csrfCheck(c)) return c.json({ error: "Forbidden" }, 403);
  const ip = getIp(c);
  const userAgent = getUserAgent(c);

  const auth = await getAuthenticatedUser(c);
  if (!auth) {
    return c.json({ error: "Not authenticated." }, 401);
  }

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  const { currentPassword, newPassword } = body;
  if (!currentPassword || !newPassword) {
    return c.json({ error: "Current password and new password are required" }, 400);
  }

  // Look up user password hash
  const user = db.query("SELECT password_hash FROM users WHERE id = ?").get(auth.userId) as { password_hash: string } | null;
  if (!user) {
    return c.json({ error: "User not found." }, 400);
  }

  // Verify current password
  const passwordValid = await verifyPassword(currentPassword, user.password_hash);
  if (!passwordValid) {
    return c.json({ error: "Current password is incorrect." }, 401);
  }

  // Validate new password strength
  const pwCheck = validatePassword(newPassword);
  if (!pwCheck.valid) {
    return c.json({ error: pwCheck.error, score: pwCheck.score }, 400);
  }

  // Check HIBP breach
  const breached = await isPasswordBreached(newPassword);
  if (breached) {
    return c.json({ error: "This password has appeared in a data breach. Please choose a different password." }, 400);
  }

  // Hash and update
  const passwordHash = await hashPassword(newPassword);
  db.run(
    "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?",
    [passwordHash, auth.userId]
  );

  // Invalidate all OTHER sessions (keep current)
  deleteUserSessions(db, auth.userId, auth.sessionId);

  logAuthEvent(db, auth.userId, "password_changed", ip, userAgent);

  return c.json({ success: true });
});

// --- Session management endpoints ---

// GET /auth/sessions — list active sessions for current user
app.get("/auth/sessions", authLimit, async (c) => {
  const auth = await getAuthenticatedUser(c);
  if (!auth) {
    return c.json({ error: "Not authenticated." }, 401);
  }

  const sessions = db.query(
    "SELECT id, ip_address, user_agent, created_at FROM sessions WHERE user_id = ? AND expires_at > datetime('now') ORDER BY created_at DESC"
  ).all(auth.userId) as Array<{ id: string; ip_address: string; user_agent: string; created_at: string }>;

  const result = sessions.map((s) => {
    const parsed = parseUserAgent(s.user_agent);
    return {
      id: s.id,
      ip_address: s.ip_address,
      browser: parsed.browser,
      os: parsed.os,
      created_at: s.created_at,
      is_current: s.id === auth.sessionId,
    };
  });

  return c.json(result);
});

// DELETE /auth/sessions/:id — revoke a specific session (not current)
app.delete("/auth/sessions/:id", authLimit, async (c) => {
  if (!csrfCheck(c)) return c.json({ error: "Forbidden" }, 403);
  const auth = await getAuthenticatedUser(c);
  if (!auth) {
    return c.json({ error: "Not authenticated." }, 401);
  }

  const ip = getIp(c);
  const userAgent = getUserAgent(c);
  const targetId = c.req.param("id");

  if (targetId === auth.sessionId) {
    return c.json({ error: "Cannot revoke your current session. Use logout instead." }, 400);
  }

  // Verify target session belongs to this user
  const target = db.query("SELECT id FROM sessions WHERE id = ? AND user_id = ?").get(targetId, auth.userId) as { id: string } | null;
  if (!target) {
    return c.json({ error: "Session not found." }, 404);
  }

  deleteSession(db, targetId);
  logAuthEvent(db, auth.userId, "session_revoked", ip, userAgent, { revoked_session: targetId.slice(0, 8) });

  return c.json({ success: true });
});

// DELETE /auth/sessions — revoke all other sessions
app.delete("/auth/sessions", authLimit, async (c) => {
  if (!csrfCheck(c)) return c.json({ error: "Forbidden" }, 403);
  const auth = await getAuthenticatedUser(c);
  if (!auth) {
    return c.json({ error: "Not authenticated." }, 401);
  }

  const ip = getIp(c);
  const userAgent = getUserAgent(c);

  deleteUserSessions(db, auth.userId, auth.sessionId);
  logAuthEvent(db, auth.userId, "all_sessions_revoked", ip, userAgent);

  return c.json({ success: true });
});

// --- API Key management endpoints ---

// POST /auth/keys — create a new API key
app.post("/auth/keys", authLimit, async (c) => {
  if (!csrfCheck(c)) return c.json({ error: "Forbidden" }, 403);
  const auth = await getAuthenticatedUser(c);
  if (!auth) {
    return c.json({ error: "Not authenticated." }, 401);
  }

  const ip = getIp(c);
  const userAgent = getUserAgent(c);

  // Per-user key ops rate limit
  const rlKeyOps = checkAuthRateLimit(db, "key-ops", auth.userId);
  if (!rlKeyOps.allowed) {
    c.header("Retry-After", String(rlKeyOps.retryAfter));
    return c.json({ error: "Too many key operations. Try again later." }, 429);
  }

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  const label = typeof body.label === "string" ? body.label.trim() : "";
  if (!label || label.length > 64) {
    return c.json({ error: "Label is required (max 64 characters)." }, 400);
  }

  const result = createApiKey(db, auth.userId, label);
  if ("error" in result) {
    return c.json({ error: result.error }, 400);
  }

  logAuthEvent(db, auth.userId, "api_key_created", ip, userAgent, { key_id: result.id, prefix: result.prefix });

  return c.json({
    success: true,
    key: {
      id: result.id,
      plaintext: result.plaintext,
      prefix: result.prefix,
      label: label,
    },
  });
});

// GET /auth/keys — list user's API keys
app.get("/auth/keys", authLimit, async (c) => {
  const auth = await getAuthenticatedUser(c);
  if (!auth) {
    return c.json({ error: "Not authenticated." }, 401);
  }

  const keys = getUserKeys(db, auth.userId);
  return c.json({ keys });
});

// DELETE /auth/keys/:id — revoke an API key
app.delete("/auth/keys/:id", authLimit, async (c) => {
  if (!csrfCheck(c)) return c.json({ error: "Forbidden" }, 403);
  const auth = await getAuthenticatedUser(c);
  if (!auth) {
    return c.json({ error: "Not authenticated." }, 401);
  }

  const ip = getIp(c);
  const userAgent = getUserAgent(c);

  // Per-user key ops rate limit
  const rlKeyOps = checkAuthRateLimit(db, "key-ops", auth.userId);
  if (!rlKeyOps.allowed) {
    c.header("Retry-After", String(rlKeyOps.retryAfter));
    return c.json({ error: "Too many key operations. Try again later." }, 429);
  }

  const keyId = c.req.param("id");

  const revoked = revokeApiKey(db, keyId, auth.userId);
  if (!revoked) {
    return c.json({ error: "Key not found or already revoked." }, 404);
  }

  logAuthEvent(db, auth.userId, "api_key_revoked", ip, userAgent, { key_id: keyId });

  return c.json({ success: true });
});

// --- Billing routes (session-protected) ---
app.post("/billing/checkout", authLimit, async (c) => {
  if (!csrfCheck(c)) return c.json({ error: "Forbidden" }, 403);
  const auth = await getAuthenticatedUser(c);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  const ip = getIp(c);
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  const { tier } = body;
  if (!tier || typeof tier !== "string" || !CREDIT_TIERS[tier]) {
    return c.json({ error: "Invalid tier. Must be one of: starter, builder, pro, scale" }, 400);
  }

  const user = db.query("SELECT email FROM users WHERE id = ?").get(auth.userId) as { email: string } | null;
  if (!user) return c.json({ error: "User not found" }, 404);

  const result = await createCheckoutSession(auth.userId, user.email, tier);

  if ("error" in result) {
    return c.json({ error: result.error }, 500);
  }

  logAuthEvent(db, auth.userId, "checkout_initiated", ip, getUserAgent(c), { tier });
  return c.json({ checkout_url: result.url });
});

app.get("/billing/balance", authLimit, async (c) => {
  const auth = await getAuthenticatedUser(c);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  const balance = getBalance(db, auth.userId);
  return c.json({ balance_microdollars: balance });
});

app.get("/billing/tiers", publicLimit, (c) => {
  const tiers = Object.entries(CREDIT_TIERS).map(([key, tier]) => ({
    id: key,
    label: tier.label,
    price_cents: tier.price,
    price_display: `$${(tier.price / 100).toFixed(0)}`,
    credits_microdollars: tier.credits,
    bonus_percent: tier.bonus,
  }));
  return c.json({ tiers });
});

// --- Transaction history (session-protected, paginated) ---
app.get("/billing/transactions", authLimit, async (c) => {
  const auth = await getAuthenticatedUser(c);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  const limit = Math.min(Math.max(parseInt(c.req.query("limit") || "50", 10) || 50, 1), 100);
  const offset = Math.max(parseInt(c.req.query("offset") || "0", 10) || 0, 0);

  const transactions = getTransactions(db, auth.userId, limit, offset);
  return c.json({ transactions });
});

// --- Alert threshold (read current) ---
app.get("/billing/alert-threshold", authLimit, async (c) => {
  const auth = await getAuthenticatedUser(c);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  const row = db.query(
    "SELECT alert_threshold_microdollars FROM credit_balances WHERE user_id = ?"
  ).get(auth.userId) as { alert_threshold_microdollars: number | null } | null;

  return c.json({ threshold_microdollars: row?.alert_threshold_microdollars ?? null });
});

// --- Alert threshold (set/clear) ---
app.post("/billing/alert-threshold", authLimit, async (c) => {
  if (!csrfCheck(c)) return c.json({ error: "Forbidden" }, 403);
  const auth = await getAuthenticatedUser(c);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  const { threshold_microdollars } = body;

  if (threshold_microdollars === null || threshold_microdollars === 0) {
    db.run("UPDATE credit_balances SET alert_threshold_microdollars = NULL WHERE user_id = ?", [auth.userId]);
    return c.json({ success: true, threshold_microdollars: null });
  }

  if (typeof threshold_microdollars !== "number" || threshold_microdollars < 0 || !Number.isInteger(threshold_microdollars)) {
    return c.json({ error: "Threshold must be a positive integer (microdollars) or null/0 to disable" }, 400);
  }

  db.run("UPDATE credit_balances SET alert_threshold_microdollars = ? WHERE user_id = ?", [threshold_microdollars, auth.userId]);
  return c.json({ success: true, threshold_microdollars });
});

// --- Account overview API (single request for dashboard data) ---
app.get("/account/overview", authLimit, async (c) => {
  const auth = await getAuthenticatedUser(c);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  const balance = getBalance(db, auth.userId);
  const keys = getUserKeys(db, auth.userId);
  const activeKeys = keys.filter((k: any) => !k.revoked).length;
  const recentTransactions = getTransactions(db, auth.userId, 5, 0);

  const alertRow = db.query(
    "SELECT alert_threshold_microdollars FROM credit_balances WHERE user_id = ?"
  ).get(auth.userId) as { alert_threshold_microdollars: number | null } | null;

  return c.json({
    balance_microdollars: balance,
    active_key_count: activeKeys,
    total_key_count: keys.length,
    max_keys: 5,
    recent_transactions: recentTransactions,
    alert_threshold_microdollars: alertRow?.alert_threshold_microdollars ?? null,
  });
});

// --- Billing page (session-protected) ---
app.get("/account/billing", authLimit, async (c) => {
  const auth = await getAuthenticatedUser(c);
  if (!auth) {
    return c.redirect("/login", 302);
  }

  const file = Bun.file(join(import.meta.dir, "../landing/billing.html"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
      },
    });
  }
  return c.text("Billing page not found", 404);
});

// --- Settings page (session-protected) ---
app.get("/account/settings", authLimit, async (c) => {
  const auth = await getAuthenticatedUser(c);
  if (!auth) {
    return c.redirect("/login", 302);
  }

  const file = Bun.file(join(import.meta.dir, "../landing/settings.html"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
      },
    });
  }
  return c.text("Settings page not found", 404);
});

// --- API Keys management page (session-protected) ---
app.get("/account/keys", authLimit, async (c) => {
  const auth = await getAuthenticatedUser(c);
  if (!auth) {
    return c.redirect("/login", 302);
  }

  const file = Bun.file(join(import.meta.dir, "../landing/keys.html"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
      },
    });
  }
  return c.text("Keys page not found", 404);
});

// --- Account page (session-protected) ---
app.get("/account", authLimit, async (c) => {
  const auth = await getAuthenticatedUser(c);
  if (!auth) {
    return c.redirect("/login", 302);
  }

  const file = Bun.file(join(import.meta.dir, "../landing/account.html"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
      },
    });
  }
  return c.text("Account page not found", 404);
});

// Auth JS — external script for login/signup UI (Plan 02-03)
app.get("/auth.js", publicLimit, async (c) => {
  const file = Bun.file(join(import.meta.dir, "../landing/auth.js"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "application/javascript; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-cache",
      },
    });
  }
  return c.text("Not found", 404);
});

// zxcvbn JS — password strength library for client-side strength bar
app.get("/zxcvbn.js", publicLimit, async (c) => {
  const file = Bun.file(join(import.meta.dir, "../../node_modules/zxcvbn/dist/zxcvbn.js"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "application/javascript; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "public, max-age=86400",
      },
    });
  }
  return c.text("Not found", 404);
});

// CORS before rate limiter so 429 responses include CORS headers
const ALLOWED_ORIGIN = (() => {
  const defaultOrigin = process.env.NODE_ENV === "staging"
    ? "https://staging.apimesh.xyz"
    : "https://apimesh.xyz";
  const o = process.env.CORS_ORIGIN || defaultOrigin;
  if (o === "*") {
    console.warn(`[security] CORS_ORIGIN=* is not permitted for the dashboard; defaulting to ${defaultOrigin}`);
    return defaultOrigin;
  }
  return o;
})();
app.use("/api/*", cors({
  origin: ALLOWED_ORIGIN,
  allowMethods: ["GET", "PUT", "DELETE"],
  allowHeaders: ["Authorization", "Content-Type"],
}));

// Rate limit all other requests — 30/min per IP (brute force protection)
app.use("*", rateLimit("dashboard", 30, 60_000));
app.use("*", bearerAuth({ token: DASHBOARD_TOKEN }));

app.get("/", (c) => {
  const revenue7d = getTotalRevenue(7);
  const revenue30d = getTotalRevenue(30);
  const apis = db.query(
    "SELECT name, subdomain, status, created_at FROM api_registry WHERE status = 'active'"
  ).all();
  const revenueByApi = getRevenueByApi(7);

  return c.json({
    status: "operational",
    wallet: WALLET_ADDRESS,
    revenue: {
      last_7_days: revenue7d,
      last_30_days: revenue30d,
      by_api: revenueByApi,
    },
    apis,
    timestamp: new Date().toISOString(),
  });
});

app.get("/api/stats", (c) => {
  const chartRange = c.req.query("chart_range") || "24h";
  const validRanges = ["24h", "7d", "14d", "30d", "90d", "all"];
  const range = validRanges.includes(chartRange) ? chartRange : "24h";

  // Determine the effective days for range-aware stats
  const rangeDays = range === "24h" ? 1 : range === "all" ? 365 : parseInt(range);

  const revenue7d = getTotalRevenue(7);
  const revenue30d = getTotalRevenue(30);
  const revenueByApi = getRevenueByApi(7);
  const activeApis = getActiveApis();

  const apis = activeApis.map((api) => {
    const detailed = getApiDetailedStats(api.name);
    return {
      name: api.name,
      subdomain: api.subdomain,
      status: api.status,
      created_at: api.created_at,
      requests_range: getRequestCount(api.name, rangeDays).count,
      error_rate_range: getErrorRate(api.name, rangeDays),
      revenue_7d: getApiRevenue(api.name, 7),
      total_requests: detailed.total_requests,
      total_errors: detailed.total_errors,
      paid_requests: detailed.paid_requests,
      total_revenue_usd: detailed.total_revenue_usd,
      avg_latency_ms: detailed.avg_latency_ms,
      p95_latency_ms: detailed.p95_latency_ms,
      unique_callers: detailed.unique_callers,
      first_request_at: detailed.first_request_at,
      last_request_at: detailed.last_request_at,
    };
  });

  const totalRequestsRange = apis.reduce((sum, a) => sum + a.requests_range, 0);

  // Build chart data based on requested range
  let chartData: { labels: string[]; values: number[]; mode: string };
  if (range === "24h") {
    const hourly = getHourlyRequests(24);
    chartData = {
      labels: hourly.map(h => h.hour),
      values: hourly.map(h => h.total),
      mode: "hourly",
    };
  } else {
    const days = range === "all" ? 365 : parseInt(range);
    const daily = getDailyRequests(days);
    chartData = {
      labels: daily.map(d => d.date),
      values: daily.map(d => d.total),
      mode: "daily",
    };
  }

  return c.json({
    revenue_7d: revenue7d.total_usd,
    revenue_30d: revenue30d.total_usd,
    revenue_by_api: revenueByApi,
    apis,
    total_requests: totalRequestsRange,
    recent_requests: getRecentRequests(20),
    signup_notifications: {
      counts: getSignupNotificationCounts(),
      recent: getRecentSignupNotifications(undefined, 20),
    },
    wedge_events_24h: getEventCounts(24),
    charts: {
      daily_revenue_7d: getDailyRevenue(7),
      daily_revenue_30d: getDailyRevenue(30),
      daily_requests_7d: getDailyRequests(7),
      hourly_requests_24h: getHourlyRequests(24),
      range_data: chartData,
    },
    chart_range: range,
    wallet: WALLET_ADDRESS,
    timestamp: new Date().toISOString(),
  });
});

// --- Per-API Detail ---
app.get("/api/api-detail", (c) => {
  const name = c.req.query("name");
  if (!name || name.length > 64) return c.json({ error: "Invalid API name" }, 400);
  const range = c.req.query("range") || "24h";
  const days = range === "24h" ? 1 : range === "all" ? 365 : parseInt(range) || 1;

  const statusBreakdown = getApiStatusBreakdown(name, days);
  const errors = getApiErrors(name, days, 50);
  const recentRequests = getApiRequests(name, days, 100);
  const detailed = getApiDetailedStats(name);

  return c.json({
    name,
    range,
    status_breakdown: statusBreakdown,
    errors,
    recent_requests: recentRequests,
    stats: detailed,
  });
});

// --- Audit Log ---
app.get("/api/audit-log", (c) => {
  const wallet = c.req.query("wallet") || undefined;
  if (wallet && !/^0x[0-9a-fA-F]{40}$/.test(wallet)) {
    return c.json({ error: "Invalid wallet address" }, 400);
  }
  const apiRaw = c.req.query("api") || undefined;
  if (apiRaw && apiRaw.length > 64) {
    return c.json({ error: "Invalid api name" }, 400);
  }
  const api = apiRaw;
  const limit = Math.max(1, Math.min(200, parseInt(c.req.query("limit") || "50", 10) || 50));
  const offset = Math.max(0, parseInt(c.req.query("offset") || "0", 10) || 0);

  const result = getAuditLog(wallet, api, limit, offset);
  return c.json({
    rows: result.rows,
    total: result.total,
    limit,
    offset,
    has_more: offset + limit < result.total,
  });
});

// --- Wallet Summaries ---
app.get("/api/wallets", (c) => {
  const wallets = getWalletSummaries();
  const caps = getAllSpendCaps();
  const capMap = new Map(caps.map(cap => [cap.wallet, cap]));

  return c.json({
    wallets: wallets.map(w => ({
      ...w,
      cap: capMap.get(w.wallet) ?? null,
    })),
  });
});

// --- Spend Caps ---
app.get("/api/spend-caps", (c) => {
  return c.json({ caps: getAllSpendCaps() });
});

app.put("/api/spend-caps", async (c) => {
  const MAX_BODY = 4096;
  const contentLength = parseInt(c.req.header("content-length") || "0", 10);
  if (contentLength > MAX_BODY) {
    return c.json({ error: "Request body too large" }, 413);
  }
  const rawBody = await c.req.arrayBuffer();
  if (rawBody.byteLength > MAX_BODY) {
    return c.json({ error: "Request body too large" }, 413);
  }
  let body: any;
  try {
    body = JSON.parse(new TextDecoder().decode(rawBody));
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }
  const { wallet, label, daily_limit_usd, monthly_limit_usd } = body;

  if (!wallet || typeof wallet !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(wallet)) {
    return c.json({ error: "Invalid wallet address (must be 0x-prefixed 40-char hex)" }, 400);
  }
  if (label !== undefined && label !== null) {
    if (typeof label !== "string") {
      return c.json({ error: "Label must be a string or null" }, 400);
    }
    if (label.length > 128) {
      return c.json({ error: "Label must be 128 characters or fewer" }, 400);
    }
  }
  if (daily_limit_usd !== undefined && daily_limit_usd !== null) {
    if (typeof daily_limit_usd !== "number" || !Number.isFinite(daily_limit_usd) || daily_limit_usd <= 0) {
      return c.json({ error: "daily_limit_usd must be a finite positive number or null" }, 400);
    }
  }
  if (monthly_limit_usd !== undefined && monthly_limit_usd !== null) {
    if (typeof monthly_limit_usd !== "number" || !Number.isFinite(monthly_limit_usd) || monthly_limit_usd <= 0) {
      return c.json({ error: "monthly_limit_usd must be a finite positive number or null" }, 400);
    }
  }

  upsertSpendCap(
    wallet.toLowerCase(),
    label ?? null,
    daily_limit_usd ?? null,
    monthly_limit_usd ?? null
  );

  return c.json({ ok: true, wallet: wallet.toLowerCase() });
});

app.delete("/api/spend-caps/:wallet", (c) => {
  const wallet = c.req.param("wallet");
  if (!wallet || !/^0x[0-9a-fA-F]{40}$/.test(wallet)) {
    return c.json({ error: "Invalid wallet address" }, 400);
  }
  deleteSpendCap(wallet.toLowerCase());
  return c.json({ ok: true, deleted: wallet.toLowerCase() });
});

app.onError((err, c) => {
  // Let Hono's HTTPException (e.g. 401 from bearerAuth) pass through
  if ("getResponse" in err) return (err as any).getResponse();
  console.error(`[${new Date().toISOString()}] dashboard error:`, err);
  return c.json({ error: "Internal server error" }, 500);
});

app.notFound((c) => c.json({ error: "Not found" }, 404));

// Regenerate the apex /.well-known/mpp manifest on startup so Caddy can serve
// it statically. Crawlers observed in apr 2026 probe this path on every request.
async function writeMppManifest() {
  try {
    const { buildPlatformManifest } = await import("../../shared/mpp-manifest");
    const publicDir = resolve(import.meta.dir, "../../public/.well-known");
    await Bun.$`mkdir -p ${publicDir}`.quiet();
    const manifest = buildPlatformManifest("apimesh.xyz");
    await Bun.write(join(publicDir, "mpp"), JSON.stringify(manifest, null, 2));
    console.log(`[mpp] wrote manifest with ${manifest.api_count} apis → ${publicDir}/mpp`);
  } catch (e: any) {
    console.error(`[mpp] failed to write manifest:`, e?.message ?? e);
  }
}
writeMppManifest();

const server = Bun.serve({
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
});

console.log(`dashboard listening on ${server.hostname}:${server.port}`);
