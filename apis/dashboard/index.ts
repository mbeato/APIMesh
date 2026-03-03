import { Hono } from "hono";
import { cors } from "hono/cors";
import { bearerAuth } from "hono/bearer-auth";
import { resolve, join } from "path";
import db, { getRevenueByApi, getTotalRevenue, getRequestCount, getErrorRate, getApiRevenue, getRecentRequests, getActiveApis, getDailyRevenue, getDailyRequests, getHourlyRequests, getAuditLog, getWalletSummaries, getAllSpendCaps, upsertSpendCap, deleteSpendCap, getWalletSpend, getSpendCap } from "../../shared/db";
import { WALLET_ADDRESS } from "../../shared/x402";
import { rateLimit } from "../../shared/rate-limit";

const app = new Hono();
const PORT = 3000;

const DASHBOARD_TOKEN = process.env.DASHBOARD_TOKEN;
if (!DASHBOARD_TOKEN) {
  console.error("FATAL: DASHBOARD_TOKEN env var not set");
  process.exit(1);
}
if (DASHBOARD_TOKEN.length < 32) {
  console.error("FATAL: DASHBOARD_TOKEN must be at least 32 characters (use: openssl rand -hex 24)");
  process.exit(1);
}

// Rate limit for public routes (higher limit, still bounded)
const publicLimit = rateLimit("dashboard-public", 120, 60_000);

// Health check — no rate limit, must work from localhost monitoring
app.get("/health", (c) => c.json({ status: "ok" }));

// Serve discovery files at root (Caddy proxies apimesh.xyz to dashboard)
app.get("/llms.txt", publicLimit, async (c) => {
  const file = Bun.file("public/llms.txt");
  if (await file.exists()) return c.text(await file.text());
  return c.text("# apimesh.xyz\nNo llms.txt generated yet.\n", 404);
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

// Landing page — public, no auth (served at apimesh.xyz root)
app.get("/", publicLimit, async (c) => {
  const file = Bun.file(join(import.meta.dir, "../landing/landing.html"));
  if (await file.exists()) {
    return new Response(await file.text(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src data:; connect-src 'self'",
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
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src data:; connect-src 'self'",
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

app.put("/wallet/:address/cap", walletLimit, async (c) => {
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

// CORS before rate limiter so 429 responses include CORS headers
const ALLOWED_ORIGIN = (() => {
  const o = process.env.CORS_ORIGIN || "https://apimesh.xyz";
  if (o === "*") {
    console.warn("[security] CORS_ORIGIN=* is not permitted for the dashboard; defaulting to https://apimesh.xyz");
    return "https://apimesh.xyz";
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
  const revenue7d = getTotalRevenue(7);
  const revenue30d = getTotalRevenue(30);
  const revenueByApi = getRevenueByApi(7);
  const activeApis = getActiveApis();

  const apis = activeApis.map((api) => ({
    name: api.name,
    subdomain: api.subdomain,
    status: api.status,
    requests_7d: getRequestCount(api.name, 7).count,
    error_rate_7d: getErrorRate(api.name, 7),
    revenue_7d: getApiRevenue(api.name, 7),
  }));

  const totalRequests7d = apis.reduce((sum, a) => sum + a.requests_7d, 0);

  return c.json({
    revenue_7d: revenue7d.total_usd,
    revenue_30d: revenue30d.total_usd,
    revenue_by_api: revenueByApi,
    apis,
    total_requests_7d: totalRequests7d,
    recent_requests: getRecentRequests(20),
    charts: {
      daily_revenue_7d: getDailyRevenue(7),
      daily_revenue_30d: getDailyRevenue(30),
      daily_requests_7d: getDailyRequests(7),
      hourly_requests_24h: getHourlyRequests(24),
    },
    wallet: WALLET_ADDRESS,
    timestamp: new Date().toISOString(),
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

console.log(`dashboard listening on port ${PORT}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
