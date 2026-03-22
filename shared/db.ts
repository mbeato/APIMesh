import { Database } from "bun:sqlite";
import { join, resolve } from "path";
import { migrate } from "./migrate";

const ALLOWED_DATA_PREFIXES = [
  "/opt/conway-agent/data",
  "/opt/conway-staging/data",
];

function resolveDataDir(): string {
  const raw = process.env.DATA_DIR;
  if (!raw) return join(import.meta.dir, "..", "data");
  const resolved = resolve(raw);
  const allowed = ALLOWED_DATA_PREFIXES.some(p => resolved === p || resolved.startsWith(p + "/"));
  if (!allowed) {
    console.error(`FATAL: DATA_DIR '${resolved}' is not in allowed paths: ${ALLOWED_DATA_PREFIXES.join(", ")}`);
    process.exit(1);
  }
  return resolved;
}

const dataDir = resolveDataDir();
Bun.spawnSync(["mkdir", "-p", dataDir]);

const DB_PATH = join(dataDir, "agent.db");
const db = new Database(DB_PATH, { create: true });
db.exec("PRAGMA journal_mode=WAL;");
db.exec("PRAGMA busy_timeout=5000;");
db.exec("PRAGMA foreign_keys=ON;");
db.exec("PRAGMA secure_delete=ON;");

migrate(db, join(import.meta.dir, "..", "data", "migrations"));

export default db;

export function logRequest(
  apiName: string,
  endpoint: string,
  method: string,
  statusCode: number,
  responseTimeMs: number,
  paid: boolean,
  amountUsd: number,
  clientIp: string,
  payerWallet?: string,
  userId?: string,
  apiKeyId?: string
) {
  db.run(
    `INSERT INTO requests (api_name, endpoint, method, status_code, response_time_ms, paid, amount_usd, client_ip, payer_wallet, user_id, api_key_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [apiName, endpoint, method, statusCode, responseTimeMs, paid ? 1 : 0, amountUsd, clientIp, payerWallet ?? null, userId ?? null, apiKeyId ?? null]
  );
}

export function logRevenue(apiName: string, amountUsd: number, txHash: string, network: string, payerWallet?: string) {
  db.run(
    `INSERT INTO revenue (api_name, amount_usd, tx_hash, network, payer_wallet) VALUES (?, ?, ?, ?, ?)`,
    [apiName, amountUsd, txHash, network, payerWallet ?? null]
  );
}

function safeDays(days: number): number {
  return Math.max(1, Math.min(365, Math.floor(days)));
}

export function getRevenueByApi(days: number = 7) {
  return db.query(`
    SELECT api_name, SUM(amount_usd) as total_usd, COUNT(*) as tx_count
    FROM revenue
    WHERE created_at > datetime('now', '-' || ? || ' days')
    GROUP BY api_name
    ORDER BY total_usd DESC
  `).all(safeDays(days));
}

export function getTotalRevenue(days: number = 7) {
  return db.query(`
    SELECT COALESCE(SUM(amount_usd), 0) as total_usd, COUNT(*) as tx_count
    FROM revenue
    WHERE created_at > datetime('now', '-' || ? || ' days')
  `).get(safeDays(days)) as { total_usd: number; tx_count: number };
}

export function getRequestCount(apiName: string, days: number = 7) {
  return db.query(`
    SELECT COUNT(*) as count
    FROM requests
    WHERE api_name = ? AND created_at > datetime('now', '-' || ? || ' days')
  `).get(apiName, safeDays(days)) as { count: number };
}

export function registerApi(name: string, port: number, subdomain: string) {
  db.run(
    `INSERT OR REPLACE INTO api_registry (name, port, subdomain, updated_at)
     VALUES (?, ?, ?, datetime('now'))`,
    [name, port, subdomain]
  );
}

// --- Brain helper functions ---

export interface BacklogItem {
  id: number;
  name: string;
  description: string;
  demand_score: number;
  effort_score: number;
  competition_score: number;
  overall_score: number;
  status: string;
  created_at: string;
}

export function getTopBacklogItem(): BacklogItem | null {
  return db.query(`
    SELECT * FROM backlog
    WHERE status = 'pending'
    ORDER BY overall_score DESC
    LIMIT 1
  `).get() as BacklogItem | null;
}

export function updateBacklogStatus(id: number, status: string) {
  db.run(`UPDATE backlog SET status = ? WHERE id = ?`, [status, id]);
}

export function insertBacklogItem(
  name: string,
  description: string,
  demandScore: number,
  effortScore: number,
  competitionScore: number,
  overallScore: number
) {
  db.run(
    `INSERT OR IGNORE INTO backlog (name, description, demand_score, effort_score, competition_score, overall_score)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [name, description, demandScore, effortScore, competitionScore, overallScore]
  );
}

export function backlogItemExists(name: string): boolean {
  const row = db.query(`SELECT 1 FROM backlog WHERE name = ?`).get(name);
  return !!row;
}

export interface ApiRegistryEntry {
  id: number;
  name: string;
  port: number;
  subdomain: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export function getActiveApis(): ApiRegistryEntry[] {
  return db.query(`SELECT * FROM api_registry WHERE status = 'active'`).all() as ApiRegistryEntry[];
}

export function deactivateApi(name: string) {
  db.run(`UPDATE api_registry SET status = 'inactive', updated_at = datetime('now') WHERE name = ?`, [name]);
}

export function getErrorRate(apiName: string, days: number = 7): { total: number; errors: number; rate: number } {
  const result = db.query(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) as errors
    FROM requests
    WHERE api_name = ? AND created_at > datetime('now', '-' || ? || ' days')
  `).get(apiName, safeDays(days)) as { total: number; errors: number };
  return {
    total: result.total,
    errors: result.errors ?? 0,
    rate: result.total > 0 ? (result.errors ?? 0) / result.total : 0,
  };
}

export function getRecentRequests(limit: number = 20) {
  return db.query(`
    SELECT api_name, endpoint, method, status_code, response_time_ms, paid, amount_usd, created_at
    FROM requests ORDER BY created_at DESC LIMIT ?
  `).all(Math.min(limit, 100));
}

export function getApiRevenue(apiName: string, days: number = 7): number {
  const result = db.query(`
    SELECT COALESCE(SUM(amount_usd), 0) as total_usd
    FROM revenue
    WHERE api_name = ? AND created_at > datetime('now', '-' || ? || ' days')
  `).get(apiName, safeDays(days)) as { total_usd: number };
  return result.total_usd;
}

// --- Time-series query functions for dashboard charts ---

export interface DailyRevenue {
  date: string;
  total_usd: number;
  tx_count: number;
}

export function getDailyRevenue(days: number = 7): DailyRevenue[] {
  const safeDaysVal = safeDays(days);
  const rows = db.query(`
    SELECT date(created_at) as date,
           COALESCE(SUM(amount_usd), 0) as total_usd,
           COUNT(*) as tx_count
    FROM revenue
    WHERE created_at > datetime('now', '-' || ? || ' days')
    GROUP BY date(created_at)
    ORDER BY date ASC
  `).all(safeDaysVal) as DailyRevenue[];

  const byDate = new Map(rows.map(r => [r.date, r]));
  const result: DailyRevenue[] = [];
  for (let i = safeDaysVal - 1; i >= 0; i--) {
    const d = new Date();
    d.setUTCDate(d.getUTCDate() - i);
    const date = d.toISOString().slice(0, 10);
    result.push(byDate.get(date) ?? { date, total_usd: 0, tx_count: 0 });
  }
  return result;
}

export interface DailyRequests {
  date: string;
  total: number;
  paid: number;
  free: number;
  errors: number;
}

export function getDailyRequests(days: number = 7): DailyRequests[] {
  const safeDaysVal = safeDays(days);
  const rows = db.query(`
    SELECT date(created_at) as date,
           COUNT(*) as total,
           SUM(CASE WHEN paid = 1 THEN 1 ELSE 0 END) as paid,
           SUM(CASE WHEN paid = 0 THEN 1 ELSE 0 END) as free,
           SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) as errors
    FROM requests
    WHERE created_at > datetime('now', '-' || ? || ' days')
    GROUP BY date(created_at)
    ORDER BY date ASC
  `).all(safeDaysVal) as DailyRequests[];

  const byDate = new Map(rows.map(r => [r.date, r]));
  const result: DailyRequests[] = [];
  for (let i = safeDaysVal - 1; i >= 0; i--) {
    const d = new Date();
    d.setUTCDate(d.getUTCDate() - i);
    const date = d.toISOString().slice(0, 10);
    result.push(byDate.get(date) ?? { date, total: 0, paid: 0, free: 0, errors: 0 });
  }
  return result;
}

export interface HourlyRequests {
  hour: string;
  total: number;
}

export function getHourlyRequests(hours: number = 24): HourlyRequests[] {
  const safeHoursVal = Math.max(1, Math.min(168, Math.floor(hours)));
  const rows = db.query(`
    SELECT strftime('%Y-%m-%d %H:00', created_at) as hour,
           COUNT(*) as total
    FROM requests
    WHERE created_at > datetime('now', '-' || ? || ' hours')
    GROUP BY strftime('%Y-%m-%d %H:00', created_at)
    ORDER BY hour ASC
  `).all(safeHoursVal) as HourlyRequests[];

  const byHour = new Map(rows.map(r => [r.hour, r]));
  const result: HourlyRequests[] = [];
  const now = new Date();
  for (let i = safeHoursVal - 1; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 3600_000);
    const hour = d.getUTCFullYear() + "-" +
      String(d.getUTCMonth() + 1).padStart(2, "0") + "-" +
      String(d.getUTCDate()).padStart(2, "0") + " " +
      String(d.getUTCHours()).padStart(2, "0") + ":00";
    result.push(byHour.get(hour) ?? { hour, total: 0 });
  }
  return result;
}

// --- Spend cap & audit log queries ---

export function getWalletSpend(wallet: string, days: number): number {
  const result = db.query(`
    SELECT COALESCE(SUM(amount_usd), 0) as total_usd
    FROM revenue
    WHERE payer_wallet = ? AND created_at > datetime('now', '-' || ? || ' days')
  `).get(wallet, safeDays(days)) as { total_usd: number };
  return result.total_usd;
}

export interface SpendCap {
  id: number;
  wallet: string;
  label: string | null;
  daily_limit_usd: number | null;
  monthly_limit_usd: number | null;
  enabled: number;
  created_at: string;
  updated_at: string;
}

export function getSpendCap(wallet: string): SpendCap | null {
  return db.query(`SELECT * FROM spend_caps WHERE wallet = ? AND enabled = 1`).get(wallet) as SpendCap | null;
}

export function getAllSpendCaps(): SpendCap[] {
  return db.query(`SELECT * FROM spend_caps ORDER BY created_at DESC`).all() as SpendCap[];
}

export function upsertSpendCap(wallet: string, label: string | null, dailyLimit: number | null, monthlyLimit: number | null) {
  db.run(
    `INSERT INTO spend_caps (wallet, label, daily_limit_usd, monthly_limit_usd)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(wallet) DO UPDATE SET
       label = excluded.label,
       daily_limit_usd = excluded.daily_limit_usd,
       monthly_limit_usd = excluded.monthly_limit_usd,
       updated_at = datetime('now')`,
    [wallet, label, dailyLimit, monthlyLimit]
  );
}

export function deleteSpendCap(wallet: string) {
  db.run(`DELETE FROM spend_caps WHERE wallet = ?`, [wallet]);
}

export interface AuditLogEntry {
  id: number;
  api_name: string;
  endpoint: string;
  method: string;
  status_code: number;
  response_time_ms: number;
  paid: number;
  amount_usd: number;
  payer_wallet: string | null;
  created_at: string;
  tx_hash: string | null;
}

export function getAuditLog(
  wallet?: string,
  api?: string,
  limit: number = 50,
  offset: number = 0
): { rows: AuditLogEntry[]; total: number } {
  const safeLimit = Math.max(1, Math.min(200, limit));
  const safeOffset = Math.max(0, Math.min(100_000, Math.floor(offset)));

  const conditions: string[] = [];
  const params: (string | number)[] = [];

  if (wallet) {
    conditions.push("r.payer_wallet = ?");
    params.push(wallet);
  }
  if (api) {
    conditions.push("r.api_name = ?");
    params.push(api);
  }

  const where = conditions.length > 0 ? "WHERE " + conditions.join(" AND ") : "";

  const countResult = db.query(
    `SELECT COUNT(*) as total FROM requests r ${where}`
  ).get(...params) as { total: number };

  const rows = db.query(`
    SELECT r.id, r.api_name, r.endpoint, r.method, r.status_code,
           r.response_time_ms, r.paid, r.amount_usd, r.payer_wallet, r.created_at,
           (SELECT rev.tx_hash FROM revenue rev
            WHERE rev.api_name = r.api_name
              AND rev.payer_wallet IS NOT NULL
              AND rev.payer_wallet = r.payer_wallet
              AND abs(julianday(rev.created_at) - julianday(r.created_at)) < 0.00002
            LIMIT 1) as tx_hash
    FROM requests r
    ${where}
    ORDER BY r.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, safeLimit, safeOffset) as AuditLogEntry[];

  return { rows, total: countResult.total };
}

export interface WalletSummary {
  wallet: string;
  total_spent: number;
  spend_7d: number;
  spend_30d: number;
  request_count: number;
  last_seen: string;
}

export function getWalletSummaries(): WalletSummary[] {
  return db.query(`
    SELECT
      payer_wallet as wallet,
      COALESCE(SUM(amount_usd), 0) as total_spent,
      COALESCE(SUM(CASE WHEN created_at > datetime('now', '-7 days') THEN amount_usd ELSE 0 END), 0) as spend_7d,
      COALESCE(SUM(CASE WHEN created_at > datetime('now', '-30 days') THEN amount_usd ELSE 0 END), 0) as spend_30d,
      COUNT(*) as request_count,
      MAX(created_at) as last_seen
    FROM revenue
    WHERE payer_wallet IS NOT NULL
    GROUP BY payer_wallet
    ORDER BY spend_30d DESC
  `).all() as WalletSummary[];
}
