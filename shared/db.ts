import { Database } from "bun:sqlite";
import { join } from "path";
import { mkdirSync } from "fs";

const DB_PATH = join(import.meta.dir, "..", "data", "agent.db");
mkdirSync(join(import.meta.dir, "..", "data"), { recursive: true });

const db = new Database(DB_PATH, { create: true });
db.exec("PRAGMA journal_mode=WAL;");

db.exec(`
  CREATE TABLE IF NOT EXISTS api_registry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    port INTEGER UNIQUE NOT NULL,
    subdomain TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_name TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER,
    response_time_ms REAL,
    paid INTEGER DEFAULT 0,
    amount_usd REAL DEFAULT 0,
    client_ip TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS revenue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_name TEXT NOT NULL,
    amount_usd REAL NOT NULL,
    tx_hash TEXT,
    network TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS backlog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    demand_score REAL DEFAULT 0,
    effort_score REAL DEFAULT 0,
    competition_score REAL DEFAULT 0,
    overall_score REAL DEFAULT 0,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

export default db;

export function logRequest(
  apiName: string,
  endpoint: string,
  method: string,
  statusCode: number,
  responseTimeMs: number,
  paid: boolean,
  amountUsd: number,
  clientIp: string
) {
  db.run(
    `INSERT INTO requests (api_name, endpoint, method, status_code, response_time_ms, paid, amount_usd, client_ip)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [apiName, endpoint, method, statusCode, responseTimeMs, paid ? 1 : 0, amountUsd, clientIp]
  );
}

export function logRevenue(apiName: string, amountUsd: number, txHash: string, network: string) {
  db.run(
    `INSERT INTO revenue (api_name, amount_usd, tx_hash, network) VALUES (?, ?, ?, ?)`,
    [apiName, amountUsd, txHash, network]
  );
}

export function getRevenueByApi(days: number = 7) {
  return db.query(`
    SELECT api_name, SUM(amount_usd) as total_usd, COUNT(*) as tx_count
    FROM revenue
    WHERE created_at > datetime('now', '-' || ? || ' days')
    GROUP BY api_name
    ORDER BY total_usd DESC
  `).all(days);
}

export function getTotalRevenue(days: number = 7) {
  return db.query(`
    SELECT COALESCE(SUM(amount_usd), 0) as total_usd, COUNT(*) as tx_count
    FROM revenue
    WHERE created_at > datetime('now', '-' || ? || ' days')
  `).get(days) as { total_usd: number; tx_count: number };
}

export function getRequestCount(apiName: string, days: number = 7) {
  return db.query(`
    SELECT COUNT(*) as count
    FROM requests
    WHERE api_name = ? AND created_at > datetime('now', '-' || ? || ' days')
  `).get(apiName, days) as { count: number };
}

export function registerApi(name: string, port: number, subdomain: string) {
  db.run(
    `INSERT OR REPLACE INTO api_registry (name, port, subdomain, updated_at)
     VALUES (?, ?, ?, datetime('now'))`,
    [name, port, subdomain]
  );
}
