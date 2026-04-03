import { Database } from "bun:sqlite";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "path";

/**
 * Adds a column to a table if it doesn't already exist.
 * Uses PRAGMA table_info() introspection (not try/catch).
 */
function addColumnIfAbsent(
  db: Database,
  table: string,
  column: string,
  definition: string
): void {
  const exists = db
    .query(`SELECT COUNT(*) AS cnt FROM pragma_table_info('${table}') WHERE name = ?`)
    .get(column) as { cnt: number };
  if (exists.cnt === 0) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

export function migrate(db: Database, migrationsDir: string): void {
  // Create tracking table with checksum column
  db.exec(`
    CREATE TABLE IF NOT EXISTS _migrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      checksum TEXT NOT NULL,
      applied_at TEXT DEFAULT (datetime('now'))
    );
  `);

  // Pre-migration: Add missing columns to pre-existing tables BEFORE running migrations.
  // This handles the case where tables were created before the migration system existed
  // and migrations reference columns (e.g., indexes) that don't exist yet.
  const preExistingRequests = db
    .query("SELECT COUNT(*) AS cnt FROM sqlite_master WHERE type='table' AND name='requests'")
    .get() as { cnt: number };
  if (preExistingRequests.cnt > 0) {
    addColumnIfAbsent(db, "requests", "payer_wallet", "TEXT");
    addColumnIfAbsent(db, "requests", "user_id", "TEXT");
    addColumnIfAbsent(db, "requests", "api_key_id", "TEXT");
  }
  const preExistingRevenue = db
    .query("SELECT COUNT(*) AS cnt FROM sqlite_master WHERE type='table' AND name='revenue'")
    .get() as { cnt: number };
  if (preExistingRevenue.cnt > 0) {
    addColumnIfAbsent(db, "revenue", "payer_wallet", "TEXT");
  }

  // Pre-migration: Add saturation_score to backlog if missing (006 was a no-op)
  const preExistingBacklog = db
    .query("SELECT COUNT(*) AS cnt FROM sqlite_master WHERE type='table' AND name='backlog'")
    .get() as { cnt: number };
  if (preExistingBacklog.cnt > 0) {
    addColumnIfAbsent(db, "backlog", "saturation_score", "REAL DEFAULT 0");
  }

  // Read migration files, sorted by name for ordering
  let files: string[];
  try {
    const glob = new Bun.Glob("*.sql");
    files = Array.from(glob.scanSync(migrationsDir)).sort();
  } catch {
    // Fallback to readdirSync if Bun.Glob is unavailable
    files = readdirSync(migrationsDir)
      .filter((f) => f.endsWith(".sql"))
      .sort();
  }

  for (const file of files) {
    const filePath = join(migrationsDir, file);
    const sql = readFileSync(filePath, "utf-8");

    // Compute SHA-256 checksum
    const hasher = new Bun.CryptoHasher("sha256");
    hasher.update(sql);
    const checksum = hasher.digest("hex");

    // Check if already applied
    const existing = db
      .query("SELECT checksum FROM _migrations WHERE name = ?")
      .get(file) as { checksum: string } | null;

    if (existing) {
      // Verify checksum hasn't changed
      if (existing.checksum !== checksum) {
        throw new Error(
          `Migration file '${file}' has been modified after initial application. ` +
            `Expected checksum: ${existing.checksum}, got: ${checksum}`
        );
      }
      // Already applied with matching checksum, skip
      continue;
    }

    // Apply migration in a transaction
    const applyMigration = db.transaction(() => {
      db.exec(sql);
      db.run("INSERT INTO _migrations (name, checksum) VALUES (?, ?)", [
        file,
        checksum,
      ]);
    });
    applyMigration();

    console.log(`Migration applied: ${file}`);
  }

}
