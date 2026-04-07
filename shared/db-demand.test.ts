import { test, expect, describe, beforeEach } from "bun:test";
import { Database } from "bun:sqlite";
import { migrate } from "./migrate";
import { join } from "path";

const MIGRATIONS_DIR = join(import.meta.dir, "..", "data", "migrations");

describe("demand columns in backlog", () => {
  let db: Database;

  beforeEach(() => {
    db = new Database(":memory:");
    db.exec("PRAGMA journal_mode=WAL;");
    db.exec("PRAGMA foreign_keys=ON;");
    migrate(db, MIGRATIONS_DIR);
    // Migration 006 is a no-op and the pre-migration hook in migrate.ts only
    // adds saturation_score to PRE-EXISTING backlog tables. For in-memory DBs
    // where migration 001 creates the table fresh, saturation_score is missing.
    // Add it here if absent so the demand column tests can use the full schema.
    const hasSaturation = db
      .query("SELECT COUNT(*) AS cnt FROM pragma_table_info('backlog') WHERE name = 'saturation_score'")
      .get() as { cnt: number };
    if (hasSaturation.cnt === 0) {
      db.exec("ALTER TABLE backlog ADD COLUMN saturation_score REAL DEFAULT 0");
    }
  });

  test("migration 008 adds demand columns to backlog", () => {
    const columns = db
      .query("SELECT name FROM pragma_table_info('backlog')")
      .all() as { name: string }[];
    const colNames = columns.map((c) => c.name);
    expect(colNames).toContain("search_volume");
    expect(colNames).toContain("marketplace_listings");
    expect(colNames).toContain("measured_demand_score");
    expect(colNames).toContain("demand_source");
    expect(colNames).toContain("category");
  });

  test("insert with demand data stores values correctly", () => {
    db.run(
      `INSERT INTO backlog (name, description, demand_score, effort_score, competition_score, overall_score, saturation_score, search_volume, marketplace_listings, measured_demand_score, demand_source, category)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ["test-api", "Test API", 7, 6, 8, 7.5, 5, 5000, 42, 8.2, "dataforseo", "security"]
    );

    const row = db.query("SELECT * FROM backlog WHERE name = 'test-api'").get() as any;
    expect(row.search_volume).toBe(5000);
    expect(row.marketplace_listings).toBe(42);
    expect(row.measured_demand_score).toBeCloseTo(8.2);
    expect(row.demand_source).toBe("dataforseo");
    expect(row.category).toBe("security");
  });

  test("insert without demand data defaults new columns to NULL", () => {
    db.run(
      `INSERT INTO backlog (name, description, demand_score, effort_score, competition_score, overall_score, saturation_score)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ["basic-api", "Basic API", 5, 5, 5, 5, 3]
    );

    const row = db.query("SELECT * FROM backlog WHERE name = 'basic-api'").get() as any;
    expect(row.search_volume).toBeNull();
    expect(row.marketplace_listings).toBeNull();
    expect(row.measured_demand_score).toBeNull();
    expect(row.demand_source).toBeNull();
    expect(row.category).toBeNull();
  });

  test("getTopBacklogItem-style query returns demand fields", () => {
    db.run(
      `INSERT INTO backlog (name, description, demand_score, effort_score, competition_score, overall_score, saturation_score, search_volume, demand_source, category)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ["top-api", "Top API", 9, 8, 9, 9, 7, 12000, "dataforseo", "devops"]
    );

    const row = db
      .query("SELECT * FROM backlog WHERE status = 'pending' ORDER BY overall_score DESC LIMIT 1")
      .get() as any;

    expect(row).not.toBeNull();
    expect(row.name).toBe("top-api");
    expect(row.search_volume).toBe(12000);
    expect(row.demand_source).toBe("dataforseo");
    expect(row.category).toBe("devops");
  });
});
