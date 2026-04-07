import { test, expect } from "bun:test";
import { analyzeCompetitorGaps } from "./competitors";

test("returns all 5 competitor entries", () => {
  const gaps = analyzeCompetitorGaps();
  expect(gaps).toHaveLength(5);
});

test("includes SecurityTrails, BuiltWith, and Qualys", () => {
  const gaps = analyzeCompetitorGaps();
  const names = gaps.map((g) => g.competitor_name);
  expect(names).toContain("SecurityTrails");
  expect(names).toContain("BuiltWith");
  expect(names).toContain("Qualys SSL Labs");
});

test("coverage values are valid enum values", () => {
  const gaps = analyzeCompetitorGaps();
  const validCoverage = new Set(["none", "partial", "full"]);
  for (const gap of gaps) {
    expect(validCoverage.has(gap.our_coverage)).toBe(true);
  }
});

test("each gap has required fields", () => {
  const gaps = analyzeCompetitorGaps();
  for (const gap of gaps) {
    expect(typeof gap.competitor_name).toBe("string");
    expect(typeof gap.category).toBe("string");
    expect(typeof gap.our_coverage).toBe("string");
    expect(typeof gap.gap_description).toBe("string");
    expect(typeof gap.their_pricing).toBe("string");
  }
});
