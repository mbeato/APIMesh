import { GradeLetter, Recommendation, IPInfrastructureAnalysis } from "./types";

export function gradeFromScore(score: number): GradeLetter {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  if (score >= 30) return "E";
  return "F";
}

export function clampScore(score: number): number {
  if (score > 100) return 100;
  if (score < 0) return 0;
  return Math.round(score);
}

// Basic IP validation simple regex checks IPv4 and IPv6
export function validateIp(input: string): boolean {
  // IPv4
  const ipv4Regex = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;
  // IPv6 (simple, accepts compressed and full)
  const ipv6Regex = /^((?:[\da-fA-F]{1,4}:){7}[\da-fA-F]{1,4}|((?:[\da-fA-F]{1,4}:){1,7}:)|((?:[\da-fA-F]{1,4}:){1,6}:[\da-fA-F]{1,4})|((?:[\da-fA-F]{1,4}:){1,5}(?::[\da-fA-F]{1,4}){1,2})|((?:[\da-fA-F]{1,4}:){1,4}(?::[\da-fA-F]{1,4}){1,3})|((?:[\da-fA-F]{1,4}:){1,3}(?::[\da-fA-F]{1,4}){1,4})|((?:[\da-fA-F]{1,4}:){1,2}(?::[\da-fA-F]{1,4}){1,5})|([\da-fA-F]{1,4}:(?:(?::[\da-fA-F]{1,4}){1,6}))|(:((?::[\da-fA-F]{1,4}){1,7}|:)))$/;

  return ipv4Regex.test(input) || ipv6Regex.test(input);
}

export function createRecommendation(issue: string, severity: number, suggestion: string): Recommendation {
  return { issue, severity, suggestion };
}

export function combineScores(scores: number[]): number {
  if (scores.length === 0) return 0;
  const total = scores.reduce((acc, v) => acc + v, 0);
  return clampScore(total / scores.length);
}

/**
 * Helper to summarize recommendations, merges duplicates by issue text, reduces severity to max found
 */
export function dedupeRecommendations(recs: Recommendation[]): Recommendation[] {
  const seen = new Map<string, Recommendation>();
  for (const rec of recs) {
    const existing = seen.get(rec.issue);
    if (!existing) {
      seen.set(rec.issue, { ...rec });
    } else {
      if (rec.severity > existing.severity) {
        existing.severity = rec.severity;
      }
    }
  }
  return [...seen.values()];
}
