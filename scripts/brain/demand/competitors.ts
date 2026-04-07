/**
 * Competitor gap analysis.
 *
 * Maintains a static registry of known competitors and our coverage gaps.
 * This is a synchronous function -- no API calls. Updated manually.
 */

export interface CompetitorGap {
  competitor_name: string;
  category: string;
  our_coverage: "none" | "partial" | "full";
  gap_description: string;
  their_pricing: string;
}

const COMPETITOR_REGISTRY: CompetitorGap[] = [
  {
    competitor_name: "SecurityTrails",
    category: "security",
    our_coverage: "partial",
    gap_description: "Domain/IP intelligence, DNS history, WHOIS, associated domains",
    their_pricing: "$50/mo starter",
  },
  {
    competitor_name: "BuiltWith",
    category: "tech-detection",
    our_coverage: "partial",
    gap_description: "Historical tech stack tracking, market share data, lead generation",
    their_pricing: "$295/mo basic",
  },
  {
    competitor_name: "Qualys SSL Labs",
    category: "ssl-analysis",
    our_coverage: "none",
    gap_description: "Deep SSL/TLS analysis, certificate chain validation, protocol support matrix",
    their_pricing: "Free (limited API)",
  },
  {
    competitor_name: "Screaming Frog",
    category: "seo-crawling",
    our_coverage: "none",
    gap_description: "Full site crawl, broken links, redirect chains at scale, structured data validation",
    their_pricing: "$259/year",
  },
  {
    competitor_name: "Snyk",
    category: "dependency-security",
    our_coverage: "none",
    gap_description: "Dependency vulnerability scanning, license compliance, fix suggestions",
    their_pricing: "$25/mo developer",
  },
];

export function analyzeCompetitorGaps(): CompetitorGap[] {
  return [...COMPETITOR_REGISTRY];
}
