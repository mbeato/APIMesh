import type { DisclosureElement, ComplianceSignals } from "./types";

// Simple keyword-based matcher for compliance signals and privacy disclosures
// No external subprocesses or exec calls

// These keyword sets can be extended or improved with regexes, patterns etc.

const GDPR_KEYWORDS = [
  "gdpr",
  "general data protection regulation",
  "data subject",
  "personal data",
  "consent",
  "right to erasure",
  "data controller",
  "processing",
  "data protection officer",
  "right to access",
  "right to rectification",
  "right to object",
  "data portability",
  "profiling",
  "supervisory authority",
  "data minimization",
];

const CCPA_KEYWORDS = [
  "ccpa",
  "california consumer privacy act",
  "do not sell",
  "personal information",
  "consumer rights",
  "right to know",
  "right to delete",
  "non-discrimination",
  "sale of personal information",
  "opt-out",
];

const DATA_SHARING_PHRASES = [
  "share with third parties",
  "share with partners",
  "third-party",
  "affiliate",
  "service provider",
  "data transfer",
  "data shared",
  "advertising partners",
  "analytics providers",
  "tracking partners",
];

function textIncludesAny(text: string, keywords: string[]): boolean {
  const lower = text.toLowerCase();
  return keywords.some((k) => lower.includes(k));
}

function findMentions(text: string, keywords: string[]): DisclosureElement[] {
  const results: DisclosureElement[] = [];
  const lower = text.toLowerCase();

  for (const phrase of keywords) {
    let idx = lower.indexOf(phrase);
    if (idx >= 0) {
      // Capture context snippet around phrase, about 120 characters
      const start = Math.max(0, idx - 60);
      const end = Math.min(text.length, idx + phrase.length + 60);
      const snippet = text.slice(start, end).replace(/\s+/g, " ").trim();

      results.push({
        type: "disclosure",
        text: snippet,
        confidence: 0.7, // heuristic
      });
    }
  }
  return results;
}

export function analyzeTextsForDisclosures(texts: string[]): DisclosureElement[] {
  const elements: DisclosureElement[] = [];
  for (const text of texts) {
    elements.push(...findMentions(text, DATA_SHARING_PHRASES));

    if (textIncludesAny(text, GDPR_KEYWORDS)) {
      elements.push({ type: "gdpr-notice", text, confidence: 0.9, severity: "high" });
    }
    if (textIncludesAny(text, CCPA_KEYWORDS)) {
      elements.push({ type: "ccpa-notice", text, confidence: 0.9, severity: "high" });
    }
  }
  return elements;
}

export function computeComplianceSignals(disclosures: DisclosureElement[]): ComplianceSignals {
  let gdprCount = 0;
  let ccpaCount = 0;
  let dataSharingCount = 0;

  for (const d of disclosures) {
    if (d.type === "gdpr-notice") gdprCount++;
    else if (d.type === "ccpa-notice") ccpaCount++;
    else if (d.type === "disclosure") dataSharingCount++;
  }

  // Simple scoring heuristics
  const gdprDetected = gdprCount > 0;
  const ccpaDetected = ccpaCount > 0;

  // Scores 0-100 by frequency (max 10)
  const gdprScore = Math.min(100, gdprCount * 20);
  const ccpaScore = Math.min(100, ccpaCount * 20);

  return {
    gdprDetected,
    gdprScore,
    ccpaDetected,
    ccpaScore,
    dataSharingCount,
  };
}
