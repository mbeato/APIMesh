import type {
  FetchedSource,
  PrivacyRiskScoreResponse,
  Recommendation,
  DisclosureElement,
  GradeLetter,
} from "./types";
import { analyzeTextsForDisclosures, computeComplianceSignals } from "./nlp";

// Compute risk score (0-100) based on compliance signals and disclosure counts

function riskScoreFromCompliance(compliance: {
  gdprScore: number;
  ccpaScore: number;
  dataSharingCount: number;
}): number {
  // Start with 100 means no risk -> invert scoring
  // Combine inversely: more compliance -> lower risk
  // More data sharing mentions -> higher risk

  // Scale GDPR and CCPA scores 0-100 protective
  const gdprFactor = 1 - compliance.gdprScore / 100;
  const ccpaFactor = 1 - compliance.ccpaScore / 100;

  // Data sharing factor capped at 10 mentions
  const maxDataSharing = 10;
  const dataSharingFactor = Math.min(compliance.dataSharingCount, maxDataSharing) / maxDataSharing;

  // Combine factors weighted
  // Higher data sharing: raise risk
  // Higher compliance scores: reduce risk

  const baseRisk = 50; // baseline risk

  const risk = baseRisk * gdprFactor + baseRisk * ccpaFactor + 50 * dataSharingFactor;
  return Math.min(100, Math.max(0, Math.round(risk)));
}

export function gradeFromScore(score: number): GradeLetter {
  if (score <= 15) return "A";
  if (score <= 30) return "B";
  if (score <= 50) return "C";
  if (score <= 70) return "D";
  if (score <= 85) return "E";
  return "F";
}

export function generateRecommendations(
  compliance: {
    gdprDetected: boolean;
    ccpaDetected: boolean;
    gdprScore: number;
    ccpaScore: number;
    dataSharingCount: number;
  },
  disclosures: DisclosureElement[],
  riskScore: number
): Recommendation[] {
  const recs: Recommendation[] = [];

  if (!compliance.gdprDetected) {
    recs.push({
      issue: "GDPR compliance notices not detected",
      severity: "high",
      suggestion: "Add explicit GDPR disclosures if applicable to your audience.",
    });
  } else if (compliance.gdprScore < 60) {
    recs.push({
      issue: "GDPR compliance signals detected but with low coverage",
      severity: "medium",
      suggestion: "Review your GDPR statement for completeness and clarity.",
    });
  }

  if (!compliance.ccpaDetected) {
    recs.push({
      issue: "CCPA compliance notices not detected",
      severity: "medium",
      suggestion: "Add CCPA or California privacy rights disclosures if applicable.",
    });
  } else if (compliance.ccpaScore < 60) {
    recs.push({
      issue: "CCPA disclosures incomplete or insufficient",
      severity: "medium",
      suggestion: "Enhance your California privacy notices and opt-out options.",
    });
  }

  if (compliance.dataSharingCount === 0) {
    recs.push({
      issue: "No data sharing disclosures detected",
      severity: "low",
      suggestion: "Consider explicitly disclosing data sharing practices for transparency.",
    });
  } else if (compliance.dataSharingCount > 5) {
    recs.push({
      issue: "Many data sharing mentions detected",
      severity: "high",
      suggestion: "Review and minimize data sharing practices to reduce user privacy risks.",
    });
  }

  if (riskScore > 50) {
    recs.push({
      issue: "High composite privacy risk score",
      severity: "critical",
      suggestion: "Perform a comprehensive privacy review and update your policies accordingly.",
    });
  } else if (riskScore > 30) {
    recs.push({
      issue: "Moderate privacy risk score",
      severity: "medium",
      suggestion: "Improve clarity and completeness of privacy disclosures.",
    });
  } else {
    recs.push({
      issue: "Low privacy risk score",
      severity: "low",
      suggestion: "Maintain current privacy practices and disclosures.",
    });
  }

  return recs;
}

// Compose explanation text
export function composeExplanation(
  compliance: {
    gdprDetected: boolean;
    ccpaDetected: boolean;
    gdprScore: number;
    ccpaScore: number;
    dataSharingCount: number;
  },
  riskScore: number
): string {
  const parts: string[] = [];
  parts.push(`Privacy risk score is ${riskScore} out of 100 (higher means more risk).`);

  if (compliance.gdprDetected) {
    parts.push(`GDPR compliance signals detected with coverage score ${compliance.gdprScore}%.`);
  } else {
    parts.push(`GDPR compliance signals not detected.`);
  }

  if (compliance.ccpaDetected) {
    parts.push(`CCPA compliance signals detected with coverage score ${compliance.ccpaScore}%.`);
  } else {
    parts.push(`CCPA compliance signals not detected.`);
  }

  parts.push(`Data sharing mentions count: ${compliance.dataSharingCount}.`);

  parts.push(`Consider recommendations to improve your privacy disclosures and reduce risks.`);

  return parts.join(" ");
}

// Main analysis combining inputs
export async function fullAnalysis(
  domain: string,
  fetchedSources: FetchedSource[]
): Promise<PrivacyRiskScoreResponse> {
  // Extract texts from bodies
  const texts: string[] = fetchedSources
    .map((src) => src.bodySnippet)
    .filter((body) => !!body);

  // Analyze disclosures via NLP
  const disclosures = analyzeTextsForDisclosures(texts);

  // Compute compliance signals
  const compliance = computeComplianceSignals(disclosures);

  // Compute composite risk score
  const riskScore = riskScoreFromCompliance(compliance);

  // Grade
  const grade = gradeFromScore(riskScore);

  // Recommendations
  const recommendations = generateRecommendations(compliance, disclosures, riskScore);

  // Compose explanation
  const explanation = composeExplanation(compliance, riskScore);

  return {
    domain,
    sources: fetchedSources,
    disclosures,
    compliance,
    riskScore,
    grade,
    recommendations,
    explanation,
  };
}
