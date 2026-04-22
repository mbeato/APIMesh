import { safeFetch, validateExternalUrl } from "../../shared/ssrf";

// ------------ TYPES ------------

export interface GdprSignals {
  dataSubjectsRights: boolean; // e.g. right to access, to delete
  lawfulBasis: boolean; // e.g. consent, contract
  dataTransfers: boolean; // cross-border transfers mentioned
}

export interface CcpaSignals {
  doNotSell: boolean; // clearly stated Do Not Sell
  optOutMechanism: boolean; // link or method for opt out
}

export interface Recommendation {
  issue: string;
  severity: number; // 1-100
  suggestion: string;
}

export type GradeLetter = "A" | "B" | "C" | "D" | "F";

export interface PrivacyPolicyAnalysisResult {
  url: string;
  complianceScore: number; // 0-100
  grade: GradeLetter;
  gdprSignals: GdprSignals;
  ccpaSignals: CcpaSignals;
  dataSharingDeclared: boolean;
  recommendations: Recommendation[];
  details: string; // human readable
  duration_ms?: number;
}

// ------------ CONSTANTS ------------

const MAX_BODY_BYTES = 200_000; // Limit to 200KB body to prevent huge
const TIMEOUT_MS = 10_000;
const PREVIEW_TIMEOUT_MS = 20_000;

// ------------ UTILS ------------

function simpleGradeFromScore(score: number): GradeLetter {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

function normalizeText(text: string): string {
  return text.replace(/[\s\u00A0]+/g, " ").toLowerCase();
}

// ------------ NLP & ANALYSIS FUNCTIONS ------------

function extractGdprSignals(text: string): GdprSignals {
  // Use regexes and keyword scans
  const normalized = normalizeText(text);

  const dataSubjectsRights = /right to access|right to delete|right to be forgotten|data subject rights/.test(normalized);
  const lawfulBasis = /lawful basis|consent|contract|legitimate interest|legal obligation/.test(normalized);
  const dataTransfers = /cross[- ]?border transfer|international transfer|standard contractual clauses|privacy shield/.test(normalized);

  return { dataSubjectsRights, lawfulBasis, dataTransfers };
}

function extractCcpaSignals(text: string): CcpaSignals {
  const normalized = normalizeText(text);

  const doNotSell = /do not sell|do not share|sale of personal information/.test(normalized);
  const optOutMechanism = /opt[- ]out|request to opt[- ]out|rights to opt[- ]out/.test(normalized);

  return { doNotSell, optOutMechanism };
}

function detectDataSharing(text: string): boolean {
  const normalized = normalizeText(text);

  // Look for third party sharing disclosures
  const indicators = [
    "third party",
    "share with",
    "service provider",
    "partner",
    "affiliate",
    "data recipient",
    "data shared",
    "disclose",
    "transfer to",
  ];

  return indicators.some((indicator) => normalized.includes(indicator));
}

function generateComplianceScore(gdpr: GdprSignals, ccpa: CcpaSignals, sharing: boolean): number {
  // Start base 0
  let score = 0;

  score += gdpr.dataSubjectsRights ? 30 : 0;
  score += gdpr.lawfulBasis ? 30 : 0;
  score += gdpr.dataTransfers ? 10 : 0;

  score += ccpa.doNotSell ? 15 : 0;
  score += ccpa.optOutMechanism ? 10 : 0;

  score += sharing ? 5 : 0;

  return Math.min(score, 100);
}

function generateRecommendations(
  gdpr: GdprSignals,
  ccpa: CcpaSignals,
  sharing: boolean
): Recommendation[] {
  const recs: Recommendation[] = [];

  if (!gdpr.dataSubjectsRights) {
    recs.push({
      issue: "Lacks clear data subjects rights",
      severity: 80,
      suggestion: "Include sections about user rights like access, correction, deletion, and portability.",
    });
  }
  if (!gdpr.lawfulBasis) {
    recs.push({
      issue: "No stated lawful basis for data processing",
      severity: 85,
      suggestion: "Declare legal grounds such as consent, contract, or legitimate interest.",
    });
  }
  if (!gdpr.dataTransfers) {
    recs.push({
      issue: "Missing data transfer disclosures",
      severity: 50,
      suggestion: "Describe any international data transfer practices and safeguards.",
    });
  }
  if (!ccpa.doNotSell) {
    recs.push({
      issue: "No explicit Do Not Sell clause",
      severity: 70,
      suggestion: "Add a Do Not Sell My Personal Information section if applicable.",
    });
  }
  if (!ccpa.optOutMechanism) {
    recs.push({
      issue: "No CCPA opt-out mechanism",
      severity: 80,
      suggestion: "Provide clear opt-out instructions or links for California residents.",
    });
  }
  if (!sharing) {
    recs.push({
      issue: "No declared data sharing or third-party disclosure",
      severity: 60,
      suggestion: "Add details on what data is shared with third parties and why.",
    });
  }

  return recs;
}

// ------------ MAIN ANALYSIS FUNCTION ------------

/**
 * Analyze privacy policy content fetched from URL.
 * @param url URL of privacy policy or main landing page
 * @param preview If true, run less expensive analysis with longer timeout
 */
export async function analyzePrivacyPolicies(url: string, preview = false): Promise<PrivacyPolicyAnalysisResult | { error: string }> {
  const timeoutMs = preview ? PREVIEW_TIMEOUT_MS : TIMEOUT_MS;

  const validated = validateExternalUrl(url);
  if ("error" in validated) {
    return { error: validated.error };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  let textBody = "";
  try {
    // Fetch main URL content
    const res = await safeFetch(validated.url.toString(), {
      method: "GET",
      signal: controller.signal,
      headers: {
        "User-Agent": "privacy-policy-qualify/1.0 apimesh.xyz",
        Accept: "text/html,application/xhtml+xml,application/xml",
      },
    });

    if (!res.ok || !res.headers.get("content-type")?.includes("text/html")) {
      clearTimeout(timeoutId);
      return { error: `Failed to fetch HTML content: HTTP ${res.status}` };
    }

    // Read body with a size cap
    const reader = res.body?.getReader();
    if (!reader) {
      clearTimeout(timeoutId);
      return { error: "Response has no body to read" };
    }

    const chunks: Uint8Array[] = [];
    let receivedLength = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        chunks.push(value);
        receivedLength += value.length;
        if (receivedLength > MAX_BODY_BYTES) {
          break;
        }
      }
    }

    const concat = new Uint8Array(receivedLength);
    let position = 0;
    for (const chunk of chunks) {
      concat.set(chunk, position);
      position += chunk.length;
    }

    // Decode for UTF-8
    const decoder = new TextDecoder("utf-8", { fatal: false });
    textBody = decoder.decode(concat);

  } catch (e) {
    clearTimeout(timeoutId);
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return { error: `Failed to fetch or read content: ${msg}` };
  }

  clearTimeout(timeoutId);

  // --- Multi-pass NLP analysis ---
  try {
    // Basic heuristic checks
    const gdprSignals = extractGdprSignals(textBody);
    const ccpaSignals = extractCcpaSignals(textBody);
    const sharing = detectDataSharing(textBody);
    const score = generateComplianceScore(gdprSignals, ccpaSignals, sharing);
    const grade = simpleGradeFromScore(score);
    const recs = generateRecommendations(gdprSignals, ccpaSignals, sharing);

    const details = `Privacy policy content fetched from ${url} was analyzed using multiple NLP heuristics. GDPR signals: rights=${gdprSignals.dataSubjectsRights}, lawfulBasis=${gdprSignals.lawfulBasis}, transfers=${gdprSignals.dataTransfers}. CCPA signals: doNotSell=${ccpaSignals.doNotSell}, optOutMechanism=${ccpaSignals.optOutMechanism}. Data sharing declared: ${sharing}. Compliance score calculated to ${score} with grade ${grade}.`;

    return {
      url,
      complianceScore: score,
      grade,
      gdprSignals,
      ccpaSignals,
      dataSharingDeclared: sharing,
      recommendations: recs,
      details
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Failed to analyze content: ${msg}` };
  }
}