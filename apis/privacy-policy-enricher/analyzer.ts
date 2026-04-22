import { safeFetch, validateExternalUrl } from "../../shared/ssrf";

// -----------------------------
// Types
// -----------------------------

export interface EnricherResult {
  url: string;
  gdprDetected: boolean;
  ccpaDetected: boolean;
  dataSharingPractices: DataSharingAnalysis;
  privacyFeatures: PrivacyFeaturesAnalysis;
  score: number; // 0-100
  grade: Grade;
  recommendations: Recommendation[];
  explanation: string;
  checkedAt: string;
}

export interface DataSharingAnalysis {
  thirdPartyTrackersFound: boolean;
  sharedDataTypes: string[]; // e.g., emails, IP address
  detail: string;
}

export interface PrivacyFeaturesAnalysis {
  cookieControlPresent: boolean;
  optOutMechanismPresent: boolean;
  encryptionMentioned: boolean;
  dataRetentionPolicyPresent: boolean;
  detail: string;
}

export interface Recommendation {
  issue: string;
  severity: Severity;
  suggestion: string;
}

export type Severity = "low" | "medium" | "high";
export type Grade = "A" | "B" | "C" | "D" | "F";

// -----------------------------
// Helper Functions
// -----------------------------

function gradeFromScore(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

// Basic keyword sets for detection
const GDPR_KEYWORDS = ["gdpr", "general data protection regulation", "european union", "eu privacy", "data subject rights"];
const CCPA_KEYWORDS = ["ccpa", "california consumer privacy act", "california", "consumer rights"];
const DATA_SHARING_KEYWORDS = ["share", "third party", "partner", "affiliate", "advertising network", "analytics", "tracking", "cookie", "pixel"];
const DATA_TYPES = ["email", "ip address", "location", "phone number", "cookies", "browsing history", "usage data"];
const PRIVACY_FEATURES_KEYWORDS = {
  cookieControlPresent: ["cookie consent", "cookie control", "cookie banner", "cookie preferences"],
  optOutMechanismPresent: ["opt out", "unsubscribe", "do not sell", "do not track"],
  encryptionMentioned: ["encryption", "ssl", "tls", "https", "secure connection"],
  dataRetentionPolicyPresent: ["data retention", "retention period", "data storage"]
};

function containsKeywords(text: string, keywords: string[]): boolean {
  const lower = text.toLowerCase();
  return keywords.some(k => lower.includes(k));
}

function findDataTypes(text: string): string[] {
  const found: string[] = [];
  const lower = text.toLowerCase();
  for (const dt of DATA_TYPES) {
    if (lower.includes(dt)) found.push(dt);
  }
  return found;
}

// -----------------------------
// Main Analyzer
// -----------------------------

export async function fullEnrich(rawUrl: string): Promise<EnricherResult | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: check.error };

  const url = check.url.toString();
  const start = performance.now();

  // Fetch privacy page text content
  let bodyText = "";
  try {
    // We fetch with 10s timeout
    const res = await safeFetch(url, { timeoutMs: 10000, headers: { "User-Agent": "privacy-policy-enricher/1.0 apimesh.xyz" } });
    if (!res.ok) {
      return { error: `HTTP error fetching ${url}: ${res.status} ${res.statusText}` };
    }
    const contentType = res.headers.get("content-type") || "";
    if (!contentType.includes("text/html")) {
      return { error: `Expected HTML content-type but got ${contentType}` };
    }

    // Limit body size to 512kB
    const maxBytes = 512 * 1024;
    const reader = res.body?.getReader();
    if (!reader) return { error: "No body reader available" };

    const chunks: Uint8Array[] = [];
    let readBytes = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        chunks.push(value);
        readBytes += value.length;
        if (readBytes >= maxBytes) break;
      }
    }
    const uint8All = new Uint8Array(readBytes);
    let offset = 0;
    for (const chunk of chunks) {
      uint8All.set(chunk, offset);
      offset += chunk.length;
    }
    const utf8decoder = new TextDecoder("utf-8");
    bodyText = utf8decoder.decode(uint8All);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return { error: "Analysis temporarily unavailable", detail: msg };
  }

  // Extract text content by stripping HTML tags (basic)
  const textContent = bodyText.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/[\s\n\r]+/g, " ")
    .trim();

  // Analyze GDPR & CCPA mentions
  const gdprDetected = containsKeywords(textContent, GDPR_KEYWORDS);
  const ccpaDetected = containsKeywords(textContent, CCPA_KEYWORDS);

  // Analyze data sharing
  const thirdPartyTrackersFound = containsKeywords(textContent, DATA_SHARING_KEYWORDS);
  const sharedDataTypes = findDataTypes(textContent);

  // Analyze privacy features
  const privacyFeatures: PrivacyFeaturesAnalysis = {
    cookieControlPresent: containsKeywords(textContent, PRIVACY_FEATURES_KEYWORDS.cookieControlPresent),
    optOutMechanismPresent: containsKeywords(textContent, PRIVACY_FEATURES_KEYWORDS.optOutMechanismPresent),
    encryptionMentioned: containsKeywords(textContent, PRIVACY_FEATURES_KEYWORDS.encryptionMentioned),
    dataRetentionPolicyPresent: containsKeywords(textContent, PRIVACY_FEATURES_KEYWORDS.dataRetentionPolicyPresent),
    detail: "",
  };

  // Compose detail strings
  const dataSharingDetails = [];
  if (thirdPartyTrackersFound) {
    dataSharingDetails.push("Privacy policy mentions sharing data with third parties such as advertising networks or analytics.");
  } else {
    dataSharingDetails.push("No explicit mention of third-party data sharing detected.");
  }
  if (sharedDataTypes.length > 0) {
    dataSharingDetails.push(`Data types shared described: ${sharedDataTypes.join(", ")}.`);
  } else {
    dataSharingDetails.push("No explicit data types detailed for sharing.");
  }

  privacyFeatures.detail = `Cookie control present: ${privacyFeatures.cookieControlPresent}, opt-out mechanism: ${privacyFeatures.optOutMechanismPresent}, encryption mentioned: ${privacyFeatures.encryptionMentioned}, data retention policy: ${privacyFeatures.dataRetentionPolicyPresent}.`;

  // Scoring: weighted mix
  // GDPR adds 15 points, CCPA 10
  // Data sharing negative if trackers found (-20)
  // Privacy features positive (+15)
  let score = 50;
  if (gdprDetected) score += 15;
  if (ccpaDetected) score += 10;
  if (thirdPartyTrackersFound) score -= 20;
  let pfScore = 0;
  if (privacyFeatures.cookieControlPresent) pfScore += 5;
  if (privacyFeatures.optOutMechanismPresent) pfScore += 5;
  if (privacyFeatures.encryptionMentioned) pfScore += 3;
  if (privacyFeatures.dataRetentionPolicyPresent) pfScore += 5;
  score += pfScore;

  if (score > 100) score = 100;
  if (score < 0) score = 0;

  // Grade
  const grade = gradeFromScore(score);

  // Recommendations
  const recommendations: Recommendation[] = [];

  if (!gdprDetected) {
    recommendations.push({
      issue: "GDPR compliance unclear",
      severity: "high",
      suggestion: "Clearly specify GDPR compliance details and data subject rights in your privacy policy.",
    });
  }

  if (!ccpaDetected) {
    recommendations.push({
      issue: "CCPA compliance missing",
      severity: "medium",
      suggestion: "Include California Consumer Privacy Act compliance details if applicable.",
    });
  }

  if (thirdPartyTrackersFound) {
    recommendations.push({
      issue: "Extensive third-party data sharing",
      severity: "high",
      suggestion: "Disclose specific third-party partners and purpose of data sharing; provide opt-out options.",
    });
  } else {
    recommendations.push({
      issue: "No third-party data sharing mentioned",
      severity: "low",
      suggestion: "Indicate explicitly if no third-party data sharing is conducted, to reassure users.",
    });
  }

  if (!privacyFeatures.cookieControlPresent) {
    recommendations.push({
      issue: "Cookie consent mechanism missing",
      severity: "high",
      suggestion: "Implement cookie control banners or consent management platform compliant with regulations.",
    });
  }

  if (!privacyFeatures.optOutMechanismPresent) {
    recommendations.push({
      issue: "Opt-out mechanism not described",
      severity: "medium",
      suggestion: "Provide clear methods for users to opt out of tracking or data sale.",
    });
  }

  if (!privacyFeatures.encryptionMentioned) {
    recommendations.push({
      issue: "Encryption and data security not addressed",
      severity: "medium",
      suggestion: "Mention encryption use to protect user data during transmission and storage.",
    });
  }

  if (!privacyFeatures.dataRetentionPolicyPresent) {
    recommendations.push({
      issue: "Data retention policies missing",
      severity: "medium",
      suggestion: "Specify how long user data is retained and deletion procedures.",
    });
  }

  // Compose explanation text
  const explanation = `This privacy policy was analyzed for GDPR and CCPA compliance mentions, data sharing declarations, and key privacy features. ${gdprDetected ? "GDPR-related information was found." : "No GDPR mentions detected."} ${ccpaDetected ? "References to the CCPA were found." : "No CCPA mentions detected."} Third-party data sharing is ${thirdPartyTrackersFound ? "present" : "not detected"}, with data types including: ${sharedDataTypes.length > 0 ? sharedDataTypes.join(", ") : "none explicitly stated"}. Key privacy features such as cookie control (${privacyFeatures.cookieControlPresent}), opt-out mechanisms (${privacyFeatures.optOutMechanismPresent}), encryption (${privacyFeatures.encryptionMentioned}), and data retention policies (${privacyFeatures.dataRetentionPolicyPresent}) were evaluated.`;

  const duration_ms = Math.round(performance.now() - start);

  return {
    url,
    gdprDetected,
    ccpaDetected,
    dataSharingPractices: {
      thirdPartyTrackersFound,
      sharedDataTypes,
      detail: dataSharingDetails.join(" "),
    },
    privacyFeatures,
    score,
    grade,
    recommendations,
    explanation,
    checkedAt: new Date().toISOString(),
  };
}