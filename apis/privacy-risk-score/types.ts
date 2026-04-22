export type GradeLetter = "A" | "B" | "C" | "D" | "E" | "F";

export interface Recommendation {
  issue: string;
  severity: "low" | "medium" | "high" | "critical";
  suggestion: string;
}

export interface DisclosureElement {
  type: string; // e.g., "data-sharing", "gdpr-notice", "ccpa-notice", "cookie-policy"
  text: string; // Extracted text snippet
  confidence: number; // NLP confidence score 0-1
  severity?: "low" | "medium" | "high" | "critical";
}

export interface SourceFetchResult {
  url: string;
  fetchedUrl: string; // Actual final downloaded URL after redirects
  status: number;
  contentType: string | null;
  bodySnippet: string; // First ~2KB snippet of body
  error?: string;
}

export interface ComplianceSignals {
  gdprDetected: boolean;
  gdprScore: number; // 0-100
  ccpaDetected: boolean;
  ccpaScore: number; // 0-100
  dataSharingCount: number; // number of data sharing mentions
}

export interface PrivacyRiskScoreResponse {
  domain: string;
  sources: SourceFetchResult[];
  disclosures: DisclosureElement[];
  compliance: ComplianceSignals;
  riskScore: number; // 0-100, higher means higher privacy risk
  grade: GradeLetter; // Based on riskScore, A=best, F=worst
  recommendations: Recommendation[];
  explanation: string;
}

export interface PreviewResponse {
  domain: string;
  fetchedUrl?: string;
  preview: true;
  summary: string;
  compliance?: Partial<ComplianceSignals>;
  note: string;
}

export interface InfoDocEndpoint {
  method: string;
  path: string;
  description: string;
  parameters: Array<{ name: string; required: boolean; description: string }>;
  exampleResponse: object;
}

export interface InfoDoc {
  api: string;
  status: string;
  version: string;
  docs: {
    endpoints: InfoDocEndpoint[];
    parameters: Array<{ name: string; description: string }>;
    examples: Array<{ request: string; response: object }>;
  };
  pricing: {
    tiers: Array<{ level: string; price: string; description: string }>;
  };
}
