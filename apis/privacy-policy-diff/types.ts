export interface PolicyVersion {
  url: string;
  fetchedAt: string; // ISO8601
  rawText: string;
}

export interface ComplianceSignal {
  id: string;
  description: string;
  severity: number; // 0-100
  scoreImpact: number; // positive or negative score delta
  examples?: string[];
}

export interface PolicyDiff {
  fetchedAtOld: string;
  fetchedAtNew: string;
  changesSummary: string;
  severityScore: number; // 0-100
  grade: string; // A-F
  complianceSignals: ComplianceSignal[];
  recommendations: PolicyRecommendation[];
  detailedChanges: DiffDetail[];
}

export interface DiffDetail {
  section: string;
  changeType: "added" | "removed" | "modified";
  contentBefore?: string;
  contentAfter?: string;
  severityImpact: number; // 0-100
  explanation: string;
}

export interface PolicyRecommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface DiffResult {
  domain: string;
  policyOld: PolicyVersion;
  policyNew: PolicyVersion;
  diff: PolicyDiff;
  analysisDate: string;
  processingTimeMs: number;
}

export interface PreviewResult {
  domain: string;
  latestPolicyIndexUrl: string | null;
  previewTextSnippet: string;
  previewTimestamp: string;
  note: string;
  analysisDate: string;
  processingTimeMs: number;
}