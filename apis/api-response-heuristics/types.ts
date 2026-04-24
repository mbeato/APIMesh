export interface ApiHeuristicsInput {
  url: string;
}

export interface ApiResponseHeaders {
  [key: string]: string | null;
}

export interface FetchTiming {
  startTimeIso: string;
  durationMs: number;
}

export interface ResponseSummary {
  statusCode: number;
  headers: ApiResponseHeaders;
  fetchTiming: FetchTiming;
  bodyPreview: string | null;
  contentType: string | null;
}

export interface EndpointAnalysis {
  url: string;
  stableResponse: boolean;
  statusCodeDiversity: number; // number of distinct status codes observed
  commonStatusCodes: number[]; // top observed status codes
  averageResponseTimeMs: number;
  responseSamples: ResponseSummary[];
  inferredApiType: string;
  complexityScore: number; // 0-100
  issues: string[];
  score: number; // 0-100 overall
  grade: string; // A-F
  recommendations: Recommendation[];
  details: string;
}

export interface Recommendation {
  issue: string;
  severity: "low" | "medium" | "high" | "critical";
  suggestion: string;
}

export interface HeuristicsResult {
  analyzedUrl: string;
  analysis: EndpointAnalysis;
  reportGeneratedAt: string;
}

export interface PreviewResult {
  url: string;
  reachable: boolean;
  statusCode: number | null;
  contentType: string | null;
  responseTimeMs: number | null;
  note: string;
}
