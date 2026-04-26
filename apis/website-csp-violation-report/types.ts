export type Grade = "A+" | "A" | "B" | "C" | "D" | "F";

export interface IssueRecommendation {
  issue: string;
  severity: "critical" | "warning" | "info";
  suggestion: string;
}

export interface ViolationDetails {
  document_uri: string;
  referrer: string | null;
  violated_directive: string | null;
  original_policy: string | null;
  blocked_uri: string | null;
  effective_directive: string | null;
  source_file: string | null;
  line_number: number | null;
  column_number: number | null;
  status_code: number | null;
  script_sample: string | null;
}

export interface ReportEnvelope {
  "csp-report": ViolationDetails;
}

export interface ReportAnalysis {
  score: number; // 0-100 numeric
  grade: Grade;
  severity: "critical" | "warning" | "info";
  summary: string;
  details: string;
  recommendations: IssueRecommendation[];
  rawReport: ViolationDetails;
}

export interface InfoEndpointResponse {
  api: string;
  status: string;
  version: string;
  docs: {
    endpoints: {
      method: string;
      path: string;
      description: string;
      parameters: {
        name: string;
        description: string;
        required: boolean;
        type: string;
      }[];
      example_response: unknown;
    }[];
    parameters: {
      name: string;
      description: string;
      required: boolean;
      type: string;
    }[];
    examples: {
      description: string;
      request: string;
      response: unknown;
    }[];
  };
  pricing: {
    preview: string;
    paid: string;
  };
}
