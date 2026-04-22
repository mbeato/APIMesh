export interface Recommendation {
  issue: string;
  severity: "low" | "medium" | "high" | "critical";
  suggestion: string;
}

export type GradeLetter = "A" | "B" | "C" | "D" | "E" | "F";

export interface SectionScore {
  score: number; // 0-100
  grade: GradeLetter;
  explanation: string;
}

export interface SSLCertificateDetails {
  valid: boolean;
  subject: string;
  issuer: string;
  validFrom: string | null;
  validTo: string | null;
  expiryDays: number | null;
  signatureAlgorithm?: string;
  strengthScore: number;
  errors: string[];
}

export interface TLSAnalysis {
  protocolsSupported: string[];
  deprecatedProtocols: string[];
  strongestCipher: string | null;
  cipherStrengthScore: number; // 0-100
  cipherSuitesTested: string[];
  unsupportedByServer: string[];
  errors: string[];
}

export interface SecurityHeadersAnalysis {
  headersPresent: string[];
  headersMissing: string[];
  headersWeak: string[];
  overallGrade: GradeLetter;
  score: number;
  details: string;
}

export interface HardeningScoreResult {
  url: string;
  sslCertificate: SSLCertificateDetails;
  tlsAnalysis: TLSAnalysis;
  securityHeaders: SecurityHeadersAnalysis;
  combinedScore: number;
  combinedGrade: GradeLetter;
  recommendations: Recommendation[];
  checkedAt: string;
}

export interface PreviewResult {
  url: string;
  preview: true;
  sslCertificateSummary: {
    valid: boolean;
    expiryDays: number | null;
  };
  tlsSummary: {
    strongProtocols: string[];
    weakProtocols: string[];
  };
  overallScore: number;
  overallGrade: GradeLetter;
  checkedAt: string;
  note: string;
}
