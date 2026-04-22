export interface RiskRecommendation {
  issue: string;
  severity: number; // 1-10
  suggestion: string;
}

export interface SslProtocolScore {
  protocol: string; // e.g. TLS 1.0
  deprecated: boolean;
  scoreImpact: number; // 0 to 100 where 0 is worst
  explanation: string;
}

export interface CipherSuiteInfo {
  name: string;
  strengthScore: number; // 0-100
  deprecated: boolean;
  explanation: string;
}

export interface CertificateTransparencyEntry {
  loggedAt: string; // ISO date
  issuer: string;
  subject: string;
  isValid: boolean;
  notBefore: string; // ISO date
  notAfter: string; // ISO date
  signatureAlgorithm: string;
}

export interface DnsTlsRecords {
  tlsa?: string[];
  cAA?: string[];
  dANE?: string[]; 
  explanation: string;
}

export interface RiskScore {
  numeric: number; // 0-100 (higher is better)
  grade: "A" | "B" | "C" | "D" | "F";
}

export interface RiskAssessment {
  overallScore: RiskScore;
  protocolsEvaluated: SslProtocolScore[];
  weakCiphers: CipherSuiteInfo[];
  certTransparencyIssues: string[];
  dnsTlsRecords: DnsTlsRecords;
  recommendations: RiskRecommendation[];
  explanation: string;
  checkedAt: string; // ISO 8601
  targetHost: string;
}
