export type ScoreGrade = "A" | "B" | "C" | "D" | "F";

export interface Recommendation {
  issue: string;
  severity: "low" | "medium" | "high";
  suggestion: string;
}

export interface SslScanReport {
  supportsTlsVersions: string[];
  weakProtocolsDetected: boolean;
  ciphersSummary: {
    total: number;
    weak: number;
    strong: number;
  };
  detailsUrl?: string;
}

export interface DnsRecord {
  type: string;
  host: string;
  value: string;
  ttl: number;
}

export interface TlsHandshakeInfo {
  protocolVersion: string | null;
  cipherSuite: string | null;
  sessionResumed: boolean;
  serverCertificates: string[];
  error?: string;
}

export interface ComplianceScores {
  tlsSupportScore: number; // 0-100
  cipherStrengthScore: number; // 0-100
  overall: number; // 0-100
  grade: ScoreGrade;
}

export interface AuditResult {
  domain: string;
  sslScan: SslScanReport;
  dnsRecords: DnsRecord[] | null;
  tlsHandshake: TlsHandshakeInfo;
  complianceScores: ComplianceScores;
  recommendations: Recommendation[];
  explanation: string;
}

export interface PreviewResult {
  domain: string;
  preview: true;
  tlsSupportSummary: string;
  recommendations: Recommendation[];
  note: string;
}
