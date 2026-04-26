export interface NetworkPathInferResult {
  targetIp: string;
  targetHostname?: string;
  asnHops: AsnHop[];
  pathScore: number; // 0-100
  pathGrade: string; // A-F
  geolocations: GeoLocation[];
  topologyGraphSvg?: string;
  explanation: string;
  recommendations: Recommendation[];
  analyzedAt: string;
}

export interface AsnHop {
  hopIndex: number;
  ip: string;
  asn: number | null;
  asnName: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  error?: string;
}

export interface GeoLocation {
  ip: string;
  country: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
}

export interface Recommendation {
  issue: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  suggestion: string;
}

export interface InferRequest {
  target: string; // IP or hostname
}
