export type GradeLetter = "A" | "B" | "C" | "D" | "E" | "F";

export interface Recommendation {
  issue: string;
  severity: number; // 1 (low) to 10 (critical)
  suggestion: string;
}

export interface ASNInfo {
  asn: number | null;
  name: string | null;
  country: string | null;
  description: string | null;
  routeCount?: number | null; // optional extended info
}

export interface ISPInfo {
  isp: string | null;
  organization: string | null;
  asn: number | null;
  queryIp: string; // the IP that was queried
}

export interface GeoLocation {
  country: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string | null;
  postalCode: string | null;
}

export interface RoutingInfo {
  originAS: number | null;
  ASPath: number[]; // full AS path if available
  prefixes: string[]; // announced IP prefixes
  peersCount?: number; // number of peers seen in routings
}

export interface IPInfrastructureAnalysis {
  inputIP: string;
  isValidIp: boolean;
  asnInfo: ASNInfo;
  ispInfo: ISPInfo;
  geoLocation: GeoLocation;
  routingInfo: RoutingInfo;

  score: number; // 0-100 numeric score representing confidence + risk
  grade: GradeLetter; // A-F computed from score
  recommendations: Recommendation[];
  details: string; // overall human-readable explanation
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
      parameters: { name: string; type: string; required: boolean; description: string }[];
      exampleResponse: object;
    }[];
    parameters: { name: string; type: string; description: string }[];
    examples: { name: string; description: string; request: string; response: object }[];
  };
  pricing: {
    pricePerCall: string;
    notes: string;
  };
}
