export interface EndpointDiscoveryRequest {
  url: string;
  maxDepth?: number; // optional crawl depth, default 2
  maxEndpoints?: number; // optional max total endpoints to discover, default 50
}

export interface EndpointInfo {
  path: string; // URL path
  methods: string[]; // HTTP methods detected (GET, POST, etc.)
  statusCodes: Record<number, number>; // count of responses by status code
  contentTypes: Record<string, number>; // count of content-types seen
  sampleResponses: string[]; // small samples of bodies (up to 3)
  lastChecked: string; // ISO timestamp
}

export interface EndpointGraphNode {
  path: string;
  methods: string[];
  statusCodes: Record<number, number>;
  contentTypes: Record<string, number>;
  sampledBodies: string[];
}

export interface EndpointDiscoveryResult {
  baseUrl: string;
  crawledPaths: number;
  discoveredEndpoints: EndpointInfo[];
  score: number; // 0-100, coverage and data richness
  grade: string; // A-F letter grade
  recommendations: Array<{ issue: string; severity: number; suggestion: string }>;
  explanation: string;
  completedAt: string; // ISO timestamp
}

export interface DiscoveryPreviewResult {
  baseUrl: string;
  samplePaths: string[];
  note: string;
  preview: true;
  timestamp: string;
}
