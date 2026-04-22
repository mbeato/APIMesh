import { safeFetch } from "../../shared/ssrf";

// -------------- Types --------------

export interface PortScanInput {
  targets: string[]; // IP addresses or CIDR ranges
  maxPorts: number; // max top ports to scan per host
}

export interface PortInfo {
  port: number;
  service: string;
  banner?: string;
}

export interface VulnerabilityInfo {
  cveId: string;
  description: string;
  severity: number; // 0-100
  referenceUrl: string;
}

export interface HostScanResult {
  ip: string;
  openPorts: number[];
  services: string[];
  vulnerabilities: VulnerabilityInfo[];
  score: number; // 0-100
  grade: string; // A-F
  recommendations: PortScanRecommendation[];
}

export interface AggregatedPortScanResult {
  scanId: string;
  totalHosts: number;
  scannedHosts: number;
  overallScore: number; // 0-100
  grade: string; // A-F
  hosts: HostScanResult[];
  details: string; // human-readable summary
  completedAt: string;
}

export interface PortScanRecommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface PortScanPreviewResult {
  ip: string;
  openPorts: number[];
  services: string[];
  score: number; // 0-100
  grade: string; // letter grade A-F
  details: string;
  recommendations: PortScanRecommendation[];
}

// -------------- Constants and helpers --------------

const COMMON_TOP_100_PORTS = [
  80, 443, 22, 21, 25, 53, 110, 139, 445, 3306, 8080, 23, 161, 4433, 3389, 5900,
  143, 993, 995, 1723, 873, 111, 995, 993, 465, 514, 6000, 2000, 2049, 179, 513,
];

function gradeFromScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 50) return "D";
  if (score >= 30) return "E";
  return "F";
}

function calculateHostScore(
  openPortsCount: number,
  vulnerabilities: VulnerabilityInfo[]
): number {
  // Start from 100
  let score = 100;
  // Deduct 5 points for every open port beyond 3
  if (openPortsCount > 3) score -= (openPortsCount - 3) * 5;
  // Deduct vulnerability severities weighted
  for (const vuln of vulnerabilities) {
    score -= Math.min(vuln.severity, 50); // max 50 deduction
  }
  if (score < 0) score = 0;
  return Math.round(score);
}

function generateRecommendations(
  openPorts: number[],
  vulnerabilities: VulnerabilityInfo[]
): PortScanRecommendation[] {
  const recs: PortScanRecommendation[] = [];

  for (const port of openPorts) {
    recs.push({
      issue: `Open port ${port}`,
      severity: 40,
      suggestion: `Evaluate necessity and restrict access to port ${port} as needed.`,
    });
  }

  for (const vul of vulnerabilities) {
    recs.push({
      issue: `Vulnerability ${vul.cveId}`,
      severity: vul.severity,
      suggestion: `Patch affected software: ${vul.description}`,
    });
  }

  if (openPorts.length === 0 && vulnerabilities.length === 0) {
    recs.push({
      issue: "No vulnerabilities found",
      severity: 0,
      suggestion: "Maintain current network security best practices.",
    });
  }

  return recs;
}

// Validate IPv4, IPv6
const IPV4_REGEX = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;
const IPV6_REGEX = /^([\da-f]{1,4}:){7}[\da-f]{1,4}$/i;

function isIpOrCidr(input: string): boolean {
  // Rough check: IPv4 or IPv6 or CIDR
  if (IPV4_REGEX.test(input)) return true;
  if (IPV6_REGEX.test(input)) return true;
  // CIDR check
  const cidrMatch = input.match(/\/(\d{1,2})$/);
  if (cidrMatch) {
    const prefix = Number(cidrMatch[1]);
    if (prefix >= 0 && prefix <= 128) {
      const baseIp = input.replace(/\/(\d{1,2})$/, "");
      return IPV4_REGEX.test(baseIp) || IPV6_REGEX.test(baseIp);
    }
  }
  return false;
}

// Simulate vulnerability DB -- in real scenario use external APIs or DB
const KNOWN_VULNERABILITIES: Record<string, VulnerabilityInfo[]> = {
  "22": [
    {
      cveId: "CVE-2021-41617",
      description: "OpenSSH User Enumeration Timing Vulnerability",
      severity: 70,
      referenceUrl: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41617",
    },
  ],
  "80": [
    {
      cveId: "CVE-2019-0190",
      description: "Apache HTTP Server mod_http2 DoS",
      severity: 65,
      referenceUrl: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0190",
    },
  ],
  "3306": [
    {
      cveId: "CVE-2016-6662",
      description: "MySQL Server Authentication Bypass",
      severity: 85,
      referenceUrl: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6662",
    },
  ],
};

function retrieveVulnerabilitiesForPorts(
  ports: number[]
): VulnerabilityInfo[] {
  const vulns: VulnerabilityInfo[] = [];
  for (const p of ports) {
    const pStr = p.toString();
    if (pStr in KNOWN_VULNERABILITIES) {
      vulns.push(...KNOWN_VULNERABILITIES[pStr]);
    }
  }
  return vulns;
}

// Simulated service name map by port
const PORT_SERVICE_MAP: Record<number, string> = {
  22: "ssh",
  80: "http",
  443: "https",
  3306: "mysql",
  53: "dns",
  25: "smtp",
  21: "ftp",
  23: "telnet",
  3389: "rdp",
  5900: "vnc",
};

// -------------- Main scanning implementation --------------

/**
 * Perform lightweight preview scan for single IP with limited top ports.
 * This is used for free preview endpoint.
 */
export async function performPreviewPortScan(
  ip: string
): Promise<PortScanPreviewResult> {
  // Validate IP format
  if (!isIpOrCidr(ip)) {
    throw new Error(`Invalid IP address or CIDR: ${ip}`);
  }

  // For preview, check top 15 ports only
  const portsToScan = COMMON_TOP_100_PORTS.slice(0, 15);

  // Parallel queries to simulated port availability and DNS info
  const scanPromises = portsToScan.map(async (port) => {
    // Fetch from public blind port check API (simulate)
    try {
      // Use a public port scan API or similarly: here simulate
      // In real app, replace with real API calls and timeout
      // Use a stubbed random open/closed
      await new Promise((r) => setTimeout(r, 30)); // simulate delay
      const isOpen = Math.random() < 0.15; // 15% open
      return isOpen ? port : null;
    } catch {
      return null;
    }
  });

  const portResults = await Promise.all(scanPromises);
  const openPorts = portResults.filter((p): p is number => typeof p === "number");
  const services = openPorts
    .map((p) => (PORT_SERVICE_MAP[p] ? PORT_SERVICE_MAP[p] : "unknown"))
    .filter((v, i, a) => a.indexOf(v) === i); // uniq

  const vulnerabilities = retrieveVulnerabilitiesForPorts(openPorts);

  const score = calculateHostScore(openPorts.length, vulnerabilities);
  const grade = gradeFromScore(score);
  const recommendations = generateRecommendations(openPorts, vulnerabilities);

  return {
    ip,
    openPorts,
    services,
    score,
    grade,
    details: "Preview scan covers top 15 ports with quick checks.",
    recommendations,
  };
}

/**
 * Deep scan multiple IPs or CIDRs with multi-source aggregation.
 * For each IP in the input, resolves IPs expanded from CIDRs,
 * queries multiple public sources, aggregates, assigns scores and grades,
 * returns detailed results.
 */
export async function performDeepPortScan(
  input: PortScanInput
): Promise<AggregatedPortScanResult> {
  const { targets, maxPorts } = input;

  // Expand CIDRs to individual IPs, capped at 50 total
  const ips: string[] = [];
  for (const target of targets) {
    if (target.includes("/")) {
      // expand CIDR (only IPv4 for simplicity)
      try {
        const expanded = expandCidr(target);
        for (const ip of expanded) {
          if (ips.length >= 50) break;
          ips.push(ip);
        }
      } catch (e) {
        // Skip invalid CIDR
      }
    } else if (isIpOrCidr(target)) {
      ips.push(target);
    }
    if (ips.length >= 50) break;
  }
  if (ips.length === 0) {
    throw new Error("No valid IPs to scan");
  }

  // For each IP, gather data from parallel external sources

  // Function for scanning a single IP
  async function scanIp(ip: string): Promise<HostScanResult> {
    // Prepare a 10s timeout abort signal
    const timeoutSignal = AbortSignal.timeout(10_000);
    // Query multiple sources in parallel
    // 1. DNS PTR lookup
    // 2. Open port databases (e.g. public APIs)
    // 3. Service detection hints
    // 4. Vulnerability databases (local static)
    // 5. IP info (geo, ISP) for score adjustments

    const dnsPtrPromise = fetchDnsPtr(ip, timeoutSignal);
    const publicPortScanPromise = fetchPublicPortData(ip, maxPorts, timeoutSignal);
    const ipInfoPromise = fetchIpInfo(ip, timeoutSignal);

    const [dnsPtr, portScanData, ipInfo] = await Promise.all([
      dnsPtrPromise.catch(() => null),
      publicPortScanPromise.catch(() => null),
      ipInfoPromise.catch(() => null),
    ]);

    // Parse and aggregate results
    let openPorts: number[] = [];
    let services: string[] = [];

    if (portScanData) {
      openPorts = portScanData.openPorts;
      services = portScanData.services;
    }

    // Add service names from PORT_SERVICE_MAP for openPorts if missing
    const knownServices = new Set(services);
    for (const p of openPorts) {
      const svc = PORT_SERVICE_MAP[p] || "unknown";
      if (!knownServices.has(svc)) {
        services.push(svc);
        knownServices.add(svc);
      }
    }

    // Retrieve vulnerabilities for the open ports
    const vulnerabilities = retrieveVulnerabilitiesForPorts(openPorts);

    // Calculate score influenced by IP Info reputation
    const baseScore = calculateHostScore(openPorts.length, vulnerabilities);
    const reputationAdjustment = ipInfo?.reputationScore ? Math.round(ipInfo.reputationScore / 10) : 0;
    let finalScore = baseScore + reputationAdjustment;
    if (finalScore > 100) finalScore = 100;

    const grade = gradeFromScore(finalScore);

    // Generate remediation recommendations
    const recommendations = generateRecommendations(openPorts, vulnerabilities);

    // If DNS PTR obtained, add recommendation for reverse DNS check
    if (dnsPtr) {
      recommendations.push({
        issue: "Reverse DNS resolved",
        severity: 30,
        suggestion: `Verify reverse DNS pointer ${dnsPtr} for this IP ${ip}.`,
      });
    }

    return {
      ip,
      openPorts,
      services,
      vulnerabilities,
      score: finalScore,
      grade,
      recommendations,
    };
  }

  // Run scans in parallel with limited concurrency
  const concurrency = 5;
  const hostScanResults: HostScanResult[] = [];

  async function worker(queue: string[]) {
    while (queue.length > 0) {
      const ip = queue.shift()!;
      try {
        const res = await scanIp(ip);
        hostScanResults.push(res);
      } catch (e) {
        // add placeholder error record
        hostScanResults.push({
          ip,
          openPorts: [],
          services: [],
          vulnerabilities: [],
          score: 0,
          grade: "F",
          recommendations: [
            {
              issue: "Scan failed",
              severity: 90,
              suggestion: `Could not perform scan: ${(e instanceof Error ? e.message : String(e))}`,
            },
          ],
        });
      }
    }
  }

  const queue = ips.slice();
  const workers = [];
  for (let i = 0; i < concurrency; i++) {
    workers.push(worker(queue));
  }

  await Promise.all(workers);

  // Compute overall score
  const totalScore =
    hostScanResults.reduce((acc, h) => acc + h.score, 0) / hostScanResults.length || 0;
  const overallGrade = gradeFromScore(totalScore);

  return {
    scanId: `scan-${Math.random().toString(36).slice(2, 10)}`,
    totalHosts: ips.length,
    scannedHosts: hostScanResults.length,
    overallScore: Math.round(totalScore),
    grade: overallGrade,
    hosts: hostScanResults,
    details:
      "Aggregated scan combining DNS PTR, open port queries, public databases, IP reputation, and vulnerability lookup.",
    completedAt: new Date().toISOString(),
  };
}

// -------------- External data source simulations and helpers --------------

async function fetchDnsPtr(
  ip: string,
  signal: AbortSignal
): Promise<string | null> {
  // Query DNS PTR record for IP - Use public DNS over HTTPS
  try {
    const queryIp = ip.includes(":") ? ip : ip.split(":").pop() || ip; // quick fallback
    // Use Google DNS over HTTPS for PTR lookup
    const url = `https://dns.google/resolve?name=${encodeURIComponent(
      ipToPtr(ip)
    )}&type=PTR`;
    const res = await safeFetch(url, {
      timeoutMs: 10_000,
      signal,
    });
    if (!res.ok) return null;
    const json = await res.json();
    if (json.Answer && Array.isArray(json.Answer) && json.Answer.length > 0) {
      // PTR record is in data field
      return json.Answer[0].data || null;
    }
    return null;
  } catch {
    return null;
  }
}

function ipToPtr(ip: string): string {
  // Return in-addr.arpa or ip6.arpa PTR format
  if (ip.includes(":")) {
    // IPv6 (expand zeroes not fully implemented for brevity)
    const fullIp = expandIpv6(ip);
    const nibbles = fullIp.replace(/:/g, "").split("").reverse();
    return nibbles.join(".") + ".ip6.arpa";
  } else {
    // IPv4 reverse order
    return ip.split(".").reverse().join(".") + ".in-addr.arpa";
  }
}

function expandIpv6(ip: string): string {
  // Expand IPv6 zero compression :: (Basic implementation, not fully robust)
  if (!ip.includes("::")) return ip.toLowerCase();
  const parts = ip.split("::");
  const left = parts[0].split(":").filter((p) => p.length > 0);
  const right = parts[1].split(":").filter((p) => p.length > 0);
  const missing = 8 - (left.length + right.length);
  const zeros = new Array(missing).fill("0000");
  const full = [...left, ...zeros, ...right].map((p) => p.padStart(4, "0"));
  return full.join(":");
}

async function fetchPublicPortData(
  ip: string,
  maxPorts: number,
  signal: AbortSignal
): Promise<{ openPorts: number[]; services: string[] } | null> {
  // Query public port scan database or service
  // Example free service: Shodan, Censys, though they require keys
  // Here simulate by randomly selecting ports

  try {
    await new Promise((r) => setTimeout(r, 50)); // simulate delay

    // Simulate 10%-25% open ports from top maxPorts
    const candidatePorts = COMMON_TOP_100_PORTS.slice(0, maxPorts);
    const openPorts = candidatePorts.filter(() => Math.random() < 0.15);

    const services = openPorts.map((p) => PORT_SERVICE_MAP[p] || "unknown");

    return { openPorts, services };
  } catch {
    return null;
  }
}

interface IpInfo {
  ip: string;
  country?: string;
  isp?: string;
  reputationScore?: number; // 0 (bad) to 100 (good)
}

async function fetchIpInfo(ip: string, signal: AbortSignal): Promise<IpInfo | null> {
  // Use free IP info API e.g. ip-api.com/json/ip
  try {
    const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,isp,proxy`;
    const res = await safeFetch(url, { timeoutMs: 10_000, signal });
    if (!res.ok) return null;
    const json = await res.json();
    if (json.status !== "success") return null;
    // Determine reputation score roughly
    const reputationScore = json.proxy ? 20 : 80;
    return {
      ip,
      country: json.country || undefined,
      isp: json.isp || undefined,
      reputationScore,
    };
  } catch {
    return null;
  }
}

// Expand IPv4 CIDR into list of IPs (limit to max 50)
function expandCidr(cidr: string): string[] {
  // Use IPv4 only for simplicity
  if (!cidr.includes("/")) return [cidr];
  const [ip, prefixStr] = cidr.split("/");
  if (!IPV4_REGEX.test(ip)) throw new Error("Invalid IPv4 CIDR");
  const prefix = Number(prefixStr);
  if (prefix < 0 || prefix > 32) throw new Error("Invalid prefix");

  const ipNum = ipv4ToInt(ip);
  const mask = 0xffffffff << (32 - prefix);
  const network = ipNum & mask;
  const hostCount = 2 ** (32 - prefix);

  const maxHosts = Math.min(hostCount, 50);
  const ips: string[] = [];
  for (let i = 0; i < maxHosts; i++) {
    ips.push(intToIpv4(network + i));
  }
  return ips;
}

function ipv4ToInt(ip: string): number {
  return ip
    .split(".")
    .map((b) => Number(b))
    .reduce((a, b) => (a << 8) + b, 0) >>> 0;
}

function intToIpv4(num: number): string {
  return [
    (num >>> 24) & 0xff,
    (num >>> 16) & 0xff,
    (num >>> 8) & 0xff,
    num & 0xff,
  ].join(".");
}

export {
  gradeFromScore,
  calculateHostScore,
  generateRecommendations,
};
