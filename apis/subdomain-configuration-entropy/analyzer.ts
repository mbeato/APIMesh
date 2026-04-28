import { safeFetch, validateExternalUrl } from "../../shared/ssrf";

// --- Types ---

export interface Recommendation {
  issue: string;
  severity: "low" | "medium" | "high";
  suggestion: string;
}

export interface SubdomainConfigEntropyResult {
  domain: string;
  totalSubdomainsAnalyzed: number;
  uniqueDnsRecords: number;
  txtEntropyScore: number; // 0-100 numeric diversity score
  cnameConsistencyGrade: "A" | "B" | "C" | "D" | "F";
  ttlStabilityScore: number; // 0-100
  anomalyDetections: string[];
  grade: number; // 0-100 overall
  explanation: string;
  recommendations: Recommendation[];
}

export interface SubdomainConfigEntropyPreviewResult {
  domain: string;
  subdomainsScanned: number;
  distinctDnsRecords: number;
  txtRecordsDiversity: number; // 0-1 fraction
  cNameConsistencyScore: number; // 0-100
  explanation: string;
  grade: number; // 0-100
  recommendations: Recommendation[];
}

// --- Utility Functions ---

function entropy(counts: number[]): number {
  const total = counts.reduce((a, b) => a + b, 0);
  if (total === 0) return 0;
  let ent = 0;
  for (const c of counts) {
    if (c === 0) continue;
    const p = c / total;
    ent -= p * Math.log2(p);
  }
  return ent;
}

function gradeFromScore(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

// Normalize TTL variance to 0 to 100 with 100 being most stable (low variance)
function ttlStability(ttls: number[]): number {
  if (ttls.length === 0) return 0;
  const mean = ttls.reduce((a, b) => a + b, 0) / ttls.length;
  const variance = ttls.reduce((a, b) => a + (b - mean) ** 2, 0) / ttls.length;
  // Map variance to 0-100 scale with max variance capped at 3600
  const cappedVar = Math.min(variance, 3600);
  const score = 100 - (cappedVar / 3600) * 100;
  return Math.round(score);
}

// Fetch DNS records via Google DNS-over-HTTPS JSON API
async function fetchDnsRecords(name: string, type: string, signal: AbortSignal): Promise<DnsAnswerRecord[]> {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
  try {
    const res = await safeFetch(url, { signal, timeoutMs: 10000 });
    if (!res.ok) {
      throw new Error(`DNS query failed status ${res.status}`);
    }
    const data = await res.json();
    if (!data.Answer) return [];
    return data.Answer as DnsAnswerRecord[];
  } catch (e) {
    throw e;
  }
}

interface DnsAnswerRecord {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

// Extract unique subdomains for a domain using NS, A and CNAME records for common zone
// We limit to a max of 50 subdomains (sample) to avoid very long processing
// For preview, max 10 subdomains
async function fetchSubdomains(domain: string, limit: number, signal: AbortSignal): Promise<string[]> {
  // We try to fetch NS records for domain and then A, CNAME on first 100 common sub-subdomains (generated heuristically)
  // As we lack zone transfer, we try common prefixes
  const commonPrefixes = [
    "www",
    "mail",
    "ftp",
    "webmail",
    "smtp",
    "ns1",
    "ns2",
    "api",
    "blog",
    "dev",
    "staging",
    "beta",
    "shop",
    "test",
    "portal",
    "vpn",
    "admin",
    "m",
    "mobile",
    "cdn",
    "static",
    "support",
    "email",
    "crm",
    "docs",
    "help",
    "news",
    "prod",
    "uat",
  ];

  const candidates: string[] = [];

  for (const prefix of commonPrefixes) {
    candidates.push(prefix + "." + domain);
    if (candidates.length >= limit) break;
  }

  // For each candidate, check if DNS records exist via A or CNAME
  const foundSubdomains: string[] = [];
  const signalTimeout = signal;

  try {
    const lookupPromises = candidates.map(async (subdomain) => {
      // Make parallel calls for A and CNAME
      const signals = [
        AbortSignal.timeout(10000),
        AbortSignal.timeout(10000),
      ];
      try {
        const [aRecords, cnameRecords] = await Promise.all([
          fetchDnsRecords(subdomain, "A", signals[0]),
          fetchDnsRecords(subdomain, "CNAME", signals[1]),
        ]);
        if (aRecords.length > 0 || cnameRecords.length > 0) {
          return subdomain;
        }
      } catch {
        return null;
      }
      return null;
    });

    const results = await Promise.all(lookupPromises);
    for (const res of results) {
      if (res) foundSubdomains.push(res);
      if (foundSubdomains.length >= limit) break;
    }
  } catch {
    // Fail silently
  }

  return foundSubdomains;
}

// Parse TXT record data to get records array
function parseTxtRecordData(data: string): string[] {
  // Google DNS returns TXT data as "\"v=spf1 include:_spf.google.com ~all\""
  // Strip wrapping quotes and split on spaces
  const trimmed = data.trim();
  let txt = trimmed;
  if (txt.startsWith('"') && txt.endsWith('"')) {
    txt = txt.slice(1, -1);
  }
  return txt.split(/\s+/).filter(Boolean);
}

// Count distinct TXT record token sets across subdomains
function calculateTxtDiversity(txtSets: string[][]): number {
  if (txtSets.length === 0) return 0;
  // Count unique token sets as strings
  const uniqueSets = new Set<string>();
  for (const txt of txtSets) {
    const sortedTokens = [...txt].sort().join(" ");
    uniqueSets.add(sortedTokens);
  }
  // Diversity fraction
  return uniqueSets.size / txtSets.length;
}

// Calculate CNAME consistency score (0-100)
function calculateCnameConsistency(cnames: string[]): number {
  if (cnames.length === 0) return 100;
  // Majority target
  const counts: Record<string, number> = {};
  for (const ctarget of cnames) {
    counts[ctarget] = (counts[ctarget] || 0) + 1;
  }
  const maxCount = Math.max(...Object.values(counts));
  return Math.round((maxCount / cnames.length) * 100);
}

// Generate letter grade from score
function letterGrade(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

// Main comprehensive analysis function
export async function analyzeSubdomainConfigurations(domain: string): Promise<SubdomainConfigEntropyResult | { error: string }> {
  // Validate domain format rudimentarily
  if (!/^[a-z0-9.-]+$/i.test(domain)) {
    return { error: "Invalid domain format" };
  }

  // AbortSignal timeout for full analysis
  const signal = AbortSignal.timeout(20_000);

  try {
    // Step 1: Find subdomains by common prefixes
    const subdomains = await fetchSubdomains(domain, 50, signal);
    if (subdomains.length === 0) {
      return {
        domain,
        totalSubdomainsAnalyzed: 0,
        uniqueDnsRecords: 0,
        txtEntropyScore: 0,
        cnameConsistencyGrade: "F",
        ttlStabilityScore: 0,
        anomalyDetections: ["No subdomains with DNS records found."],
        grade: 0,
        explanation: "No detectable subdomains with DNS records. Could indicate a dormant domain or DNS resolution issues.",
        recommendations: [
          {
            issue: "No detectable subdomains",
            severity: "high",
            suggestion: "Verify DNS zone configuration and consider registering subdomains.",
          },
        ],
      };
    }

    // Step 2: For each subdomain, fetch DNS record sets in parallel
    // Types: A, AAAA, CNAME, TXT, MX, NS (limited)
    type DnsData = {
      a: string[];
      aaaa: string[];
      cname: string | null;
      txt: string[];
      mx: string[];
      ns: string[];
      ttl: number[];
    };

    const dnsDataPerSubdomain: Record<string, DnsData> = {};
    const fetchPromises = subdomains.map(async (sub) => {
      const res: DnsData = {
        a: [],
        aaaa: [],
        cname: null,
        txt: [],
        mx: [],
        ns: [],
        ttl: [],
      };
      try {
        const [aRecords, aaaaRecords, cnameRecords, txtRecords, mxRecords, nsRecords] = await Promise.all([
          fetchDnsRecords(sub, "A", signal),
          fetchDnsRecords(sub, "AAAA", signal),
          fetchDnsRecords(sub, "CNAME", signal),
          fetchDnsRecords(sub, "TXT", signal),
          fetchDnsRecords(sub, "MX", signal),
          fetchDnsRecords(sub, "NS", signal),
        ]);

        res.a.push(...aRecords.map((r) => r.data));
        res.aaaa.push(...aaaaRecords.map((r) => r.data));
        if (cnameRecords.length > 0) res.cname = cnameRecords[0].data;
        res.txt.push(...txtRecords.map((r) => r.data));
        res.mx.push(...mxRecords.map((r) => r.data));
        res.ns.push(...nsRecords.map((r) => r.data));

        // Collect TTLs from these records
        res.ttl.push(...aRecords.map((r) => r.TTL));
        res.ttl.push(...aaaaRecords.map((r) => r.TTL));
        res.ttl.push(...cnameRecords.map((r) => r.TTL));
        res.ttl.push(...txtRecords.map((r) => r.TTL));
        res.ttl.push(...mxRecords.map((r) => r.TTL));
        res.ttl.push(...nsRecords.map((r) => r.TTL));
      } catch {
        // Ignore errors per subdomain
      }
      dnsDataPerSubdomain[sub] = res;
    });

    await Promise.all(fetchPromises);

    // Step 3: Analyze TXT record diversity
    const allTxtTokensArrays: string[][] = [];
    for (const sub of subdomains) {
      const txtRecords = dnsDataPerSubdomain[sub]?.txt || [];
      // Parse each TXT record string into tokens and join
      const tokensJoined: string[] = [];
      txtRecords.forEach((txt) => {
        const parts = parseTxtRecordData(txt);
        tokensJoined.push(...parts);
      });
      // Deduplicate tokens
      const uniqueTokens = Array.from(new Set(tokensJoined));
      allTxtTokensArrays.push(uniqueTokens);
    }
    // Calculate diversity
    const txtDiversity = calculateTxtDiversity(allTxtTokensArrays); // 0-1
    const txtEntropyScore = Math.round(txtDiversity * 100);

    // Step 4: Analyze CNAME consistency
    const cnameTargets: string[] = [];
    for (const sub of subdomains) {
      const cnameTarget = dnsDataPerSubdomain[sub]?.cname;
      if (cnameTarget) cnameTargets.push(cnameTarget.toLowerCase());
    }
    const cnameConsistencyScore = calculateCnameConsistency(cnameTargets);
    const cnameConsistencyGrade = letterGrade(cnameConsistencyScore);

    // Step 5: Analyze TTL stability (variance across subdomains)
    const allTTLs: number[] = [];
    for (const sub of subdomains) {
      const ttlValues = dnsDataPerSubdomain[sub]?.ttl || [];
      if (ttlValues.length > 0) {
        const medianTTL = ttlValues.sort((a, b) => a - b)[Math.floor(ttlValues.length / 2)];
        allTTLs.push(medianTTL);
      }
    }
    const ttlStabilityScore = ttlStability(allTTLs);

    // Step 6: Anomaly detections (simplified rules)
    const anomalies: string[] = [];

    // e.g. Detect subdomains lacking SPF TXT records (containing "v=spf1")
    const missingSpfSubs: string[] = [];
    for (const sub of subdomains) {
      const txts = dnsDataPerSubdomain[sub]?.txt || [];
      const hasSpf = txts.some((txt) => txt.toLowerCase().includes("v=spf1"));
      if (!hasSpf) missingSpfSubs.push(sub);
    }
    if (missingSpfSubs.length > 0) {
      anomalies.push(`${missingSpfSubs.length} subdomains have missing SPF TXT record.`);
    }

    // Detect inconsistent CNAME patterns
    if (cnameConsistencyGrade === "D" || cnameConsistencyGrade === "F") {
      anomalies.push("Multiple inconsistent CNAME targets detected across subdomains.");
    }

    // Step 7: Calculate overall grade as weighted average
    // Weights: txtEntropy 30%, cnameConsistency 35%, ttlStability 35%
    let gradeScore = Math.round(
      (txtEntropyScore * 0.3) +
      (cnameConsistencyScore * 0.35) +
      (ttlStabilityScore * 0.35)
    );
    if (gradeScore > 100) gradeScore = 100;
    if (gradeScore < 0) gradeScore = 0;

    // Step 8: Generate explanation
    const explanation =
      `The analysis considered DNS A, AAAA, CNAME, TXT, MX, and NS records across ${subdomains.length} subdomains. ` +
      `TXT record diversity score of ${txtEntropyScore} indicates ${
        txtEntropyScore > 70 ? "good uniformity" : "significant variation"
      } in TXT records. ` +
      `CNAME consistency grade is ${cnameConsistencyGrade}, reflecting the degree of uniformity in CNAME targets. ` +
      `TTL stability score of ${ttlStabilityScore} suggests the freshness and uniformity of DNS TTL settings across subdomains. ` +
      `Detected anomalies include: ${anomalies.join(", ") || "none"}.
    `;

    // Step 9: Generate recommendations
    const recommendations: Recommendation[] = [];
    if (txtEntropyScore > 60) {
      recommendations.push({
        issue: "High TXT record diversity",
        severity: "medium",
        suggestion: "Standardize TXT records, especially SPF, DKIM, and DMARC, across subdomains to avoid mail delivery issues.",
      });
    } else {
      recommendations.push({
        issue: "Low TXT record diversity",
        severity: "low",
        suggestion: "Maintain current TXT record uniformity for predictable DNS behavior.",
      });
    }

    if (cnameConsistencyGrade === "F" || cnameConsistencyGrade === "D") {
      recommendations.push({
        issue: "Inconsistent CNAME target records",
        severity: "high",
        suggestion: "Align CNAME targets to a consistent hostname where appropriate to avoid resolution anomalies.",
      });
    }

    if (ttlStabilityScore < 50) {
      recommendations.push({
        issue: "Unstable TTL values across subdomains",
        severity: "medium",
        suggestion: "Consider unifying TTL values for DNS records to improve caching predictability.",
      });
    } else {
      recommendations.push({
        issue: "Stable TTL configuration",
        severity: "low",
        suggestion: "Maintain consistent TTL settings for optimal DNS caching behavior.",
      });
    }

    if (missingSpfSubs.length > 0) {
      recommendations.push({
        issue: "Missing SPF records in some subdomains",
        severity: "high",
        suggestion: "Add SPF TXT records to all subdomains that send mail to improve email security and deliverability.",
      });
    }

    return {
      domain,
      totalSubdomainsAnalyzed: subdomains.length,
      uniqueDnsRecords: Object.values(dnsDataPerSubdomain).reduce(
        (acc, val) => {
          acc += val.a.length + val.aaaa.length + (val.cname ? 1 : 0) + val.txt.length + val.mx.length + val.ns.length;
          return acc;
        },
        0
      ),
      txtEntropyScore,
      cnameConsistencyGrade,
      ttlStabilityScore,
      anomalyDetections: anomalies,
      grade: gradeScore,
      explanation,
      recommendations,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Failed full analysis: ${msg}` };
  }
}

// Preview analyzer returns basic sample and limited metrics
export async function analyzeSubdomainPreview(domain: string): Promise<SubdomainConfigEntropyPreviewResult | { error: string }> {
  try {
    const signal = AbortSignal.timeout(20000);
    // Try to fetch up to 10 subdomains
    const sampleSubdomains = await fetchSubdomains(domain, 10, signal);
    if (sampleSubdomains.length === 0) {
      return {
        domain,
        subdomainsScanned: 0,
        distinctDnsRecords: 0,
        txtRecordsDiversity: 0,
        cNameConsistencyScore: 0,
        explanation: "No detectable common subdomains found during preview analysis.",
        grade: 0,
        recommendations: [
          {
            issue: "No detectable subdomains",
            severity: "high",
            suggestion: "Verify domain DNS configuration; preview analysis limited by no detectable subdomains.",
          },
        ],
      };
    }

    const cnameTargets: string[] = [];
    const txtRecords: string[][] = [];
    const ttlValues: number[] = [];

    const signalPerFetch = AbortSignal.timeout(10000);

    const fetchPromises = sampleSubdomains.map(async (sub) => {
      try {
        const [cname, txt, a] = await Promise.all([
          fetchDnsRecords(sub, "CNAME", signalPerFetch),
          fetchDnsRecords(sub, "TXT", signalPerFetch),
          fetchDnsRecords(sub, "A", signalPerFetch),
        ]);
        if (cname.length > 0) cnameTargets.push(cname[0].data.toLowerCase());

        const txtTokens: string[] = [];
        for (const rec of txt) {
          txtTokens.push(...parseTxtRecordData(rec.data));
        }
        if (txtTokens.length > 0) txtRecords.push(Array.from(new Set(txtTokens)));

        const ttlsSub = [...cname, ...txt, ...a].map((r) => r.TTL);
        if (ttlsSub.length > 0) {
          // median TTL
          const mid = Math.floor(ttlsSub.length / 2);
          const sorted = ttlsSub.sort((a, b) => a - b);
          ttlValues.push(sorted[mid]);
        }
      } catch {
        // ignore
      }
    });

    await Promise.all(fetchPromises);

    const distinctDnsRecords = sampleSubdomains.length;
    const txtRecordsDiversity = calculateTxtDiversity(txtRecords); // fraction 0-1
    const cNameConsistencyScore = calculateCnameConsistency(cnameTargets);

    const grade = Math.round((txtRecordsDiversity * 100) * 0.4 + cNameConsistencyScore * 0.6);

    const explanation = `Preview analysis on ${sampleSubdomains.length} common subdomains of ${domain} with basic DNS record diversity and CNAME consistency metrics.`;

    const recommendations: Recommendation[] = [];
    if (txtRecordsDiversity > 0.6) {
      recommendations.push({
        issue: "High TXT record diversity",
        severity: "medium",
        suggestion: "Consider harmonizing TXT records (e.g. SPF, DKIM) for consistent mail and security behavior.",
      });
    }
    if (cNameConsistencyScore < 50) {
      recommendations.push({
        issue: "Low CNAME consistency",
        severity: "medium",
        suggestion: "Refine CNAME usage across subdomains to stabilize DNS resolution.",
      });
    }

    return {
      domain,
      subdomainsScanned: sampleSubdomains.length,
      distinctDnsRecords,
      txtRecordsDiversity: parseFloat(txtRecordsDiversity.toFixed(3)),
      cNameConsistencyScore,
      explanation,
      grade: Math.min(grade, 100),
      recommendations,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Failed preview analysis: ${msg}` };
  }
}
