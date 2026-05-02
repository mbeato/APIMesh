import { safeFetch } from "../../shared/ssrf";

// -----------------------------
// Types
// -----------------------------

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface DnsRecordAnalysis {
  aRecords: string[];
  nsRecords: string[];
  dmarc: {
    present: boolean;
    policy?: "none" | "quarantine" | "reject";
    score: number; // 0-100
    details: string;
  };
  dnssec: {
    enabled: boolean;
    score: number; // 0-100
    details: string;
  };
}

export interface SslCertificateAnalysis {
  valid: boolean;
  issuer: string;
  validFrom: string | null;
  validTo: string | null;
  signatureAlgorithm: string | null;
  strengthScore: number; // 0-100
  recommendations: string[];
  details: string;
}

export interface WhoisAnalysis {
  registered: boolean;
  registrar: string | null;
  creationDate: string | null;
  expiryDate: string | null;
  status: string[];
  score: number; // 0-100
  details: string;
}

export interface ReportResult {
  domain: string;
  dnsRecords: DnsRecordAnalysis;
  sslCertificate: SslCertificateAnalysis | null;
  whois: WhoisAnalysis | null;
  overallScore: number; // 0-100
  grade: string; // A, B, C, D, F
  recommendations: Recommendation[];
  explanation: string;
}

export interface PreviewResult {
  domain: string;
  dmarc: {
    present: boolean;
    policy?: "none" | "quarantine" | "reject";
    score: number;
    details: string;
  };
  dnssec: {
    enabled: boolean;
    score: number;
    details: string;
  };
  score: number; // 0-100
  grade: string; // A-F
  recommendations: Recommendation[];
  explanation: string;
}

// -----------------------------
// Utilities
// -----------------------------

function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

// Clamp score to 0-100
function clampScore(score: number): number {
  if (score < 0) return 0;
  if (score > 100) return 100;
  return score;
}

// Simple deep merge helper
function arrayUnique<T>(arr: T[]): T[] {
  return [...new Set(arr)];
}

// -----------------------------
// DNS Analysis
// -----------------------------

async function fetchDnsRecords(domain: string): Promise<DnsRecordAnalysis> {
  const signal = AbortSignal.timeout(10000);

  // Fetch A records
  let aRecords: string[] = [];
  try {
    const aRes = await safeFetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`, { signal });
    if (aRes.ok) {
      const aJson = await aRes.json();
      if (aJson.Answer && Array.isArray(aJson.Answer)) {
        aRecords = aJson.Answer.filter((ans: any) => ans.type === 1).map((ans: any) => ans.data);
      }
    }
  } catch {
    aRecords = [];
  }

  // Fetch NS records
  let nsRecords: string[] = [];
  try {
    const nsRes = await safeFetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=NS`, { signal });
    if (nsRes.ok) {
      const nsJson = await nsRes.json();
      if (nsJson.Answer && Array.isArray(nsJson.Answer)) {
        nsRecords = nsJson.Answer.filter((ans: any) => ans.type === 2).map((ans: any) => ans.data);
      }
    }
  } catch {
    nsRecords = [];
  }

  // Fetch DMARC record (TXT _dmarc.domain)
  let dmarcPresent = false;
  let dmarcPolicy: "none" | "quarantine" | "reject" | undefined;
  let dmarcDetails = "DMARC record not found.";
  let dmarcScore = 0;
  try {
    const dmarcDomain = `_dmarc.${domain}`;
    const dmarcRes = await safeFetch(`https://dns.google/resolve?name=${encodeURIComponent(dmarcDomain)}&type=TXT`, { signal });
    if (dmarcRes.ok) {
      const dmarcJson = await dmarcRes.json();
      if (dmarcJson.Answer && Array.isArray(dmarcJson.Answer)) {
        const txtRecords = dmarcJson.Answer.filter((a: any) => a.type === 16).map((a: any) => a.data.replace(/"/g, ""));
        const dmarcTxt = txtRecords.join("");
        if (dmarcTxt.toLowerCase().startsWith("v=dmarc1")) {
          dmarcPresent = true;
          const policyMatch = dmarcTxt.toLowerCase().match(/p=(none|quarantine|reject)/);
          dmarcPolicy = policyMatch ? (policyMatch[1] as "none" | "quarantine" | "reject") : "none";
          dmarcDetails = `DMARC policy is set to '${dmarcPolicy}'.`;
          if (dmarcPolicy === "reject") dmarcScore = 100;
          else if (dmarcPolicy === "quarantine") dmarcScore = 75;
          else dmarcScore = 50;
        }
      }
    }
  } catch {
    // ignore
  }

  if (!dmarcPresent) {
    dmarcScore = 20;
    dmarcDetails = "DMARC record not found.";
  }

  // DNSSEC check via CDS record (type 59) or DNSKEY (48)
  // We'll check DS record type 43 as indicator
  let dnssecEnabled = false;
  let dnssecDetails = "DNSSEC status could not be verified.";
  let dnssecScore = 0;
  try {
    const dsRes = await safeFetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=DS`, { signal });
    if (dsRes.ok) {
      const dsJson = await dsRes.json();
      if (dsJson.Answer && Array.isArray(dsJson.Answer) && dsJson.Answer.length > 0) {
        dnssecEnabled = true;
        dnssecDetails = "DNSSEC is enabled and DS record is present.";
        dnssecScore = 90;
      } else {
        dnssecEnabled = false;
        dnssecDetails = "No DS record found; DNSSEC not enabled.";
        dnssecScore = 20;
      }
    }
  } catch {
    dnssecEnabled = false;
    dnssecDetails = "DNSSEC lookup failed.";
    dnssecScore = 0;
  }

  return {
    aRecords: arrayUnique(aRecords),
    nsRecords: arrayUnique(nsRecords),
    dmarc: {
      present: dmarcPresent,
      policy: dmarcPolicy,
      score: clampScore(dmarcScore),
      details: dmarcDetails
    },
    dnssec: {
      enabled: dnssecEnabled,
      score: clampScore(dnssecScore),
      details: dnssecDetails
    }
  };
}

// -----------------------------
// SSL Certificate Analysis
// -----------------------------

interface ParsedCertificate {
  validFrom: Date;
  validTo: Date;
  issuer: string;
  signatureAlgorithm: string;
}

async function fetchSslCertificate(domain: string): Promise<SslCertificateAnalysis | null> {
  const signal = AbortSignal.timeout(10000);
  // We'll use crt.sh JSON data for cert info
  const crtShUrl = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;

  try {
    const res = await safeFetch(crtShUrl, { signal });
    if (!res.ok) {
      return {
        valid: false,
        issuer: "",
        validFrom: null,
        validTo: null,
        signatureAlgorithm: null,
        strengthScore: 0,
        recommendations: [
          `crt.sh responded with HTTP status ${res.status}`
        ],
        details: `Failed to retrieve certificate information.`
      };
    }

    const text = await res.text();
    if (!text || text.trim() === "[]") {
      return {
        valid: false,
        issuer: "",
        validFrom: null,
        validTo: null,
        signatureAlgorithm: null,
        strengthScore: 0,
        recommendations: ["No certificate data found in crt.sh."],
        details: "No certificates found in public database." +
          "This may indicate no HTTPS or very new cert."
      };
    }

    const certs = JSON.parse(text);
    if (!Array.isArray(certs) || certs.length === 0) {
      return {
        valid: false,
        issuer: "",
        validFrom: null,
        validTo: null,
        signatureAlgorithm: null,
        strengthScore: 0,
        recommendations: ["No certificate data found in crt.sh."],
        details: "No certificates found or parse error."
      };
    }

    // Use the certificate with the latest valid_to date
    let latestCert = certs[0];
    for (const cert of certs) {
      if (new Date(cert.not_after) > new Date(latestCert.not_after)) {
        latestCert = cert;
      }
    }

    const now = new Date();
    const validFrom = new Date(latestCert.not_before);
    const validTo = new Date(latestCert.not_after);
    const issuer = latestCert.issuer_name || "Unknown";
    const signatureAlgorithm = (latestCert.sig_alg || latestCert.signature_algorithm_name || null)?.toString() || null;

    const valid = now >= validFrom && now <= validTo;

    let strengthScore = 70; // base

    // Adjust score by expiry
    const expireDays = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    if (expireDays > 60) strengthScore += 20;
    if (expireDays <= 30) strengthScore -= 30;

    // Adjust score based on signature algorithm strength
    const algo = signatureAlgorithm ? signatureAlgorithm.toLowerCase() : "";
    if (algo.includes("md5") || algo.includes("sha1")) {
      strengthScore -= 50;
    } else {
      strengthScore += 10;
    }

    strengthScore = clampScore(strengthScore);

    const recommendations: string[] = [];
    if (!valid) recommendations.push("SSL certificate is expired or not valid; renew immediately.");
    if (expireDays > 0 && expireDays <= 15) recommendations.push("SSL certificate will expire soon; renew promptly.");
    if (algo.includes("md5") || algo.includes("sha1")) recommendations.push("Use a stronger signature algorithm such as SHA-256 or better.");

    return {
      valid,
      issuer,
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      signatureAlgorithm,
      strengthScore,
      recommendations,
      details: `SSL certificate issued by ${issuer}, valid from ${validFrom.toISOString()} to ${validTo.toISOString()}, using ${signatureAlgorithm || "unknown"} algorithm.`
    };
  } catch (e) {
    return null;
  }
}

// -----------------------------
// WHOIS Analysis
// -----------------------------

async function fetchWhois(domain: string): Promise<WhoisAnalysis | null> {
  const signal = AbortSignal.timeout(10000);
  try {
    // Use public JSON WHOIS API: https://www.whoisxmlapi.com/services/whois-api/
    // But no API key allowed, so we use https://jsonwhoisapi.com/ free endpoints? No keys allowed...
    // Instead, fallback to https://rdap.verisign.com/com/v1/domain/{domain} which returns JSON for .com domains
    if (!domain.endsWith(".com") && !domain.endsWith(".net") && !domain.endsWith(".org")) {
      // Unsupported TLD
      return {
        registered: false,
        registrar: null,
        creationDate: null,
        expiryDate: null,
        status: [],
        score: 50,
        details: "WHOIS lookup only supported on .com/net/org in this API."
      };
    }

    const url = `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(domain)}`;
    const res = await safeFetch(url, { signal });
    if (!res.ok) {
      return {
        registered: false,
        registrar: null,
        creationDate: null,
        expiryDate: null,
        status: [],
        score: 50,
        details: `WHOIS data not found or domain not registered. Status code ${res.status}`
      };
    }

    const data = await res.json();

    if (data.errorCode && data.errorCode === 404) {
      return {
        registered: false,
        registrar: null,
        creationDate: null,
        expiryDate: null,
        status: [],
        score: 30,
        details: "Domain not registered."
      };
    }

    const registered = true;
    const registrar = data.registrar ? (data.registrar.name || null) : null;
    const creationDate = data.events?.find((e: any) => e.eventAction === "registration")?.eventDate || null;
    const expiryDate = data.events?.find((e: any) => e.eventAction === "expiration")?.eventDate || null;
    const status: string[] = data.status || [];

    // Scoring
    let score = 90;
    if (!registered) score = 10;
    // Penalty for missing registrar or expired
    if (!registrar) score -= 30;
    if (expiryDate) {
      const expDateObj = new Date(expiryDate);
      const now = new Date();
      const diffDays = Math.floor((expDateObj.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
      if (diffDays < 30) {
        score -= 40;
      } else if (diffDays < 90) {
        score -= 10;
      }
    }

    score = clampScore(score);

    const details = `Domain registered: ${registered}, registrar: ${registrar || "unknown"}, creation date: ${creationDate || "unknown"}, expiry date: ${expiryDate || "unknown"}, status: ${status.join(", ")}`;

    return {
      registered,
      registrar,
      creationDate,
      expiryDate,
      status,
      score,
      details,
    };
  } catch (e) {
    return null;
  }
}

// -----------------------------
// Grading and aggregation
// -----------------------------

function aggregateScores(
  dns: DnsRecordAnalysis,
  ssl: SslCertificateAnalysis | null,
  whois: WhoisAnalysis | null
): { overallScore: number; grade: string } {
  // Weighted scores
  // Weights: DNS (DMARC+dnssec) 40%, SSL 40%, WHOIS 20%

  const dmarcWeight = 25;
  const dnssecWeight = 15;
  const sslWeight = 40;
  const whoisWeight = 20;

  const dmarcScore = dns.dmarc.score;
  const dnssecScore = dns.dnssec.score;
  const sslScore = ssl ? ssl.strengthScore : 0;
  const whoisScore = whois ? whois.score : 0;

  let totalScore =
    (dmarcScore * dmarcWeight + dnssecScore * dnssecWeight + sslScore * sslWeight + whoisScore * whoisWeight) / 100;

  totalScore = clampScore(Math.round(totalScore));

  const grade = scoreToGrade(totalScore);

  return { overallScore: totalScore, grade };
}

// -----------------------------
// Recommendations
// -----------------------------

function gatherRecommendations(
  dns: DnsRecordAnalysis,
  ssl: SslCertificateAnalysis | null,
  whois: WhoisAnalysis | null
): Recommendation[] {
  const recs: Recommendation[] = [];

  // DNS
  if (!dns.dmarc.present) {
    recs.push({
      issue: "DMARC missing",
      severity: 90,
      suggestion: "Publish a DMARC DNS TXT record with policy reject or quarantine to prevent email spoofing."
    });
  } else if (dns.dmarc.policy === "none") {
    recs.push({
      issue: "DMARC policy none",
      severity: 60,
      suggestion: "Change DMARC policy from none to quarantine or reject for better protection."
    });
  }

  if (!dns.dnssec.enabled) {
    recs.push({
      issue: "DNSSEC missing",
      severity: 80,
      suggestion: "Enable DNSSEC for this domain to protect DNS queries from tampering and spoofing."
    });
  }

  // SSL
  if (!ssl) {
    recs.push({
      issue: "SSL certificate info unavailable",
      severity: 100,
      suggestion: "Check if your website uses HTTPS and SSL certificate is properly configured."
    });
  } else {
    if (!ssl.valid) {
      recs.push({
        issue: "SSL certificate invalid or expired",
        severity: 100,
        suggestion: "Renew or fix your site's SSL certificate to ensure HTTPS security."
      });
    }
    if (ssl.recommendations && ssl.recommendations.length > 0) {
      for (const r of ssl.recommendations) {
        recs.push({ issue: "SSL recommendation", severity: 70, suggestion: r });
      }
    }
  }

  // WHOIS
  if (!whois) {
    recs.push({
      issue: "WHOIS info unavailable",
      severity: 50,
      suggestion: "Check domain registration details and ensure domain is properly registered."
    });
  } else {
    if (!whois.registered) {
      recs.push({
        issue: "Domain not registered",
        severity: 100,
        suggestion: "Register your domain to prevent fraud and impersonation."
      });
    }
    if (whois.expiryDate) {
      const expDate = new Date(whois.expiryDate);
      const now = new Date();
      const daysLeft = Math.ceil((expDate.getTime() - now.getTime()) / (1000 * 3600 * 24));
      if (daysLeft < 30) {
        recs.push({
          issue: "Domain expiry soon",
          severity: 80,
          suggestion: "Renew your domain registration to avoid expiration and downtime."
        });
      }
    }
  }

  if (recs.length === 0) {
    recs.push({
      issue: "No immediate security issues detected",
      severity: 0,
      suggestion: "Continue monitoring security settings and renew certificates/domains as needed."
    });
  }

  return recs;
}

// -----------------------------
// Main Public Functions
// -----------------------------

export async function generatePreviewReport(domain: string): Promise<PreviewResult> {
  // Only quick DMARC and DNSSEC checks

  const start = performance.now();
  const dns = await fetchDnsRecords(domain);
  const scoreRaw = ((dns.dmarc.score * 0.7) + (dns.dnssec.score * 0.3));
  const score = clampScore(Math.round(scoreRaw));
  const grade = scoreToGrade(score);

  const recommendations: Recommendation[] = [];

  if (!dns.dmarc.present) {
    recommendations.push({
      issue: "DMARC missing",
      severity: 90,
      suggestion: "Add a DMARC record to protect email domain from spoofing."
    });
  } else if (dns.dmarc.policy === "none") {
    recommendations.push({
      issue: "Weak DMARC policy",
      severity: 60,
      suggestion: "Change DMARC policy to 'quarantine' or 'reject' to better protect emails."
    });
  }

  if (!dns.dnssec.enabled) {
    recommendations.push({
      issue: "DNSSEC not enabled",
      severity: 80,
      suggestion: "Enable DNSSEC to protect against DNS-based attacks."
    });
  }

  const explanation = `Basic domain checks found DMARC ${dns.dmarc.present ? `present with policy ${dns.dmarc.policy}` : "missing"} and DNSSEC ${dns.dnssec.enabled ? "enabled" : "disabled"}.`;

  const duration_ms = Math.round(performance.now() - start);

  return {
    domain,
    dmarc: dns.dmarc,
    dnssec: dns.dnssec,
    score,
    grade,
    recommendations,
    explanation,
  };
}

export async function generateFullReport(domain: string): Promise<ReportResult> {
  // Parallel start
  const start = performance.now();

  try {
    const [dns, ssl, whois] = await Promise.all([
      fetchDnsRecords(domain),
      fetchSslCertificate(domain),
      fetchWhois(domain)
    ]);

    const { overallScore, grade } = aggregateScores(dns, ssl, whois);

    const recommendations = gatherRecommendations(dns, ssl, whois);

    const explanation = `Comprehensive report combining DNS records (A, NS, DMARC, DNSSEC), SSL certificate, and WHOIS data. Scored ${overallScore} with grade ${grade}.`;

    const duration_ms = Math.round(performance.now() - start);

    return {
      domain,
      dnsRecords: dns,
      sslCertificate: ssl,
      whois: whois,
      overallScore,
      grade,
      recommendations,
      explanation
    };
  } catch (e: unknown) {
    const errMsg = e instanceof Error ? e.message : String(e);
    throw new Error(`Failed to generate full report: ${errMsg}`);
  }
}
