import { safeFetch } from "../../shared/ssrf";

// ── Types ─────────────────────────────────────────
export interface ExposureRecommendation {
  issue: string;
  severity: number; // 1 = lowest, 5 = critical
  suggestion: string;
}

// Preview result (free endpoint)
export interface PreviewExposureResult {
  domain: string;
  subdomains: string[];
  exposureSummary: {
    sensitiveExposed: string[];
    deprecatedApis: string[];
    highRiskCount: number;
    score: number;
    grade: ExposureGrade;
  };
  explanation: string;
  recommendations: ExposureRecommendation[];
}

export interface ExposureAuditResult {
  domain: string;
  subdomains: string[];
  exposureReport: {
    highRisk: string[];
    deprecatedEndpoints: string[];
    sensitiveSubdomains: string[];
    scoring: {
      score: number;
      grade: ExposureGrade;
    };
    exposureBreakdown: {
      highRiskCount: number;
      deprecatedCount: number;
      sensitiveCount: number;
    };
  };
  explanation: string;
  recommendations: ExposureRecommendation[];
}

export type ExposureGrade = "A" | "B" | "C" | "D" | "F";

interface SubExposure {
  name: string;
  isSensitive: boolean;
  isDeprecated: boolean;
  isHighRisk: boolean;
  riskScore: number; // 0-15 per subdomain
  evidence: string[];
}

const MAX_PREVIEW_SUBS = 6;

// ── Helper: Domain validation ───────────────
const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
export function validateDomain(input: string): { valid: boolean; error?: string } {
  if (!input || typeof input !== "string") return { valid: false, error: "Missing domain" };
  const domain = input.trim().toLowerCase();
  if (domain.length > 253) return { valid: false, error: "Domain too long" };
  if (domain.startsWith("http:")) return { valid: false, error: "Enter bare domain (no http(s)://)" };
  if (!DOMAIN_REGEX.test(domain)) return { valid: false, error: "Invalid domain format" };
  return { valid: true };
}

// ── Enumeration: DNS + CT ──────────────────
async function fetchDnsSubdomains(domain: string): Promise<string[]> {
  // Use DNSDumpster (no API key), may block bots; fallback to HackerTarget
  // We'll use HackerTarget.org (open API)
  const signal = AbortSignal.timeout(10000);
  const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
  try {
    const res = await fetch(url, { signal });
    if (!res.ok) return [];
    const body = await res.text();
    // Format: subdomain,ip per line
    const subs = body.split("\n").filter(Boolean).map(line => line.split(",")[0].trim());
    return subs.filter(s => s.endsWith(`.${domain}`));
  } catch (_) {
    return [];
  }
}

async function fetchCtLSubdomains(domain: string): Promise<string[]> {
  // Use public CT API (crt.sh)
  const signal = AbortSignal.timeout(10000);
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  try {
    const res = await fetch(url, { signal });
    if (!res.ok) return [];
    const jsonText = await res.text();
    if (!jsonText || jsonText[0] !== '[') return [];
    const objs = JSON.parse(jsonText);
    if (!Array.isArray(objs)) return [];
    const allNames = new Set<string>();
    for (const cert of objs.slice(0, 400)) {
      // Use name_value, which can be '\n'-separated
      if (cert && typeof cert.name_value === "string") {
        for (const n of cert.name_value.split(/\n|,|;/g)) {
          const t = n.trim();
          if (t.endsWith(`.${domain}`) && !t.startsWith("*")) allNames.add(t);
        }
      }
    }
    return Array.from(allNames);
  } catch (_) {
    return [];
  }
}

// ── Subdomain Risk Heuristics ───────────────
const SENSITIVE_PATTERNS = [
  /^admin\./, /^dev\./, /^test\./, /^beta\./, /^stage\./, /^staging\./,
  /^internal\./, /^git\./, /^jira\./, /^vpn\./, /^db\./, /^backup\./,
  /^sys\./, /^qa\./, /^api\./, /^dashboard\./, /^sso\./, /^auth\./
];

const DEPRECATED_PATTERNS = [
  /^old\./, /^legacy\./, /^mail[0-9]*\./, /^webmail\./, /^owa\./, /exchange\./, /^pop3\./, /^imap\./
];

const HIGH_RISK_PATTERNS = [
  /^admin\./, /^root\./, /^panel\./, /^host\./, /^login\./, /^webdav\./, /^smb\./, /^upload\./, /^remote\./
];

function scoreSubdomain(name: string): SubExposure {
  let sens = false, depr = false, risk = false, riskScore = 0, evidence: string[] = [];
  for (const p of SENSITIVE_PATTERNS) if (p.test(name)) { sens = true; riskScore += 3; evidence.push("Sensitive pattern: " + p.source); }
  for (const p of DEPRECATED_PATTERNS) if (p.test(name)) { depr = true; riskScore += 2; evidence.push("Deprecated pattern: " + p.source); }
  for (const p of HIGH_RISK_PATTERNS) if (p.test(name)) { risk = true; riskScore += 4; evidence.push("High-risk pattern: " + p.source); }
  // Extraname risk: long, verbose, or number suffixes (
  if (/\d{3,}\./.test(name)) { riskScore += 1; evidence.push("Looks like numbered/staging subdomain"); }
  if (/^(dev|test|stage)-/i.test(name)) { sens = true; riskScore += 2; evidence.push("Env prefix"); }
  return { name, isSensitive: sens, isDeprecated: depr, isHighRisk: risk, riskScore, evidence };
}

function computeExposureGrade(score: number): ExposureGrade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 55) return "C";
  if (score >= 30) return "D";
  return "F";
}

function generateRecommendations(exposures: SubExposure[]): ExposureRecommendation[] {
  const recs: ExposureRecommendation[] = [];
  for (const se of exposures) {
    if (se.isHighRisk) {
      recs.push({
        issue: `High-risk public subdomain found: ${se.name}`,
        severity: 5,
        suggestion: `Restrict network access to ${se.name} or remove from public DNS if not needed.`
      });
    } else if (se.isSensitive) {
      recs.push({
        issue: `Sensitive subdomain: ${se.name}`,
        severity: 3,
        suggestion: `Consider moving ${se.name} internal-only or audit its authentication/exposure.`
      });
    } else if (se.isDeprecated) {
      recs.push({
        issue: `Deprecated/legacy subdomain: ${se.name}`,
        severity: 2,
        suggestion: `Plan to move or decommission ${se.name} if unused.`
      });
    }
    // If more than one flag, choose highest
  }
  return recs.slice(0, 5); // limit
}

// ── Business Logic (PAID: full audit) ───────
export async function enumerateAndScoreSubdomains(inputDomain: string): Promise<ExposureAuditResult | { error: string; detail?: string }> {
  const valid = validateDomain(inputDomain);
  if (!valid.valid) return { error: valid.error || "Invalid domain" };

  const baseDomain = inputDomain.trim().toLowerCase();
  try {
    // Multi-source
    const [ct, dns] = await Promise.all([
      fetchCtLSubdomains(baseDomain),
      fetchDnsSubdomains(baseDomain)
    ]);
    // merge/unique
    const foundSet = new Set<string>();
    for (const s of ct) foundSet.add(s);
    for (const s of dns) foundSet.add(s);
    let subs = Array.from(foundSet);
    subs = subs.filter(s => s !== baseDomain && s.endsWith(`.${baseDomain}`));
    if (subs.length === 0) {
      return { error: `No subdomains found for domain` };
    }
    // Process exposures
    const exposures: SubExposure[] = subs.map(scoreSubdomain);
    // Breakdown
    const highRisk = exposures.filter(s => s.isHighRisk).map(s => s.name);
    const deprecatedEndpoints = exposures.filter(s => s.isDeprecated).map(s => s.name);
    const sensitive = exposures.filter(s => s.isSensitive).map(s => s.name);
    // Score calc: lower is worse
    let rawScore = Math.max(100 - 15 * highRisk.length - 6 * deprecatedEndpoints.length - 5 * sensitive.length, 0);
    if (subs.length > 30) rawScore -= Math.min(subs.length - 30, 30); // large attack surface penalty
    if (subs.length > 60) rawScore = Math.max(rawScore - 10, 0);
    const grade = computeExposureGrade(rawScore);
    // Explanation
    const explanation =
      `Found ${subs.length} unique subdomains from DNS and certificate transparency sources. ` +
      `${highRisk.length} high-risk, ${deprecatedEndpoints.length} deprecated, ${sensitive.length} sensitive targets.`;
    // Recommendations
    const recommendations = generateRecommendations(exposures);

    return {
      domain: baseDomain,
      subdomains: subs,
      exposureReport: {
        highRisk,
        deprecatedEndpoints,
        sensitiveSubdomains: sensitive,
        scoring: { score: rawScore, grade },
        exposureBreakdown: {
          highRiskCount: highRisk.length,
          deprecatedCount: deprecatedEndpoints.length,
          sensitiveCount: sensitive.length
        }
      },
      explanation,
      recommendations
    };
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    if (/timeout|Abort/.test(msg)) return { error: "Enumeration timed out", detail: msg };
    return { error: "Failed to enumerate subdomains", detail: msg };
  }
}

// ── preview endpoint (free, safe, truncated) ──
export async function previewEnumerateAndScore(inputDomain: string): Promise<PreviewExposureResult | { error: string; detail?: string }> {
  const valid = validateDomain(inputDomain);
  if (!valid.valid) return { error: valid.error || "Invalid domain" };
  const baseDomain = inputDomain.trim().toLowerCase();
  try {
    // Only CT logs for preview, 10 or fewer
    const ct = await fetchCtLSubdomains(baseDomain);
    let previewSubs = ct
      .filter(s => s !== baseDomain && s.endsWith(`.${baseDomain}`))
      .slice(0, MAX_PREVIEW_SUBS);
    if (previewSubs.length === 0) return { error: `No subdomains found (preview)` };
    const exposures = previewSubs.map(scoreSubdomain);
    // Summaries only:
    const sens = exposures.filter(e => e.isSensitive).map(e => e.name);
    const depr = exposures.filter(e => e.isDeprecated).map(e => e.name);
    const riskn = exposures.filter(e => e.isHighRisk).length;
    let score = Math.max(100 - 18 * riskn - 5 * depr.length - 3 * sens.length, 0);
    const grade = computeExposureGrade(score);
    // Compose
    return {
      domain: baseDomain,
      subdomains: previewSubs,
      exposureSummary: {
        sensitiveExposed: sens,
        deprecatedApis: depr,
        highRiskCount: riskn,
        score,
        grade
      },
      explanation: `Preview limited to top ${previewSubs.length} subdomains. For full enumeration and actionable detail, use /check.`,
      recommendations: generateRecommendations(exposures)
    };
  } catch (e: any) {
    const msg = e instanceof Error ? e.message : String(e);
    if (/timeout|Abort/.test(msg)) return { error: "Enumeration timed out", detail: msg };
    return { error: "Failed to enumerate (preview)", detail: msg };
  }
}
