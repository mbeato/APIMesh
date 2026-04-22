import { safeFetch, validateExternalUrl } from "../../shared/ssrf";

/** Response Types */
export interface HeatmapPreviewResult {
  domain: string;
  foundSubdomains: string[];
  total: number;
  note: string;
}

export interface SubdomainRisk {
  name: string;
  exposureLevel: number; // 0-100
  grade: "A" | "B" | "C" | "D" | "F";
  issues: string[];
  recommendations: {
    issue: string;
    severity: "low" | "medium" | "high";
    suggestion: string;
  }[];
}

export interface HeatmapAuditResult {
  domain: string;
  totalSubdomains: number;
  riskScore: number; // 0-100
  letterGrade: "A" | "B" | "C" | "D" | "F";
  subdomains: SubdomainRisk[];
  explanation: string;
  recommendations: {
    issue: string;
    severity: "low" | "medium" | "high";
    suggestion: string;
  }[];
}

const MAX_SUBDOMAINS = 50;
const DEFAULT_WORDLIST = ["www","mail","dev","test","api","app","stage","staging","beta","old","internal","admin","webmail","web","portal","vpn","ftp","static","media","docs","help","blog","shop","store","assets","gateway","db","db1","db2","secure","cloud","proxy","mx","pop","imap","smtp","gw","panel","dashboard","console","login","sso","monitor","status","cdn","backup","bkp","ns1","ns2","dns","billing","pay","payments"];

function sanitizeDomain(domain: string): string | null {
  // Allow only valid DNS patterns
  const regex = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z]{2,}$/;
  if (!domain || domain.length > 255) return null;
  if (!regex.test(domain)) return null;
  return domain.toLowerCase();
}

// --- Helper: parallel fetch with timeout for DNS/CT --
export async function previewEnumeration(domain: string): Promise<HeatmapPreviewResult> {
  const clean = sanitizeDomain(domain);
  if (!clean) throw new Error("Invalid domain name");
  // Use CRT.sh (certificate transparency logs - public), and a DNS enumeration API
  const [crtSubdomains, simpleDictionary] = await Promise.all([
    fetchCrtShSet(clean, 15_000),
    bruteForceSubdomains(clean, DEFAULT_WORDLIST.slice(0, 10), 15_000),
  ]);
  // Remove invalid and dedupe
  const set = new Set([...crtSubdomains, ...simpleDictionary]);
  const finalList = Array.from(set).filter((s) => /^[a-z0-9-]+$/i.test(s)).slice(0, 20);
  return {
    domain: clean,
    foundSubdomains: finalList,
    total: finalList.length,
    note: "Preview: lightweight dictionary-based and CRT.sh certificate extraction only. Pay to receive deep results, risk scoring, and recommendations.",
  };
}

export async function enumerateAndAnalyze(domain: string): Promise<HeatmapAuditResult> {
  const clean = sanitizeDomain(domain);
  if (!clean) throw new Error("Invalid domain name");
  // Enumerate from several open sources + dictionary attack
  const [crtSh, threatCrowd, dnsBuff, dnsBrute] = await Promise.all([
    fetchCrtShSet(clean, 10_000), // Certificate transparency, public
    fetchThreatCrowdSet(clean, 10_000), // Threat intelligence subdomains list
    fetchDnsBufferoverSet(clean, 10_000), // Bufferover.run passive DNS
    bruteForceSubdomains(clean, DEFAULT_WORDLIST, 15_000), // Local brute-force via DNS
  ]);
  // Merge and clean
  const allSubs = mergeAndDedupe([crtSh, threatCrowd, dnsBuff, dnsBrute]);
  // Limit scope for DoS/abuse
  const subdomains = allSubs.slice(0, MAX_SUBDOMAINS);

  // For each subdomain, analyze exposure in parallel with concurrency throttle
  const risks: SubdomainRisk[] = await analyzeAllSubdomains(subdomains, clean);

  // Compute composite risk score and grading
  const { letter, numeric } = overallGradeAndScore(risks);
  const explanation = explainRisks(risks, subdomains.length, clean);

  // Flatten all recommendations
  const allRecs = risks.flatMap(sd => sd.recommendations.map(r => ({ ...r, issue: `[${sd.name}] ${r.issue}` })));

  return {
    domain: clean,
    totalSubdomains: subdomains.length,
    riskScore: numeric,
    letterGrade: letter,
    subdomains: risks,
    explanation,
    recommendations: allRecs,
  };
}

// ============ Data source helpers ============
async function fetchCrtShSet(domain: string, timeoutMs: number): Promise<string[]> {
  // https://crt.sh/?q=%25.YOURDOMAIN.com&output=json
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  try {
    const ctrl = AbortSignal.timeout(timeoutMs);
    const resp = await fetch(url, { signal: ctrl });
    if (!resp.ok) return [];
    const arr = await resp.json();
    if (!Array.isArray(arr)) return [];
    const set = new Set<string>();
    for (const crt of arr) {
      const nameVal = typeof crt === "object" && crt.name_value ? crt.name_value : null;
      if (!nameVal) continue;
      String(nameVal).split(/\n|,/g).forEach((val) => {
        let d = val.trim().toLowerCase();
        if (d.endsWith(`.${domain}`) && d !== domain) {
          const label = d.slice(0, d.length - domain.length - 1).toLowerCase();
          if (label && label.length <= 63) set.add(label);
        }
      });
    }
    return Array.from(set);
  } catch {
    return [];
  }
}

async function fetchThreatCrowdSet(domain: string, timeoutMs: number): Promise<string[]> {
  // https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=example.com
  try {
    const ctrl = AbortSignal.timeout(timeoutMs);
    const url = `https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${encodeURIComponent(domain)}`;
    const resp = await fetch(url, { signal: ctrl });
    if (!resp.ok) return [];
    const data = await resp.json();
    if (data && Array.isArray(data.subdomains)) {
      return data.subdomains.flatMap((fqdn: string) => {
        if (fqdn.endsWith(`.${domain}`) && fqdn.length > domain.length + 1) {
          return [fqdn.slice(0, fqdn.length - (domain.length + 1))];
        }
        return [];
      });
    }
    return [];
  } catch {
    return [];
  }
}

async function fetchDnsBufferoverSet(domain: string, timeoutMs: number): Promise<string[]> {
  try {
    const ctrl = AbortSignal.timeout(timeoutMs);
    const url = `https://dns.bufferover.run/dns?q=.${encodeURIComponent(domain)}`;
    const resp = await fetch(url, { signal: ctrl });
    if (!resp.ok) return [];
    const data = await resp.json();
    if (data && Array.isArray(data.FQDN)) {
      return data.FQDN.flatMap((fqdn: string) => {
        if (fqdn && fqdn.endsWith(`.${domain}`) && fqdn.length > domain.length + 1) {
          return [fqdn.slice(0, fqdn.length - (domain.length + 1)).toLowerCase()];
        }
        return [];
      });
    }
    return [];
  } catch {
    return [];
  }
}

async function bruteForceSubdomains(domain: string, wordlist: string[], timeoutMs: number): Promise<string[]> {
  // Attempt A record resolve via DNS over HTTPS (Google)
  const promises = wordlist.map(async (label) => {
    const ctrl = AbortSignal.timeout(timeoutMs);
    const fqdn = `${label}.${domain}`;
    try {
      const res = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(fqdn)}&type=A`,
        { signal: ctrl }
      );
      if (!res.ok) return null;
      const data = await res.json();
      if (data && (data.Answer || data.Answers)) {
        return label;
      }
      return null;
    } catch {
      return null;
    }
  });
  const resolved = await Promise.all(promises);
  return resolved.filter((s): s is string => !!s);
}

function mergeAndDedupe(listArrays: string[][]): string[] {
  const set = new Set<string>();
  for (const arr of listArrays) {
    for (const s of arr) {
      if (s && s.length > 0 && s.length <= 63) set.add(s.toLowerCase());
    }
  }
  return Array.from(set);
}

// ============ Subdomain Risk: probe HTTP headers, banner, SSL, error status ===========
async function analyzeAllSubdomains(labels: string[], domain: string): Promise<SubdomainRisk[]> {
  // Limit concurrency (max 5 at a time)
  const concurrency = 5;
  const queue: Promise<SubdomainRisk>[] = [];
  const results: SubdomainRisk[] = [];

  function next(i: number): Promise<void> {
    if (i >= labels.length) return Promise.resolve();
    const p = analyzeSubdomain(labels[i], domain)
      .then(risk => { results[i] = risk; })
      .catch(_ => { results[i] = emptyRisk(labels[i], domain); });
    queue.push(p);
    if (queue.length < concurrency) {
      return next(i + 1);
    }
    return Promise.race(queue).then(() => next(i + 1));
  }
  await next(0);
  await Promise.all(queue);
  // Remove undefineds (rare)
  return results.filter((r): r is SubdomainRisk => r !== undefined);
}

function emptyRisk(label: string, domain: string): SubdomainRisk {
  const name = `${label}.${domain}`;
  return {
    name,
    exposureLevel: 0,
    grade: "F",
    issues: ["Could not analyze due to network error."],
    recommendations: [],
  };
}

async function analyzeSubdomain(label: string, domain: string): Promise<SubdomainRisk> {
  const name = `${label}.${domain}`;
  const fqdn = name;
  let issues: string[] = [];
  let recommendations: SubdomainRisk["recommendations"] = [];
  let exposureLevel = 0;
  let grade: SubdomainRisk["grade"] = "F";

  // Compose basic set of probes
  // 1. HTTP(S) HEAD (prefer) with 10s timeout
  // 2. Banner via HTTP if possible
  // 3. SSL certificate existence
  const checks = await Promise.all([
    httpProbe(fqdn, 10000),
    httpsProbe(fqdn, 10000),
    sslProbe(fqdn, 10000),
  ]);
  const [http, https, sslData] = checks;

  // Analysis: status, headers, content, cert, response code
  if (http.status === "online" || https.status === "online") {
    exposureLevel += 30;
    if (http.status === "online") issues.push("Responds over http (non-TLS)");
    if (https.status === "online") exposureLevel += 10;
    if (http.httpCode && (http.httpCode < 200 || http.httpCode >= 400)) {
      issues.push(`HTTP error code ${http.httpCode}`);
      exposureLevel += 5;
    }
    if (https.httpCode && (https.httpCode < 200 || https.httpCode >= 400)) {
      issues.push(`HTTPS error code ${https.httpCode}`);
      exposureLevel += 5;
    }
    if (http.banner) {
      issues.push(`Exposes banner: ${shorten(http.banner)}`);
      exposureLevel += 10;
      if (/apache|nginx|iis|tomcat|caddy|express/i.test(http.banner)) {
        issues.push("Default web server banner exposed");
        recommendations.push({
          issue: "Web server banner exposed",
          severity: "medium",
          suggestion: "Disable or modify server header to prevent fingerprinting."
        });
        exposureLevel += 9;
      }
    }
    if (https.banner) {
      issues.push(`HTTPS banner: ${shorten(https.banner)}`);
    }
    // Simple leak: headers
    if (http.headers && http.headers["x-powered-by"]) {
      exposureLevel += 9;
      issues.push(`Powered by: ${shorten(http.headers["x-powered-by"] as string)}`);
      recommendations.push({
        issue: "X-Powered-By header exposes stack info",
        severity: "medium",
        suggestion: "Remove or obfuscate X-Powered-By header to prevent stack fingerprinting."
      });
    }
    if (https.headers && https.headers["x-powered-by"]) {
      exposureLevel += 3;
    }
    // Headers exposing dev/testing
    if (http.headers && http.headers["x-debug-token"]){
      exposureLevel += 10;
      issues.push("Debug mode header present");
      recommendations.push({
        issue: "Debug token header present",
        severity: "high",
        suggestion: "Disable debug mode on production endpoints."
      });
    }
    // Legacy, backups, staging (by label)
    if (/test|dev|stage|staging|old|beta|bkp|backup|internal/.test(label)) {
      exposureLevel += 15;
      issues.push(`Label '${label}' is indicative of legacy, test, or sensitive environment.`);
      recommendations.push({
        issue: "Sensitive subdomain exposed",
        severity: "high",
        suggestion: `Restrict or decommission '${label}.${domain}' if not critical; limit to VPN/firewalled use only.`
      });
    }
    // Open SMTP/MX test for 'mail', 'smtp'
    if ((/mail|smtp|pop|imap|mx/).test(label) && http.status !== "online" && https.status !== "online") {
      // If dead, recommend cleanup
      recommendations.push({
        issue: "Mail-related subdomain not responding",
        severity: "medium",
        suggestion: `Investigate if '${label}.${domain}' is deprecated and if so, remove its DNS entry.`
      });
    }
    // Index page default
    if (http.banner && /default|apache|nginx|iis|welcome|index|it works/i.test(http.banner)) {
      issues.push("Exposes default web server page.");
      exposureLevel += 8;
      recommendations.push({
        issue: "Shows default server page",
        severity: "medium",
        suggestion: "Deploy actual content or restrict from public access."
      });
    }
    grade = gradeFromScore(exposureLevel);
  } else {
    // Not online
    issues.push("Not reachable over HTTP nor HTTPS");
    exposureLevel = 15;
    grade = "C";
    recommendations.push({
      issue: "Inactive subdomain DNS is present",
      severity: "low",
      suggestion: `If '${label}.${domain}' is unused, remove DNS to prevent future takeover risks.`
    });
  }

  // SSL Data
  if (sslData.hasCert) {
    exposureLevel += 8;
    if (!sslData.isValid) {
      issues.push("SSL certificate expired or invalid.");
      recommendations.push({
        issue: "SSL cert invalid/expired",
        severity: "high",
        suggestion: "Issue or renew SSL certificate for this endpoint."
      });
      exposureLevel += 8;
    }
    if (/let's encrypt|dst root|sectigo|c=us/i.test(sslData.issuer)) {
      issues.push("Common/free CA used.");
    }
  }

  // Clamp exposure level
  if (exposureLevel > 100) exposureLevel = 100;
  if (exposureLevel < 0) exposureLevel = 0;
  return {
    name,
    exposureLevel,
    grade,
    issues,
    recommendations,
  };
}

function gradeFromScore(score: number): SubdomainRisk["grade"] {
  if (score < 25) return "A";
  if (score < 45) return "B";
  if (score < 65) return "C";
  if (score < 85) return "D";
  return "F";
}

function overallGradeAndScore(risks: SubdomainRisk[]): { letter: HeatmapAuditResult["letterGrade"], numeric: number } {
  if (!risks || risks.length === 0) return { letter: "F", numeric: 0 };
  const avg = Math.round(risks.reduce((a, r) => a + r.exposureLevel, 0) / risks.length);
  let letter: HeatmapAuditResult["letterGrade"];
  if (avg < 25) letter = "A";
  else if (avg < 45) letter = "B";
  else if (avg < 65) letter = "C";
  else if (avg < 85) letter = "D";
  else letter = "F";
  return { letter, numeric: avg };
}

function explainRisks(risks: SubdomainRisk[], total: number, domain: string): string {
  const nCrit = risks.filter(r => r.grade === "F" || r.grade === "D").length;
  const legacy = risks.filter(r => /test|dev|old|stage|backup|internal/.test(r.name)).length;
  const notOnline = risks.filter(r => r.issues.some(i => /not reachable/i.test(i))).length;
  const problems = risks.flatMap(r => r.issues).length;
  return `${total} subdomains found on ${domain}. ${nCrit} are high or critical risk, ${legacy} appear legacy/test, ${notOnline} are unreachable. ${problems} total risk indicators detected.`;
}

function shorten(s: string, len = 48): string {
  return s.length > len ? s.slice(0, len) + "..." : s;
}

// ---- Probes ---
interface ProbeResult {
  status: "online" | "offline";
  httpCode?: number;
  headers?: Record<string, string | string[]>;
  banner?: string;
}

async function httpProbe(fqdn: string, timeoutMs: number): Promise<ProbeResult> {
  // Try http://fqdn HEAD (prefer), fall back to GET if rejected
  let url = `http://${fqdn}`;
  // SSRF-protect
  const check = validateExternalUrl(url);
  if ("error" in check) return { status: "offline" };
  try {
    const res = await safeFetch(url, { method: "HEAD", timeoutMs: timeoutMs || 8000 });
    const code = res.status;
    let headers: Record<string, string | string[]> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    let banner = headers["server"] || headers["x-powered-by"] || null;
    if (!banner) {
      // Optionally try GET for a short body if HEAD returns no content
      const res2 = await safeFetch(url, { method: "GET", timeoutMs: timeoutMs || 8000 });
      banner = res2.headers.get("server") || "";
      const text = await res2.text();
      if (text && text.length < 300 && /<!DOCTYPE|<html|it works|index of|default/i.test(text)) {
        banner += (banner ? " / " : "") + text.slice(0, 80);
      }
    }
    return { status: "online", httpCode: code, headers, banner: typeof banner === "string" ? banner : undefined };
  } catch {
    return { status: "offline" };
  }
}
async function httpsProbe(fqdn: string, timeoutMs: number): Promise<ProbeResult> {
  let url = `https://${fqdn}`;
  const check = validateExternalUrl(url);
  if ("error" in check) return { status: "offline" };
  try {
    const res = await safeFetch(url, { method: "HEAD", timeoutMs: timeoutMs || 8000 });
    const code = res.status;
    let headers: Record<string, string | string[]> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    let banner = headers["server"] || headers["x-powered-by"] || null;
    if (!banner) {
      // Optionally try GET for a short body if HEAD returns no content
      const res2 = await safeFetch(url, { method: "GET", timeoutMs });
      banner = res2.headers.get("server") || "";
      const text = await res2.text();
      if (text && text.length < 300 && /<!DOCTYPE|<html/i.test(text)) {
        banner += (banner ? " / " : "") + text.slice(0, 80);
      }
    }
    return { status: "online", httpCode: code, headers, banner: typeof banner === "string" ? banner : undefined };
  } catch {
    return { status: "offline" };
  }
}
async function sslProbe(fqdn: string, timeoutMs: number):(Promise<{ hasCert: boolean, isValid: boolean, issuer: string }>) {
  // Instead of opening self TLS (not possible), use crt.sh with the exact label
  const domain = fqdn;
  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
    const ctrl = AbortSignal.timeout(timeoutMs);
    const resp = await fetch(url, { signal: ctrl });
    if (!resp.ok) return { hasCert: false, isValid: false, issuer: "" };
    const arr = await resp.json();
    if (!Array.isArray(arr) || arr.length === 0) return { hasCert: false, isValid: false, issuer: "" };
    // Take latest for this cn
    let cert = arr[arr.length - 1];
    if (!cert || !cert.not_after || !cert.issuer_name) return { hasCert: true, isValid: false, issuer: "Unknown" };
    const expiry = Date.parse(cert.not_after);
    const valid = expiry > Date.now();
    return { hasCert: true, isValid: valid, issuer: cert.issuer_name };
  } catch {
    return { hasCert: false, isValid: false, issuer: "" };
  }
}
