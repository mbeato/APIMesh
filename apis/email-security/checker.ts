import { Resolver } from "node:dns/promises";

const resolver = new Resolver();

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface SpfResult {
  found: boolean;
  raw: string | null;
  mechanisms: {
    includes: string[];
    a: string[];
    mx: string[];
    ip4: string[];
    ip6: string[];
    all: string | null;
  };
  allQualifier: string | null;
  recursiveIncludeCount: number;
  grade: Grade;
  error?: string;
}

export interface DmarcResult {
  found: boolean;
  raw: string | null;
  policy: string | null;
  pct: number | null;
  rua: string[];
  ruf: string[];
  subdomainPolicy: string | null;
  grade: Grade;
  error?: string;
}

export interface DkimSelector {
  selector: string;
  found: boolean;
  raw?: string;
}

export interface DkimResult {
  selectorsProbed: string[];
  found: DkimSelector[];
  pass: boolean;
  error?: string;
}

export interface MxRecord {
  priority: number;
  hostname: string;
  provider: string | null;
}

export interface MxResult {
  found: boolean;
  records: MxRecord[];
  pass: boolean;
  error?: string;
}

export interface EmailSecurityReport {
  domain: string;
  spf: SpfResult;
  dmarc: DmarcResult;
  dkim?: DkimResult;
  mx?: MxResult;
  overallGrade: Grade;
  checkedAt: string;
}

// ---------------------------------------------------------------------------
// Domain Validation
// ---------------------------------------------------------------------------

const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export function validateDomain(input: string): { valid: boolean; domain?: string; error?: string } {
  if (!input || typeof input !== "string") {
    return { valid: false, error: "Domain parameter is required" };
  }

  const domain = input.trim().toLowerCase();

  if (domain.includes(" ")) {
    return { valid: false, error: "Domain must not contain spaces" };
  }
  if (!domain.includes(".")) {
    return { valid: false, error: "Domain must contain at least one dot" };
  }
  if (domain.startsWith("http://") || domain.startsWith("https://")) {
    return { valid: false, error: "Provide a bare domain (no protocol). Example: example.com" };
  }
  if (domain.includes("/")) {
    return { valid: false, error: "Provide a bare domain (no paths). Example: example.com" };
  }
  if (!DOMAIN_REGEX.test(domain)) {
    return { valid: false, error: "Invalid domain format. Example: example.com" };
  }

  return { valid: true, domain };
}

// ---------------------------------------------------------------------------
// DNS Error Handling
// ---------------------------------------------------------------------------

function isDnsError(e: unknown): boolean {
  return e instanceof Error && "code" in e;
}

function dnsErrorMessage(e: unknown): string {
  if (!isDnsError(e)) return "unknown_error";
  const code = (e as NodeJS.ErrnoException).code;
  const map: Record<string, string> = {
    ENODATA: "no_records",
    ENOTFOUND: "domain_not_found",
    ETIMEOUT: "timeout",
    ECONNREFUSED: "connection_refused",
    SERVFAIL: "server_failure",
    ESERVFAIL: "server_failure",
    REFUSED: "query_refused",
    EREFUSED: "query_refused",
  };
  return map[code ?? ""] ?? "dns_error";
}

function isNonExistent(e: unknown): boolean {
  if (!isDnsError(e)) return false;
  const code = (e as NodeJS.ErrnoException).code;
  return code === "ENODATA" || code === "ENOTFOUND";
}

// ---------------------------------------------------------------------------
// DNS Timeout Wrapper
// ---------------------------------------------------------------------------

const DNS_TIMEOUT_MS = 3_000;

async function resolveWithTimeout<T>(fn: () => Promise<T>): Promise<T> {
  return Promise.race([
    fn(),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("DNS timeout")), DNS_TIMEOUT_MS)
    ),
  ]);
}

// ---------------------------------------------------------------------------
// TXT Record Sanitization
// ---------------------------------------------------------------------------

function sanitizeTxtRecord(raw: string): string {
  return raw.replace(/[^\x20-\x7E]/g, "").slice(0, 512);
}

// ---------------------------------------------------------------------------
// SPF Checking
// ---------------------------------------------------------------------------

function parseSpfMechanisms(record: string) {
  const parts = record.split(/\s+/).slice(1); // skip "v=spf1"
  const mechanisms = {
    includes: [] as string[],
    a: [] as string[],
    mx: [] as string[],
    ip4: [] as string[],
    ip6: [] as string[],
    all: null as string | null,
  };

  let allQualifier: string | null = null;

  for (const part of parts) {
    // Strip qualifier prefix
    const qualifierMatch = part.match(/^([+\-~?])?(.+)$/);
    if (!qualifierMatch) continue;
    const qualifier = qualifierMatch[1] || "+";
    const mechanism = qualifierMatch[2];

    if (mechanism === "all") {
      allQualifier = qualifier;
      mechanisms.all = `${qualifier}all`;
    } else if (mechanism.startsWith("include:")) {
      mechanisms.includes.push(mechanism.slice(8));
    } else if (mechanism.startsWith("a:") || mechanism === "a") {
      mechanisms.a.push(mechanism === "a" ? "(self)" : mechanism.slice(2));
    } else if (mechanism.startsWith("mx:") || mechanism === "mx") {
      mechanisms.mx.push(mechanism === "mx" ? "(self)" : mechanism.slice(3));
    } else if (mechanism.startsWith("ip4:")) {
      mechanisms.ip4.push(mechanism.slice(4));
    } else if (mechanism.startsWith("ip6:")) {
      mechanisms.ip6.push(mechanism.slice(4));
    }
  }

  return { mechanisms, allQualifier };
}

async function countRecursiveIncludes(
  domain: string,
  visited: Set<string> = new Set(),
  depth: number = 0,
  budget: { remaining: number } = { remaining: 10 },
): Promise<number> {
  if (depth > 5 || visited.has(domain) || budget.remaining <= 0) return 0;
  visited.add(domain);

  try {
    budget.remaining--;
    if (budget.remaining <= 0) return 0;
    const records = await resolveWithTimeout(() => resolver.resolveTxt(domain));
    const flat = records.map((r) => r.join(""));
    const spf = flat.find((r) => r.startsWith("v=spf1"));
    if (!spf) return 0;

    const includes = (spf.match(/include:([^\s]+)/g) || []).slice(0, 50);
    let count = includes.length;

    for (const inc of includes) {
      const target = inc.slice(8);
      if (!validateDomain(target).valid) continue;
      count += await countRecursiveIncludes(target, visited, depth + 1, budget);
    }

    return count;
  } catch {
    return 0;
  }
}

function gradeSpf(found: boolean, allQualifier: string | null): Grade {
  if (!found) return "F";
  switch (allQualifier) {
    case "-": return "A"; // -all (hard fail)
    case "~": return "B"; // ~all (soft fail)
    case "?": return "C"; // ?all (neutral)
    case "+": return "C"; // +all (pass all)
    default: return "B";   // no explicit all — treated as neutral-ish
  }
}

export async function checkSpf(domain: string): Promise<SpfResult> {
  try {
    const records = await resolveWithTimeout(() => resolver.resolveTxt(domain));
    const flat = records.map((r) => r.join(""));
    const spfRecord = flat.find((r) => r.toLowerCase().startsWith("v=spf1"));

    if (!spfRecord) {
      return {
        found: false,
        raw: null,
        mechanisms: { includes: [], a: [], mx: [], ip4: [], ip6: [], all: null },
        allQualifier: null,
        recursiveIncludeCount: 0,
        grade: "F",
      };
    }

    const { mechanisms, allQualifier } = parseSpfMechanisms(spfRecord);
    const budget = { remaining: 10 };
    const recursiveIncludeCount = await countRecursiveIncludes(domain, new Set(), 0, budget);

    return {
      found: true,
      raw: sanitizeTxtRecord(spfRecord),
      mechanisms,
      allQualifier,
      recursiveIncludeCount,
      grade: gradeSpf(true, allQualifier),
    };
  } catch (e) {
    if (isNonExistent(e)) {
      return {
        found: false,
        raw: null,
        mechanisms: { includes: [], a: [], mx: [], ip4: [], ip6: [], all: null },
        allQualifier: null,
        recursiveIncludeCount: 0,
        grade: "F",
      };
    }
    return {
      found: false,
      raw: null,
      mechanisms: { includes: [], a: [], mx: [], ip4: [], ip6: [], all: null },
      allQualifier: null,
      recursiveIncludeCount: 0,
      grade: "F",
      error: dnsErrorMessage(e),
    };
  }
}

// ---------------------------------------------------------------------------
// DMARC Checking
// ---------------------------------------------------------------------------

function parseDmarc(record: string) {
  const tags: Record<string, string> = {};
  const parts = record.split(";").map((s) => s.trim()).filter(Boolean);
  for (const part of parts) {
    const eqIdx = part.indexOf("=");
    if (eqIdx === -1) continue;
    const key = part.slice(0, eqIdx).trim().toLowerCase();
    const value = part.slice(eqIdx + 1).trim();
    tags[key] = value;
  }

  const policy = tags["p"] || null;
  const rawPct = tags["pct"] ? parseInt(tags["pct"], 10) : null;
  const pct = rawPct !== null && Number.isFinite(rawPct) && rawPct >= 0 && rawPct <= 100 ? rawPct : null;
  const rua = tags["rua"] ? tags["rua"].split(",").map((s) => s.trim()) : [];
  const ruf = tags["ruf"] ? tags["ruf"].split(",").map((s) => s.trim()) : [];
  const subdomainPolicy = tags["sp"] || null;

  return { policy, pct, rua, ruf, subdomainPolicy };
}

function gradeDmarc(found: boolean, policy: string | null, rua: string[]): Grade {
  if (!found) return "F";
  switch (policy?.toLowerCase()) {
    case "reject": return "A";
    case "quarantine": return "B";
    case "none":
      return rua.length > 0 ? "C" : "D";
    default: return "F";
  }
}

export async function checkDmarc(domain: string): Promise<DmarcResult> {
  try {
    const records = await resolveWithTimeout(() => resolver.resolveTxt(`_dmarc.${domain}`));
    const flat = records.map((r) => r.join(""));
    const dmarcRecord = flat.find((r) => r.toLowerCase().startsWith("v=dmarc1"));

    if (!dmarcRecord) {
      return {
        found: false,
        raw: null,
        policy: null,
        pct: null,
        rua: [],
        ruf: [],
        subdomainPolicy: null,
        grade: "F",
      };
    }

    const { policy, pct, rua, ruf, subdomainPolicy } = parseDmarc(dmarcRecord);

    return {
      found: true,
      raw: sanitizeTxtRecord(dmarcRecord),
      policy,
      pct,
      rua,
      ruf,
      subdomainPolicy,
      grade: gradeDmarc(true, policy, rua),
    };
  } catch (e) {
    if (isNonExistent(e)) {
      return {
        found: false,
        raw: null,
        policy: null,
        pct: null,
        rua: [],
        ruf: [],
        subdomainPolicy: null,
        grade: "F",
      };
    }
    return {
      found: false,
      raw: null,
      policy: null,
      pct: null,
      rua: [],
      ruf: [],
      subdomainPolicy: null,
      grade: "F",
      error: dnsErrorMessage(e),
    };
  }
}

// ---------------------------------------------------------------------------
// DKIM Checking
// ---------------------------------------------------------------------------

const DEFAULT_SELECTORS = [
  "google",
  "default",
  "selector1",
  "selector2",
  "k1",
  "dkim",
  "s1",
  "s2",
  "mail",
  "email",
];

async function probeDkimSelector(domain: string, selector: string): Promise<DkimSelector> {
  try {
    const records = await resolveWithTimeout(() => resolver.resolveTxt(`${selector}._domainkey.${domain}`));
    const flat = records.map((r) => r.join(""));
    const dkimRecord = flat.find((r) => r.toLowerCase().includes("v=dkim1") || r.includes("p="));

    if (dkimRecord) {
      return { selector, found: true, raw: sanitizeTxtRecord(dkimRecord) };
    }
    return { selector, found: false };
  } catch {
    return { selector, found: false };
  }
}

const DKIM_BATCH_SIZE = 3;

export async function checkDkim(domain: string): Promise<DkimResult> {
  try {
    const found: DkimSelector[] = [];
    for (let i = 0; i < DEFAULT_SELECTORS.length; i += DKIM_BATCH_SIZE) {
      const batch = DEFAULT_SELECTORS.slice(i, i + DKIM_BATCH_SIZE);
      const results = await Promise.all(batch.map(sel => probeDkimSelector(domain, sel)));
      found.push(...results.filter(r => r.found));
      if (found.length > 0) break;
    }

    return {
      selectorsProbed: DEFAULT_SELECTORS,
      found,
      pass: found.length > 0,
    };
  } catch (e) {
    return {
      selectorsProbed: DEFAULT_SELECTORS,
      found: [],
      pass: false,
      error: dnsErrorMessage(e),
    };
  }
}

// ---------------------------------------------------------------------------
// MX Checking
// ---------------------------------------------------------------------------

const MX_PROVIDERS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /\.google\.com\.?$/i, name: "Google Workspace" },
  { pattern: /\.googlemail\.com\.?$/i, name: "Google Workspace" },
  { pattern: /\.outlook\.com\.?$/i, name: "Microsoft 365" },
  { pattern: /\.microsoft\.com\.?$/i, name: "Microsoft 365" },
  { pattern: /\.pphosted\.com\.?$/i, name: "Proofpoint" },
  { pattern: /\.mimecast\.com\.?$/i, name: "Mimecast" },
  { pattern: /\.secureserver\.net\.?$/i, name: "GoDaddy" },
  { pattern: /\.zoho\.com\.?$/i, name: "Zoho Mail" },
];

function detectProvider(hostname: string): string | null {
  for (const { pattern, name } of MX_PROVIDERS) {
    if (pattern.test(hostname)) return name;
  }
  return null;
}

export async function checkMx(domain: string): Promise<MxResult> {
  try {
    const records = await resolveWithTimeout(() => resolver.resolveMx(domain));

    if (!records || records.length === 0) {
      return { found: false, records: [], pass: false };
    }

    const sorted = records.sort((a, b) => a.priority - b.priority);
    const mapped: MxRecord[] = sorted.map((r) => ({
      priority: r.priority,
      hostname: r.exchange,
      provider: detectProvider(r.exchange),
    }));

    return { found: true, records: mapped, pass: true };
  } catch (e) {
    if (isNonExistent(e)) {
      return { found: false, records: [], pass: false };
    }
    return { found: false, records: [], pass: false, error: dnsErrorMessage(e) };
  }
}

// ---------------------------------------------------------------------------
// Overall Grade
// ---------------------------------------------------------------------------

function computeOverallGrade(spf: SpfResult, dmarc: DmarcResult, dkim?: DkimResult, mx?: MxResult): Grade {
  const spfGrade = spf.grade;
  const dmarcGrade = dmarc.grade;
  const dkimPass = dkim ? dkim.pass : undefined;
  const mxPass = mx ? mx.pass : undefined;

  // F if SPF or DMARC missing
  if (spfGrade === "F" || dmarcGrade === "F") return "F";

  // If DKIM or MX explicitly checked and failed, cap at C
  if (dkimPass === false || mxPass === false) {
    // Some critical missing
    const best = Math.min(gradeToNum(spfGrade), gradeToNum(dmarcGrade));
    return numToGrade(Math.max(best, gradeToNum("C")));
  }

  // A = both SPF and DMARC are A or B, and DKIM+MX pass
  if (
    (spfGrade === "A" || spfGrade === "B") &&
    (dmarcGrade === "A" || dmarcGrade === "B")
  ) {
    // If DKIM/MX not checked (preview), use SPF+DMARC only
    if (dkimPass === undefined && mxPass === undefined) {
      return spfGrade === "A" && dmarcGrade === "A" ? "A" : "B";
    }
    if (dkimPass && mxPass) return "A";
    return "B";
  }

  // B = all present but some weak
  if (spf.found && dmarc.found) {
    return "B";
  }

  return "C";
}

function gradeToNum(g: Grade): number {
  const map: Record<Grade, number> = { A: 0, B: 1, C: 2, D: 3, F: 4 };
  return map[g];
}

function numToGrade(n: number): Grade {
  const grades: Grade[] = ["A", "B", "C", "D", "F"];
  return grades[Math.min(n, 4)];
}

// ---------------------------------------------------------------------------
// Full Check (Paid)
// ---------------------------------------------------------------------------

export async function fullCheck(domain: string): Promise<EmailSecurityReport> {
  const [spf, dmarc, dkim, mx] = await Promise.all([
    checkSpf(domain),
    checkDmarc(domain),
    checkDkim(domain),
    checkMx(domain),
  ]);

  return {
    domain,
    spf,
    dmarc,
    dkim,
    mx,
    overallGrade: computeOverallGrade(spf, dmarc, dkim, mx),
    checkedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Preview Check (Free — SPF + DMARC only)
// ---------------------------------------------------------------------------

export async function previewCheck(domain: string): Promise<EmailSecurityReport> {
  const [spf, dmarc] = await Promise.all([
    checkSpf(domain),
    checkDmarc(domain),
  ]);

  return {
    domain,
    spf,
    dmarc,
    overallGrade: computeOverallGrade(spf, dmarc),
    checkedAt: new Date().toISOString(),
  };
}
