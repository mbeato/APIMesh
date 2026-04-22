import { safeFetch, readBodyCapped } from "../../shared/ssrf";

// Types
export interface LicenseOccurrence {
  name: string;
  occurrences: number;
}

export interface DependencyLicenseSummary {
  total_dependencies: number;
  unique_licenses: number;
  high_risk_count: number;
}

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface DependencyLicenseAuditResult {
  scanned_manifests: number;
  total_dependencies: number;
  license_counts: Record<string, number>;
  risk_score: number; // 0-100 (higher bad)
  grade: string; // A-F
  recommendations: Recommendation[];
  details: string;
}

export interface DependencyLicensePreviewResult {
  manifest_url: string;
  licenses_found: LicenseOccurrence[];
  summary: DependencyLicenseSummary;
  explanations: string;
}

interface AnalyzerOpts {
  includeDev?: boolean;
  previewOnly?: boolean;
}

// License risk scoring map
const LICENSE_RISK_SCORE: Record<string, number> = {
  MIT: 10,
  "Apache-2.0": 10,
  BSD_3_Clause: 15,
  BSD_2_Clause: 20,
  ISC: 15,
  "GPL-3.0": 80,
  "GPL-2.0": 75,
  "LGPL-3.0": 50,
  "LGPL-2.1": 45,
  MPL_2_0: 40,
  Proprietary: 90,
  Unknown: 60,
};

// Grade boundaries
function scoreToGrade(score: number): string {
  if (score <= 10) return "A";
  if (score <= 30) return "B";
  if (score <= 50) return "C";
  if (score <= 70) return "D";
  return "F";
}

// Parse package.json dependencies
async function parsePackageJson(raw: string, includeDev: boolean): Promise<Record<string, string>> {
  try {
    const parsed = JSON.parse(raw);
    const deps: Record<string, string> = {};
    if (parsed.dependencies && typeof parsed.dependencies === "object") {
      Object.assign(deps, parsed.dependencies);
    }
    if (includeDev && parsed.devDependencies && typeof parsed.devDependencies === "object") {
      Object.assign(deps, parsed.devDependencies);
    }
    return deps;
  } catch {
    return {};
  }
}

// Parse requirements.txt (very simple approximation)
function parseRequirementsTxt(raw: string): Record<string, string> {
  const deps: Record<string, string> = {};
  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    // Example: package==1.2.3
    const parts = trimmed.split(/[>=<~!]+/);
    if (parts.length > 0) {
      const name = parts[0].toLowerCase();
      deps[name] = trimmed;
    }
  }
  return deps;
}

// Map common license strings to normalized forms
function normalizeLicense(lic: string): string {
  if (!lic) return "Unknown";
  const l = lic.toLowerCase();
  if (l.includes("mit")) return "MIT";
  if (l.includes("apache")) return "Apache-2.0";
  if (l.includes("bsd")) return "BSD_3_Clause";
  if (l.includes("gpl")) return l.includes("3") ? "GPL-3.0" : "GPL-2.0";
  if (l.includes("lgpl")) return l.includes("3") ? "LGPL-3.0" : "LGPL-2.1";
  if (l.includes("mpl")) return "MPL_2_0";
  if (l.includes("isc")) return "ISC";
  if (l.includes("proprietary")) return "Proprietary";
  return "Unknown";
}

// Fetch JSON or text from URL
async function fetchManifestRaw(url: string): Promise<string> {
  // Use generous timeout since depends on size and origin
  // 10s here, caller may adjust
  const res = await safeFetch(url, { timeoutMs: 10_000 });
  if (!res.ok) {
    throw new Error(`Failed to fetch manifest: HTTP ${res.status}`);
  }
  // Read max 256KB
  return readBodyCapped(res, 262_144);
}

// Query SPDX license list database (official site) to validate license names
// We do a simple fetch and search license text starting with license id
async function querySpdxLicense(licenseId: string): Promise<{ id: string; name: string; isOsiApproved: boolean }> {
  const url = `https://spdx.org/licenses/${licenseId}.json`;
  try {
    const res = await safeFetch(url, { timeoutMs: 10_000 });
    if (!res.ok) return { id: licenseId, name: licenseId, isOsiApproved: false };
    const json = await res.json();
    return {
      id: json.licenseId || licenseId,
      name: json.name || licenseId,
      isOsiApproved: Boolean(json.isOsiApproved),
    };
  } catch {
    return { id: licenseId, name: licenseId, isOsiApproved: false };
  }
}

// Query public NPM registry for package license
async function queryNpmLicense(pkgName: string): Promise<string> {
  const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}/latest`;
  try {
    const res = await safeFetch(url, { timeoutMs: 10_000 });
    if (!res.ok) return "Unknown";
    const json = await res.json();
    if (json && json.license) {
      if (typeof json.license === "string") return normalizeLicense(json.license);
      if (typeof json.license === "object" && json.license.type) {
        return normalizeLicense(json.license.type);
      }
    }
    return "Unknown";
  } catch {
    return "Unknown";
  }
}

// Simple analysis of license risk score
function calculateRisk(licenses: Record<string, number>): number {
  let total = 0;
  let count = 0;
  for (const [lic, qty] of Object.entries(licenses)) {
    const risk = LICENSE_RISK_SCORE[lic] ?? 60; // Unknown or no map treated as moderate risk
    total += risk * qty;
    count += qty;
  }
  if (count === 0) return 0;
  return total / count;
}

// Compose recommendations based on licenses
function generateRecommendations(licenses: Record<string, number>): Recommendation[] {
  const recs: Recommendation[] = [];
  if (Object.keys(licenses).length === 0) {
    return [{ issue: "No licenses detected.", severity: 90, suggestion: "Verify your manifests and ensure license metadata exists." }];
  }

  for (const [lic, count] of Object.entries(licenses)) {
    const risk = LICENSE_RISK_SCORE[lic] ?? 60;
    if (risk >= 70) {
      recs.push({
        issue: `${lic} license detected in ${count} dependencies`,
        severity: risk,
        suggestion: `Review dependencies with ${lic} license for compatibility and possible replacement.`,
      });
    } else if (risk >= 50) {
      recs.push({
        issue: `${lic} license detected in ${count} dependencies`,
        severity: risk,
        suggestion: `Consider auditing usage of ${lic} licensed packages and legal advisories.`,
      });
    }
  }

  return recs;
}

// Normalize license strings in a list (best effort)
function normalizeLicenseList(rawList: string[]): string[] {
  const normalized = rawList.map(normalizeLicense).filter(Boolean);
  return [...new Set(normalized)];
}

// Main audit function
export async function runDependencyLicenseAudit(
  manifestUrls: string | string[],
  opts: AnalyzerOpts = {}
): Promise<DependencyLicenseAuditResult | DependencyLicensePreviewResult | { error: string }> {
  const urls = Array.isArray(manifestUrls) ? manifestUrls : [manifestUrls];
  if (urls.length === 0) {
    return { error: "No manifest URLs provided" };
  }

  if (opts.previewOnly) {
    // Preview: only fetch first manifest and do partial analysis
    const url = urls[0];
    try {
      const raw = await fetchManifestRaw(url);
      // Parse only package.json and requirements.txt
      let licenses: Record<string, number> = {};
      if (url.toLowerCase().endsWith("package.json")) {
        const deps = await parsePackageJson(raw, !!opts.includeDev);
        for (const dep of Object.keys(deps)) {
          // Query npm for license (best effort)
          const license = await queryNpmLicense(dep);
          licenses[license] = (licenses[license] || 0) + 1;
        }
      } else if (url.toLowerCase().endsWith("requirements.txt")) {
        const deps = parseRequirementsTxt(raw);
        for (const dep of Object.keys(deps)) {
          // PyPI license query not implemented, mark unknown
          licenses["Unknown"] = (licenses["Unknown"] || 0) + 1;
        }
      } else {
        // Unsupported preview manifest type
        return {
          manifest_url: url,
          licenses_found: [],
          summary: { total_dependencies: 0, unique_licenses: 0, high_risk_count: 0 },
          explanations: `Unsupported manifest type for preview.`,
        };
      }
      const licenseOccurrences: LicenseOccurrence[] = Object.entries(licenses).map(
        ([name, occurrences]) => ({ name, occurrences })
      );
      const totalDeps = licenseOccurrences.reduce((a, v) => a + v.occurrences, 0);
      const uniqueLicenses = licenseOccurrences.length;
      const highRiskCount = licenseOccurrences.filter(l => (LICENSE_RISK_SCORE[l.name] ?? 60) >= 70).reduce((a, v) => a + v.occurrences, 0);

      return {
        manifest_url: url,
        licenses_found: licenseOccurrences,
        summary: { total_dependencies: totalDeps, unique_licenses: uniqueLicenses, high_risk_count: highRiskCount },
        explanations: `Preview fetched manifest and identified license types with summary. IncludeDev=${!!opts.includeDev}`,
      };
    } catch (e: any) {
      const msg = e instanceof Error ? e.message : String(e);
      return { error: `Preview failed: ${msg}` };
    }
  }

  // Full audit - fetch all manifests in parallel
  try {
    const fetches = urls.map(u => fetchManifestRaw(u));
    const raws = await Promise.all(fetches);

    // Collect dependencies licenses
    const depLicenses: Record<string, number> = {};
    let totalDeps = 0;

    for (let i = 0; i < raws.length; i++) {
      const raw = raws[i];
      const url = urls[i];
      let deps: Record<string, string> = {};

      if (url.toLowerCase().endsWith("package.json")) {
        deps = await parsePackageJson(raw, !!opts.includeDev);
      } else if (url.toLowerCase().endsWith("requirements.txt")) {
        deps = parseRequirementsTxt(raw);
      } else {
        // Unsupported manifest, skip
        continue;
      }

      totalDeps += Object.keys(deps).length;

      // Query licenses for each dependency sequentially per manifest
      // Limited concurrency for large lists is possible but for now sequential
      for (const dep of Object.keys(deps)) {
        let license = "Unknown";
        if (url.toLowerCase().endsWith("package.json")) {
          license = await queryNpmLicense(dep);
        } else {
          // For requirements.txt, no direct PyPI license query; mark Unknown
          license = "Unknown";
        }
        depLicenses[license] = (depLicenses[license] || 0) + 1;
      }
    }

    const riskScore = calculateRisk(depLicenses);
    const grade = scoreToGrade(riskScore);
    const recommendations = generateRecommendations(depLicenses);

    const details = `Scanned ${urls.length} manifests: ${urls.join(",")}. Total dependencies: ${totalDeps}. License breakdown: ${JSON.stringify(depLicenses)}.`;

    return {
      scanned_manifests: urls.length,
      total_dependencies: totalDeps,
      license_counts: depLicenses,
      risk_score: parseFloat(riskScore.toFixed(2)),
      grade,
      recommendations,
      details,
    };
  } catch (error: any) {
    const msg = error instanceof Error ? error.message : String(error);
    return { error: `Audit failed: ${msg}` };
  }
}
