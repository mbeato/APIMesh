import { safeFetch, validateExternalUrl, readBodyCapped } from "../../shared/ssrf";
import type {
  Grade,
  ViolationDetails,
  ReportEnvelope,
  ReportAnalysis,
  IssueRecommendation,
} from "./types";

const USER_AGENT = "website-csp-violation-report/1.0 apimesh.xyz";
const FETCH_TIMEOUT_MS = 10000;

function letterGrade(score: number): Grade {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 65) return "B";
  if (score >= 45) return "C";
  if (score >= 25) return "D";
  return "F";
}

function severityFromScore(score: number): "critical" | "warning" | "info" {
  if (score < 30) return "critical";
  if (score < 70) return "warning";
  return "info";
}

function parseReportEnvelope(bodyText: string): ReportEnvelope | null {
  try {
    const data = JSON.parse(bodyText);
    // Validate presence of csp-report
    if (data && typeof data === "object" && "csp-report" in data) {
      return data as ReportEnvelope;
    }
  } catch {
    return null;
  }
  return null;
}

function normalizeUri(uri: string | null): string {
  if (!uri) return "Unknown or empty URI";
  return uri.trim();
}

function analyzeViolation(report: ViolationDetails): ReportAnalysis {
  // Scoring and grading based on violation seriousness and common dangerous patterns

  let score = 100;
  const recs: IssueRecommendation[] = [];
  const issues: string[] = [];

  // Check critical issues
  if (!report.violated_directive) {
    issues.push("'violated_directive' missing or empty.");
    recs.push({ issue: "Missing violated_directive", severity: "critical", suggestion: "Ensure the CSP header defines directives correctly so violations specify which directive is violated." });
    score -= 40;
  } else {
    // Evaluate violated directive severity
    const lowerDirective = report.violated_directive.toLowerCase();
    if (lowerDirective === "script-src" || lowerDirective === "default-src") {
      score -= 40;
      recs.push({
        issue: `Violation of critical directive '${report.violated_directive}'.`,
        severity: "critical",
        suggestion: "Review your CSP directives for 'script-src' or 'default-src' to remove unsafe sources and restrict script execution paths.",
      });
    } else if (lowerDirective === "img-src" || lowerDirective === "style-src") {
      score -= 15;
      recs.push({
        issue: `Violation of important directive '${report.violated_directive}'.`,
        severity: "warning",
        suggestion: "Tighten your CSP to restrict image or style sources to trusted domains only.",
      });
    } else {
      score -= 10;
      recs.push({
        issue: `Violation of directive '${report.violated_directive}'.`,
        severity: "info",
        suggestion: "Check the CSP directive and consider restricting it further based on your site's needs.",
      });
    }
  }

  if (report.blocked_uri) {
    const blocked = report.blocked_uri.toLowerCase();
    if (blocked === "inline" || blocked === "eval") {
      score -= 30;
      recs.push({
        issue: "'inline' or 'eval' script blocked.",
        severity: "critical",
        suggestion: "Avoid inline scripts and the use of eval-like constructs; implement strict CSP without 'unsafe-inline' or 'unsafe-eval'.",
      });
    } else if (blocked === "data" || blocked.startsWith("data:")) {
      score -= 20;
      recs.push({
        issue: "Blocked use of data: URI.",
        severity: "warning",
        suggestion: "Restrict data: URIs in CSP or avoid usage; consider using safer alternatives.",
      });
    }
  }

  // Check source file and line/column for user actionable debug info
  const detailsBuilder: string[] = [];
  detailsBuilder.push(`Violation detected for directive: ${report.violated_directive || "unknown"}`);
  detailsBuilder.push(`Original policy: ${report.original_policy || "(not available)"}`);
  detailsBuilder.push(`Blocked URI: ${report.blocked_uri || "unknown"}`);
  if (report.source_file) {
    detailsBuilder.push(`Source file: ${report.source_file}`);
    if (report.line_number !== null) {
      detailsBuilder.push(`Line: ${report.line_number}`);
    }
    if (report.column_number !== null) {
      detailsBuilder.push(`Column: ${report.column_number}`);
    }
  }

  // Basic check for report with missing fields
  if (!report.original_policy) {
    recs.push({ issue: "Missing original_policy field", severity: "warning", suggestion: "Ensure your CSP reporting endpoint includes the original_policy field for better analysis." });
  }

  if (score < 0) score = 0;

  return {
    score,
    grade: letterGrade(score),
    severity: severityFromScore(score),
    summary: `CSP violation of directive '${report.violated_directive || "unknown"}' with severity ${severityFromScore(score)}.`,
    details: detailsBuilder.join(" | "),
    recommendations: recs,
    rawReport: report,
  };
}

export async function analyzeCspPayload(payload: unknown): Promise<ReportAnalysis | { error: string }> {
  if (!payload || typeof payload !== "object") {
    return { error: "Invalid or missing JSON payload" };
  }

  // Expect payload to conform to ReportEnvelope
  const jsonStr = JSON.stringify(payload);
  const parsed = parseReportEnvelope(jsonStr);
  if (!parsed) {
    return { error: "Payload does not contain valid 'csp-report' object" };
  }

  const report = parsed["csp-report"];
  return analyzeViolation(report);
}

export async function fetchAndAnalyzeReportUri(reportUri: string): Promise<ReportAnalysis | { error: string }> {
  const val = validateExternalUrl(reportUri);
  if ("error" in val) {
    return { error: `Invalid report URI: ${val.error}` };
  }
  try {
    const res = await safeFetch(val.url.toString(), {
      method: "GET",
      headers: { "User-Agent": USER_AGENT },
      timeoutMs: FETCH_TIMEOUT_MS,
    });
    if (!res.ok) {
      return { error: `Failed to fetch report URI, status ${res.status}` };
    }
    // Read sample of body up to 256KB
    const body = await readBodyCapped(res, 256 * 1024);
    const json = parseReportEnvelope(body);
    if (!json) {
      return { error: "Response body does not contain valid CSP report JSON" };
    }
    return analyzeViolation(json["csp-report"]);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`Fetch or analysis failed: ${msg}`);
  }
}

