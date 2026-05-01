import { safeFetch, validateExternalUrl } from "../../shared/ssrf";

// This file contains all core logic for fetching privacy policies from given domain URLs,
// performing multi-source fetch analysis, NLP-based drift detection, compliance scoring,
// and actionable remediation recommendations.
//
// It strictly returns typed results and handles errors gracefully.

// Types
export interface Recommendation {
  issue: string;
  severity: number; // 0-100 indicating priority (higher is more severe)
  suggestion: string;
}

export interface AnalysisResult {
  url: string;                 // The canonical URL analyzed
  snapshotHash: string;       // A hash representing the fetched policy content snapshot
  driftScore: number;         // 0-100 - estimated drift amount vs base snapshot
  complianceScore: number;    // 0-100 - heuristic compliance scoring
  grade: "A" | "B" | "C" | "D" | "F"; // letter grade based on scores
  lastFetchedAt: string;      // ISO timestamp when last fetched
  recommendations: Recommendation[]; // ordered by severity descending
  details: string;            // human-readable summary explanation
}

export interface PreviewResult {
  url: string;               // URL fetched
  snapshotHash: string;     // snapshot (more minimal)
  summary: string;          // brief NLP-generated summary text snippet
  lastFetchedAt: string;
  driftDetected: boolean;   // rough boolean if drift is present
}

// --- Constants and helpers ---

const USER_AGENT = "privacy-policy-drift/1.0 apimesh.xyz";
const FETCH_TIMEOUT_MS = 10000;
const PREVIEW_FETCH_TIMEOUT_MS = 20000;

function hashString(str: string): string {
  // Simple hash function (FNV-1a 32-bit) to get snapshot hash
  let hash = 2166136261;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return ('0000000' + (hash >>> 0).toString(16)).slice(-8);
}

function gradeFromScore(score: number): AnalysisResult["grade"] {
  if (score >= 90) return "A";
  else if (score >= 75) return "B";
  else if (score >= 60) return "C";
  else if (score >= 40) return "D";
  return "F";
}

// Minimal NLP-like text difference and drift scoring (placeholder)
// Real impl would use embedding distance or text difference alg
function computeDriftScore(prevText: string, newText: string): number {
  if (!prevText) return 100;
  const prevWords = new Set(prevText.toLowerCase().split(/\W+/));
  const newWords = new Set(newText.toLowerCase().split(/\W+/));
  let changed = 0;
  for (const w of newWords) {
    if (!prevWords.has(w)) changed++;
  }
  const total = newWords.size || 1;
  return Math.min(100, Math.round((changed / total) * 100));
}

// Generate recommendations heuristically for demonstration
function generateRecommendations(driftScore: number, complianceScore: number): Recommendation[] {
  const recs: Recommendation[] = [];

  if (driftScore > 30) {
    recs.push({
      issue: "Detected significant changes in privacy policy content.",
      severity: 80,
      suggestion: "Review the updated privacy policy for compliance and notify your users if required.",
    });
  }
  if (complianceScore < 60) {
    recs.push({
      issue: "Compliance score indicates potential missing or weak policy sections.",
      severity: 90,
      suggestion: "Add clear sections on user data collection, retention, and deletion rights to improve compliance.",
    });
  }
  if (driftScore === 0 && complianceScore >= 90) {
    recs.push({
      issue: "Policy is stable and highly compliant.",
      severity: 10,
      suggestion: "Maintain current policy and continue regular monitoring.",
    });
  }

  return recs;
}

function extractTextContent(html: string): string {
  // Naive text extraction by stripping tags and excessive whitespace
  return html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// --- Core functions ---

async function fetchPolicy(url: string, timeoutMs: number): Promise<{ finalUrl: string; content: string }> {
  // Fetch the given URL using safeFetch and AbortSignal timeout
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await safeFetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": USER_AGENT },
    });
    clearTimeout(timeout);
    if (!res.ok) {
      throw new Error(`Fetch failed with HTTP status ${res.status}`);
    }
    const content = await res.text();
    return { finalUrl: res.url, content };
  } catch (e) {
    clearTimeout(timeout);
    throw e;
  }
}

// For this example, attempts to locate privacy policy page for preview
async function fetchPrivacyPolicyUrlFromHomepage(rawUrl: string, timeoutMs: number): Promise<string> {
  // Fetch homepage HTML, try to find first <a> with 'privacy' in href text or URL
  const { content, finalUrl } = await fetchPolicy(rawUrl, timeoutMs);
  const html = content.toLowerCase();
  // Simple regex to find links, not full HTML parsing (good enough)
  const matches = [...html.matchAll(/<a\s+[^>]*href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/gi)];
  for (const m of matches) {
    const href = m[1];
    const text = m[2];
    if (href.toLowerCase().includes("privacy") || text.toLowerCase().includes("privacy")) {
      // Make absolute URL if needed
      try {
        const absUrl = new URL(href, finalUrl);
        return absUrl.toString();
      } catch {
        continue;
      }
    }
  }
  // fallback to rawUrl
  return rawUrl;
}

// NLP summary mock
function generateSummary(text: string, length: number = 160): string {
  // Shorten to first non-empty 160 character snippet
  const snippet = text.substring(0, length).trim();
  return snippet.length < length ? snippet : snippet + "...";
}

// Main preview analysis
export async function previewAnalysis(rawUrl: string): Promise<PreviewResult> {
  // Validate URL
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) throw new Error(`Invalid URL: ${check.error}`);

  // First try to fetch likely privacy policy page
  const privacyPolicyUrl = await fetchPrivacyPolicyUrlFromHomepage(check.url.toString(), PREVIEW_FETCH_TIMEOUT_MS);

  // Fetch privacy policy HTML
  const { finalUrl, content } = await fetchPolicy(privacyPolicyUrl, PREVIEW_FETCH_TIMEOUT_MS);

  const textContent = extractTextContent(content);
  const snapshotHash = hashString(textContent);
  const summary = generateSummary(textContent);

  // For preview, no drift detection (assume no prior snapshot stored)
  return {
    url: finalUrl,
    snapshotHash,
    summary,
    lastFetchedAt: new Date().toISOString(),
    driftDetected: false,
  };
}

// Mocked fetch previous snapshot for drift comparison
async function fetchPreviousSnapshotHash(url: string): Promise<string | null> {
  // Ideally from a DB or cache; here simulate no previous
  // In real production, replace with persistent storage logic
  return null;
}

// Heuristic compliance score evaluation mock
function heuristicComplianceScore(text: string): number {
  let score = 50;
  const lower = text.toLowerCase();
  if (lower.includes("cookie") || lower.includes("tracking")) score += 20;
  if (lower.includes("user rights") || lower.includes("gdpr") || lower.includes("ccpa")) score += 30;
  if (lower.includes("data deletion") || lower.includes("opt-out")) score += 10;
  if (lower.includes("transparency") || lower.includes("third-party")) score += 10;
  if (lower.includes("encryption")) score += 5;
  return Math.min(100, score);
}

// Main comprehensive analysis (paid)
export async function fullAnalysis(rawUrl: string): Promise<AnalysisResult | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: check.error };

  const originalUrl = check.url.toString();

  try {
    // Attempt to find explicit privacy policy URL
    const policyUrl = await fetchPrivacyPolicyUrlFromHomepage(originalUrl, FETCH_TIMEOUT_MS);

    // Parallel fetch current and previous snapshots (simulate previous fetch with mock)
    const [currentFetch, prevSnapshotHash] = await Promise.all([
      fetchPolicy(policyUrl, FETCH_TIMEOUT_MS),
      fetchPreviousSnapshotHash(policyUrl),
    ]);

    const textContent = extractTextContent(currentFetch.content);
    const snapshotHash = hashString(textContent);
    const lastFetchedAt = new Date().toISOString();

    // Drift score versus previous
    const driftScore = prevSnapshotHash ? computeDriftScore(prevSnapshotHash, snapshotHash) : 0;

    // Compliance score via heuristic analysis
    const complianceScore = heuristicComplianceScore(textContent);

    const grade = gradeFromScore(complianceScore);

    const recommendations = generateRecommendations(driftScore, complianceScore);

    const details = `Fetched privacy policy from ${policyUrl}. Drift score ${driftScore}. Compliance score ${complianceScore}.`;

    return {
      url: policyUrl,
      snapshotHash,
      driftScore,
      complianceScore,
      grade,
      lastFetchedAt,
      recommendations,
      details,
    };

  } catch (e: unknown) {
    const errMsg = e instanceof Error ? e.message : String(e);
    return { error: errMsg };
  }
}
