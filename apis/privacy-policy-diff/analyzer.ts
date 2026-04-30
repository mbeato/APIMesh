import { safeFetch, validateExternalUrl, readBodyCapped } from "../../shared/ssrf";
import { PolicyVersion, DiffResult, PreviewResult, PolicyDiff, DiffDetail, ComplianceSignal, PolicyRecommendation } from "./types";

const USER_AGENT = "privacy-policy-diff/1.0 apimesh.xyz";

// Retrieve the privacy policy text from given domain
// Attempts common paths and public sources
async function fetchPolicyText(domain: string, signal: AbortSignal): Promise<PolicyVersion | { error: string }> {
  const crawlTimeout = 10000;

  // Potential common privacy policy paths
  const policyPaths = [
    "/privacy-policy",
    "/privacy",
    "/privacy_policy",
    "/legal/privacy",
    "/privacypolicy",
    "/privacy.html",
    "/privacy-policy.html",
    "/docs/privacy-policy",
    "/policies/privacy",
    "/policies/privacy-policy",
  ];

  // Use HEAD to check existence with allowed shorter timeout
  async function checkExists(url: URL): Promise<boolean> {
    try {
      const res = await safeFetch(url.toString(), {
        method: "HEAD",
        headers: { "User-Agent": USER_AGENT },
        timeoutMs: 8000,
        signal,
      });
      return res.ok && (res.headers.get("content-type") || "").toLowerCase().includes("text/html");
    } catch {
      return false;
    }
  }

  try {
    const baseUrl = new URL(`https://${domain}`);

    // Find first available path
    let foundUrl: URL | null = null;

    for (const path of policyPaths) {
      const candidateUrl = new URL(path, baseUrl);
      if (await checkExists(candidateUrl)) {
        foundUrl = candidateUrl;
        break;
      }
    }

    // Fallback: root (home page) if none found
    if (!foundUrl) {
      foundUrl = baseUrl;
    }

    // Fetch the page content with timeout
    const res = await safeFetch(foundUrl.toString(), {
      method: "GET",
      headers: { "User-Agent": USER_AGENT },
      timeoutMs: crawlTimeout,
      signal,
    });

    if (!res.ok) {
      return { error: `Failed to fetch privacy policy page, status ${res.status}` };
    }

    // Read up to 256 KiB only
    const bodyText = await readBodyCapped(res, 256 * 1024);

    // Extract text content with basic cleaning
    const cleanedText = extractTextFromHtml(bodyText);

    return {
      url: foundUrl.toString(),
      fetchedAt: new Date().toISOString(),
      rawText: cleanedText,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Failed to fetch privacy policy: ${msg}` };
  }
}

function extractTextFromHtml(html: string): string {
  // Basic HTML to text extractor, removing scripts, styles, tags
  // and normalizing whitespace
  let text = html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<head[^>]*>[\s\S]*?<\/head>/gi, " ")
    .replace(/<!--.*?-->/gs, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  return text.slice(0, 25_000); // limit output size to 25k characters
}

// Compare two policy texts and produce a structured diff result
function computeTextDiff(oldText: string, newText: string): DiffDetail[] {
  // Use a basic line-based diff with some heuristics
  // Split into paragraphs for better semantic diff
  const oldParagraphs = splitIntoParagraphs(oldText);
  const newParagraphs = splitIntoParagraphs(newText);

  // Use a simple diff algorithm
  // We'll mark paragraphs as added, removed, or modified

  // Using a naive LCS-based diff to detect unchanged
  const lcsMatrix = buildLcsMatrix(oldParagraphs, newParagraphs);
  const diffs: DiffDetail[] = [];
  backtrackDiff(lcsMatrix, oldParagraphs, newParagraphs, oldParagraphs.length, newParagraphs.length, diffs);

  return diffs;
}

function splitIntoParagraphs(text: string): string[] {
  // Split by two or more newlines or sentences
  const paras = text.split(/\n{2,}|\.\s+/).map(p => p.trim()).filter(p => p.length > 0);
  return paras;
}

function buildLcsMatrix(
  oldArr: string[],
  newArr: string[]
): number[][] {
  const m = oldArr.length;
  const n = newArr.length;
  const dp: number[][] = Array(m + 1)
    .fill(null)
    .map(() => Array(n + 1).fill(0));

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = oldArr[i - 1] === newArr[j - 1]
        ? dp[i - 1][j - 1] + 1
        : Math.max(dp[i][j - 1], dp[i - 1][j]);
    }
  }
  return dp;
}

function backtrackDiff(
  dp: number[][],
  oldArr: string[],
  newArr: string[],
  i: number,
  j: number,
  diffs: DiffDetail[]
) {
  if (i > 0 && j > 0 && oldArr[i - 1] === newArr[j - 1]) {
    // No change for this paragraph
    backtrackDiff(dp, oldArr, newArr, i - 1, j - 1, diffs);
    // We do not record unchanged paragraphs
  } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
    backtrackDiff(dp, oldArr, newArr, i, j - 1, diffs);
    diffs.push({
      section: `Paragraph ${j}`,
      changeType: "added",
      contentAfter: newArr[j - 1],
      severityImpact: 40,
      explanation: "New policy text added.",
    });
  } else if (i > 0 && (j === 0 || dp[i][j - 1] < dp[i - 1][j])) {
    backtrackDiff(dp, oldArr, newArr, i - 1, j, diffs);
    diffs.push({
      section: `Paragraph ${i}`,
      changeType: "removed",
      contentBefore: oldArr[i - 1],
      severityImpact: 40,
      explanation: "Existing policy text removed.",
    });
  }
}

// Analyze compliance signals based on diffs
function analyzeComplianceSignals(diffs: DiffDetail[]): ComplianceSignal[] {
  const signals: ComplianceSignal[] = [];

  for (const d of diffs) {
    // High severity if key compliance terms removed
    if (d.changeType === "removed" && /data protection|user consent|gdpr|ccpa|cookies/i.test(d.contentBefore || "")) {
      signals.push({
        id: "compliance-risk-removed",
        description: `Potential removal of compliance-related statement: "${shorten(d.contentBefore)}"`,
        severity: 90,
        scoreImpact: -25,
        examples: [],
      });
    }
    // If added text mentions better compliance
    if (d.changeType === "added" && /gdpr|ccpa|user rights|data protection/i.test(d.contentAfter || "")) {
      signals.push({
        id: "compliance-improved",
        description: `New compliance-related addition: "${shorten(d.contentAfter)}"`,
        severity: 70,
        scoreImpact: +15,
      });
    }
  }

  return signals;
}

// Generate recommendations based on signals and diffs
function generateRecommendations(signals: ComplianceSignal[], diffs: DiffDetail[]): PolicyRecommendation[] {
  const recs: PolicyRecommendation[] = [];

  for (const s of signals) {
    if (s.scoreImpact < 0) {
      recs.push({
        issue: s.description,
        severity: s.severity,
        suggestion: "Review your privacy policy changes carefully to ensure you remain compliant with relevant privacy laws and regulations.",
      });
    } else if (s.scoreImpact > 0) {
      recs.push({
        issue: s.description,
        severity: s.severity,
        suggestion: "Ensure newly added privacy policy statements are communicated clearly to users and enforced appropriately.",
      });
    }
  }

  // Generic recommendations if no signals
  if (recs.length === 0) {
    recs.push({
      issue: "No significant compliance issues detected.",
      severity: 10,
      suggestion: "Maintain regular reviews of your privacy policy text to ensure ongoing compliance with evolving privacy laws.",
    });
  }

  return recs;
}

function shorten(text: string | undefined): string {
  if (!text) return "";
  return text.length > 100 ? text.slice(0, 97) + "..." : text;
}

function computeSeverityScore(signals: ComplianceSignal[], diffs: DiffDetail[]): number {
  // Score 0-100: sum negative impacts, sum positive impacts
  let score = 50; // neutral baseline
  for (const s of signals) {
    score += s.scoreImpact;
  }
  for (const d of diffs) {
    score += d.severityImpact * (d.changeType === "removed" ? -0.5 : 0.5);
  }

  if (score < 0) score = 0;
  if (score > 100) score = 100;
  return Math.round(score);
}

function gradeFromScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 45) return "D";
  return "F";
}

// Main diff and analysis function
export async function analyzePolicyDiff(
  domain: string,
  oldPolicy: PolicyVersion,
  newPolicy: PolicyVersion
): Promise<DiffResult> {
  const start = performance.now();

  const diffs = computeTextDiff(oldPolicy.rawText, newPolicy.rawText);
  const complianceSignals = analyzeComplianceSignals(diffs);
  const recommendations = generateRecommendations(complianceSignals, diffs);
  const severityScore = computeSeverityScore(complianceSignals, diffs);
  const grade = gradeFromScore(severityScore);

  // Summarize changes
  let addedCount = 0, removedCount = 0;
  diffs.forEach((d) => {
    if (d.changeType === "added") addedCount++;
    else if (d.changeType === "removed") removedCount++;
  });

  const changesSummary = `Added ${addedCount} paragraph(s), removed ${removedCount} paragraph(s), total changes ${diffs.length}`;

  const processingTimeMs = Math.round(performance.now() - start);

  return {
    domain,
    policyOld: oldPolicy,
    policyNew: newPolicy,
    diff: {
      fetchedAtOld: oldPolicy.fetchedAt,
      fetchedAtNew: newPolicy.fetchedAt,
      changesSummary,
      severityScore,
      grade,
      complianceSignals,
      recommendations,
      detailedChanges: diffs,
    },
    analysisDate: new Date().toISOString(),
    processingTimeMs,
  };
}

// For preview: Return summary info about the latest privacy policy discovery
export async function previewFetchPolicy(domain: string): Promise<PreviewResult> {
  const start = performance.now();
  const fetchResult = await fetchPolicyText(domain, AbortSignal.timeout(20000));

  if ("error" in fetchResult) {
    return {
      domain,
      latestPolicyIndexUrl: null,
      previewTextSnippet: "",
      previewTimestamp: new Date().toISOString(),
      note: `Preview failed: ${fetchResult.error}`,
      analysisDate: new Date().toISOString(),
      processingTimeMs: Math.round(performance.now() - start),
    };
  }

  const snippet = fetchResult.rawText.slice(0, 300);

  return {
    domain,
    latestPolicyIndexUrl: fetchResult.url,
    previewTextSnippet: snippet,
    previewTimestamp: fetchResult.fetchedAt,
    note: "This preview retrieves the latest privacy policy text snippet (free). For historical diffs and compliance scoring, pay via x402.",
    analysisDate: new Date().toISOString(),
    processingTimeMs: Math.round(performance.now() - start),
  };
}

// Fetch both policies for diff, with provided URLs or domains for old/new
// If no URLs provided, fallback: two fetches from same domain at different times not possible
export async function fetchAndAnalyze(
  domain: string,
  oldUrl?: string,
  newUrl?: string
): Promise<DiffResult | { error: string }> {
  const signal = AbortSignal.timeout(15000);

  // Validate domain
  const domainCheck = validateExternalUrl(`https://${domain}`);
  if ("error" in domainCheck) return { error: `Invalid domain: ${domainCheck.error}` };

  let oldPolicy: PolicyVersion;
  let newPolicy: PolicyVersion;

  // Try to fetch old policy from oldUrl if supplied
  if (oldUrl) {
    const oldCheck = validateExternalUrl(oldUrl);
    if ("error" in oldCheck) return { error: `Invalid oldUrl: ${oldCheck.error}` };
    const oldRes = await fetchPolicyTextFromUrl(oldCheck.url.toString(), signal);
    if ("error" in oldRes) return { error: `Failed to fetch old policy: ${oldRes.error}` };
    oldPolicy = oldRes;
  } else {
    // If no oldUrl, just fetch once for oldPolicy; simulate with empty old text
    oldPolicy = { url: "", fetchedAt: new Date(0).toISOString(), rawText: "" };
  }

  // Fetch new policy
  if (newUrl) {
    const newCheck = validateExternalUrl(newUrl);
    if ("error" in newCheck) return { error: `Invalid newUrl: ${newCheck.error}` };
    const newRes = await fetchPolicyTextFromUrl(newCheck.url.toString(), signal);
    if ("error" in newRes) return { error: `Failed to fetch new policy: ${newRes.error}` };
    newPolicy = newRes;
  } else {
    // fetch newPolicy from domain
    const newRes = await fetchPolicyText(domain, signal);
    if ("error" in newRes) return { error: `Failed to fetch new policy: ${newRes.error}` };
    newPolicy = newRes;
  }

  return analyzePolicyDiff(domain, oldPolicy, newPolicy);
}

// Fetch full text from a direct URL (used for oldUrl or newUrl passed explicitly)
async function fetchPolicyTextFromUrl(url: string, signal: AbortSignal): Promise<PolicyVersion | { error: string }> {
  try {
    const res = await safeFetch(url, {
      method: "GET",
      headers: { "User-Agent": USER_AGENT },
      timeoutMs: 15000,
      signal,
    });

    if (!res.ok) {
      return { error: `Request failed with status ${res.status}` };
    }

    const bodyText = await readBodyCapped(res, 256 * 1024);
    const cleaned = extractTextFromHtml(bodyText);

    return {
      url,
      fetchedAt: new Date().toISOString(),
      rawText: cleaned,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: `Failed to fetch from URL: ${msg}` };
  }
}
