import { safeFetch } from "../../shared/ssrf";

// Types
export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface PreviewResult {
  url: string;
  variationScore: number; // 0-100 score of content changing
  detectedObfuscations: string[]; // e.g., ["captcha-injection", "random-html" ]
  grade: string; // letter grade A-F
  recommendations: Recommendation[];
  explanation: string;
}

export interface DiffItem {
  snippet: string;
  position: number; // approx location in content
  differenceType: "added" | "removed" | "modified";
}

export interface FetchMetadata {
  fetchUrl: string;
  status: number;
  contentLength: number;
  timestamp: string;
}

export interface FullAnalysisResult {
  url: string;
  overallScore: number; // 0-100
  grade: string; // A-F
  fetchCount: number;
  detectedIssues: string[]; // e.g., ["captcha-obfuscation", "content-injection"]
  recommendations: Recommendation[];
  detailedReport: {
    diffs: DiffItem[];
    nlpScores: {
      sentimentVariation: number; // 0-100
      perplexityVariance: number;
      textEntropy: number; // entropy measure 0-10
    };
    fetches: FetchMetadata[];
  };
  explanation: string;
}

// Helpers
function gradeByScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

function getNowIso() {
  return new Date().toISOString();
}

async function fetchPageContent(url: string): Promise<{ content: string; status: number }> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await safeFetch(url, { signal: controller.signal, headers: { "User-Agent": "content-shuffle-detector/1.0 apimesh.xyz" } });
    clearTimeout(timeoutId);
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    const content = await res.text();
    return { content, status: res.status };
  } catch (e) {
    clearTimeout(timeoutId);
    throw e;
  }
}

// Simple text diff algo to track changes between strings
function diffTexts(a: string, b: string): DiffItem[] {
  // This is a simplified diff on word chunks
  const aWords = a.split(/\s+/);
  const bWords = b.split(/\s+/);
  const diffs: DiffItem[] = [];

  // Use a simple sliding window to find inserted or removed
  // Due to complexity and to avoid heavy external deps, this is approximate
  const maxLen = Math.min(aWords.length, bWords.length);

  for (let i = 0; i < maxLen; i++) {
    if (aWords[i] !== bWords[i]) {
      diffs.push({ snippet: bWords[i], position: i, differenceType: "modified" });
    }
  }
  if (aWords.length < bWords.length) {
    for (let i = aWords.length; i < bWords.length; i++) {
      diffs.push({ snippet: bWords[i], position: i, differenceType: "added" });
    }
  } else if (aWords.length > bWords.length) {
    for (let i = bWords.length; i < aWords.length; i++) {
      diffs.push({ snippet: aWords[i], position: i, differenceType: "removed" });
    }
  }
  return diffs;
}

// Naive entropy: Shannon entropy over characters normalized
function shannonEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy; // max ~4.7 for ASCII
}

// Variation score of array of strings using entropy difference and lengths
function variationScore(contents: string[]): number {
  if (contents.length < 2) return 0;
  // Calculate pairwise diffs, entropy variance
  let entropySum = 0;
  let entropies: number[] = [];
  for (const c of contents) {
    const e = shannonEntropy(c);
    entropies.push(e);
    entropySum += e;
  }
  const meanE = entropySum / entropies.length;
  const variance = entropies.reduce((acc, e) => acc + (e - meanE) ** 2, 0) / entropies.length;
  // Normalize - entropy ranges up to ~5 max, variance max ~6
  // Map to 0-100
  const entropyScore = Math.min(variance * 1000, 100);

  // Also approximate content length variation
  const lengths = contents.map((c) => c.length);
  const meanLen = lengths.reduce((a, b) => a + b, 0) / lengths.length;
  const lenVariance = lengths.reduce((acc, l) => acc + (l - meanLen) ** 2, 0) / lengths.length;
  const lenScore = Math.min(lenVariance / (meanLen * meanLen) * 10000, 100);

  // Combine scores
  return (entropyScore + lenScore) / 2;
}

// Simple NLP heuristics
function detectCaptchaOrObfuscation(texts: string[]): string[] {
  const issues: string[] = [];
  const joined = texts.join(" ").toLowerCase();
  if (joined.includes("captcha")) {issues.push("captcha-injection");}
  if (joined.match(/please verify|prove you are human|type the characters/i)) { issues.push("captcha-obfuscation"); }
  if (joined.match(/<script[^>]+eval\(/i)) { issues.push("script-eval-obfuscation"); }
  if (joined.match(/randomstring|ddos|bot challenge/i)) { issues.push("bot-detection"); }

  return issues;
}

// Preview analyzer: fetch 2 pages and do basic variation
export async function analyzeContentShufflePreview(url: string): Promise<PreviewResult> {
  // Fetch same page 2 times in parallel
  try {
    const [fetch1, fetch2] = await Promise.all([
      fetchPageContent(url),
      new Promise(async (resolve, reject) => {
        // Delay 1.5s between fetches to catch dynamic changes
        setTimeout(async () => {
          try {
            const f = await fetchPageContent(url);
            resolve(f);
          } catch (e) {
            reject(e);
          }
        }, 1500);
      }),
    ]);

    const contents = [fetch1.content, (fetch2 as any).content];
    const varScore = variationScore(contents); // 0-100
    // Grade roughly inverse
    const grade = gradeByScore(100 - varScore);
    const obfs = detectCaptchaOrObfuscation(contents);

    // Recommendations
    const recs: Recommendation[] = [];
    if (varScore > 50) {
      recs.push({ issue: "High content variation", severity: Math.round(varScore), suggestion: "Check for unauthorized content injections, dynamic scripts, or CDN inconsistencies." });
    }
    if (obfs.includes("captcha-injection") || obfs.includes("captcha-obfuscation")) {
      recs.push({ issue: "Detected CAPTCHA or obfuscation", severity: 80, suggestion: "Consider CAPTCHA detection/bypass or reduce request frequency." });
    }

    return {
      url,
      variationScore: varScore,
      detectedObfuscations: obfs,
      grade,
      recommendations: recs,
      explanation: "Preview scan uses 2 quick page fetches and analyzes variation and suspicious patterns. More frequent or complex changes reduce grade.",
    };
  } catch (e) {
    throw e;
  }
}

// Full analyzer: fetch 5+ times, analyze diffs, NLP scores, scoring, detailed report
export async function analyzeContentShuffleFull(url: string): Promise<FullAnalysisResult> {
  // Fetch page 5 times sequentially with short delays to catch variations
  const fetchCount = 7;
  const results: { content: string; status: number; timestamp: string; fetchUrl: string }[] = [];

  for (let i = 0; i < fetchCount; i++) {
    try {
      const now = getNowIso();
      // Append a cache buster param to avoid cached content
      const target = new URL(url);
      target.searchParams.set("_apimesh_cache_buster", `${Date.now()}_${i}`);

      const f = await fetchPageContent(target.toString());
      results.push({ content: f.content, status: f.status, timestamp: now, fetchUrl: target.toString() });
    } catch (e) {
      // Ignore one failed fetch but keep others
      console.error(`fetch #${i} failed:`, e);
      results.push({ content: "", status: 0, timestamp: getNowIso(), fetchUrl: url });
    }
    // Wait 700ms between fetches
    await new Promise((r) => setTimeout(r, 700));
  }

  const contents = results.map((r) => r.content);

  // Compute pairwise diffs with last fetch
  const diffs: DiffItem[] = [];
  for (let i = 0; i < fetchCount - 1; i++) {
    diffs.push(...diffTexts(contents[i], contents[fetchCount - 1]));
  }

  // NLP heuristic scores
  const sentimentVariation = variationScore(contents); // Use same variation as sentiment var approximation
  const perplexityVariance = variationScore(contents); // Placeholder for perplexity differences on texts
  const textEntropy = Math.max(...contents.map(shannonEntropy));

  // Detect obfuscations
  const obfs = detectCaptchaOrObfuscation(contents);

  // Score calculation
  let baseScore = 100;
  // Deduct for high variation
  baseScore -= Math.min(sentimentVariation, 100) * 0.6;

  // Deduct for detected obfuscation issues
  if (obfs.length > 0) {
    baseScore -= 20;
  }

  if (baseScore < 0) baseScore = 0;

  const grade = gradeByScore(baseScore);

  // Recommendations
  const recs: Recommendation[] = [];
  if (sentimentVariation > 40) {
    recs.push({
      issue: "High content variation detected",
      severity: Math.round(sentimentVariation),
      suggestion: "Review changes to underlying content, scripts, or injections causing dynamic content.",
    });
  }
  if (obfs.includes("captcha-injection") || obfs.includes("captcha-obfuscation")) {
    recs.push({
      issue: "Captcha or bot-related obfuscation detected",
      severity: 80,
      suggestion: "Consider bot detection and mitigations or use proper session handling.",
    });
  }

  if (obfs.includes("script-eval-obfuscation")) {
    recs.push({
      issue: "Script eval obfuscation detected",
      severity: 65,
      suggestion: "Audit scripts and remove eval or dynamic code where possible.",
    });
  }

  // Detailed explanation
  const explanation = `The analysis ran ${fetchCount} fetches of the URL and computed content variation scores, detected patterns related to CAPTCHA presence and script obfuscation, and performed textual statistical analysis. Final score of ${baseScore.toFixed(1)} indicates content integrity and potential dynamic alterations.`;

  return {
    url,
    overallScore: Math.round(baseScore),
    grade,
    fetchCount,
    detectedIssues: obfs,
    recommendations: recs,
    detailedReport: {
      diffs,
      nlpScores: {
        sentimentVariation: Math.round(sentimentVariation),
        perplexityVariance: Math.round(perplexityVariance),
        textEntropy: Math.round(textEntropy * 10) / 10,
      },
      fetches: results,
    },
    explanation,
  };
}
