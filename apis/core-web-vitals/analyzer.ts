// Core Web Vitals analyzer — calls Google PageSpeed Insights API v5

const PSI_BASE = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed";

function sanitizePsiUrl(raw: unknown): string {
  if (typeof raw !== "string") return "";
  try {
    const u = new URL(raw);
    if (u.protocol !== "http:" && u.protocol !== "https:") return "";
    return u.toString().slice(0, 2048);
  } catch { return ""; }
}

// ─── Thresholds (Google's official) ───────────────────────────────────────────

const THRESHOLDS = {
  LCP: { good: 2500, needsImprovement: 4000 },   // ms
  CLS: { good: 0.1, needsImprovement: 0.25 },     // unitless
  INP: { good: 200, needsImprovement: 500 },       // ms
} as const;

type VitalRating = "good" | "needs-improvement" | "poor";

function rateMetric(value: number, threshold: { good: number; needsImprovement: number }): VitalRating {
  if (value <= threshold.good) return "good";
  if (value <= threshold.needsImprovement) return "needs-improvement";
  return "poor";
}

function performanceGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 50) return "C";
  if (score >= 25) return "D";
  return "F";
}

// ─── Types ────────────────────────────────────────────────────────────────────

interface CrUXMetric {
  value: number;
  rating: VitalRating;
  percentiles: { p75: number } | null;
  distributions: { min: number; max: number; proportion: number }[] | null;
}

interface LighthouseScores {
  performance: number;
  accessibility: number;
  bestPractices: number;
  seo: number;
}

interface LoadingMetrics {
  timeToFirstByte: number | null;
  firstContentfulPaint: number | null;
  speedIndex: number | null;
  totalBlockingTime: number | null;
  largestContentfulPaint: number | null;
  cumulativeLayoutShift: number | null;
}

export interface FullReport {
  url: string;
  fetchedUrl: string;
  strategy: string;
  coreWebVitals: {
    lcp: CrUXMetric | null;
    cls: CrUXMetric | null;
    inp: CrUXMetric | null;
    fieldDataAvailable: boolean;
  };
  lighthouseScores: LighthouseScores;
  loadingMetrics: LoadingMetrics;
  overallGrade: string;
  performanceScore: number;
  checkedAt: string;
}

export interface PreviewReport {
  url: string;
  performanceScore: number;
  overallGrade: string;
  preview: true;
  checkedAt: string;
  note: string;
}

// ─── PSI fetcher ──────────────────────────────────────────────────────────────

async function callPSI(url: string, categories: string[]): Promise<any> {
  const params = new URLSearchParams();
  params.set("url", url);
  params.set("strategy", "mobile");
  for (const cat of categories) {
    params.append("category", cat);
  }

  const apiKey = process.env.PSI_API_KEY;
  if (apiKey) {
    params.set("key", apiKey);
  }

  const endpoint = `${PSI_BASE}?${params.toString()}`;
  const response = await fetch(endpoint, {
    signal: AbortSignal.timeout(60_000), // PSI can be slow
  });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    try {
      const parsed = JSON.parse(body);
      if (parsed?.error?.message) {
        console.error(`[callPSI] Google PSI error ${response.status}: ${parsed.error.message}`);
      }
    } catch {
      console.error(`[callPSI] Google PSI error ${response.status}: ${body.slice(0, 500)}`);
    }
    throw new Error("Analysis failed (upstream error)");
  }

  return response.json();
}

// ─── Extract helpers ──────────────────────────────────────────────────────────

function extractCrUXMetric(
  loadingExperience: any,
  metricKey: string,
  threshold: { good: number; needsImprovement: number },
): CrUXMetric | null {
  const metrics = loadingExperience?.metrics;
  if (!metrics || !metrics[metricKey]) return null;

  const metric = metrics[metricKey];
  const p75 = metric.percentile;
  if (p75 == null) return null;

  return {
    value: p75,
    rating: rateMetric(p75, threshold),
    percentiles: { p75 },
    distributions: metric.distributions?.map((d: any) => ({
      min: d.min,
      max: d.max ?? Infinity,
      proportion: Math.round(d.proportion * 10000) / 10000,
    })) ?? null,
  };
}

function extractLighthouseScores(data: any): LighthouseScores {
  const cats = data?.lighthouseResult?.categories ?? {};
  return {
    performance: Math.round((cats.performance?.score ?? 0) * 100),
    accessibility: Math.round((cats.accessibility?.score ?? 0) * 100),
    bestPractices: Math.round((cats["best-practices"]?.score ?? 0) * 100),
    seo: Math.round((cats.seo?.score ?? 0) * 100),
  };
}

function extractAuditNumeric(data: any, auditId: string): number | null {
  const audit = data?.lighthouseResult?.audits?.[auditId];
  if (!audit || audit.numericValue == null) return null;
  return Math.round(audit.numericValue * 100) / 100;
}

function extractLoadingMetrics(data: any): LoadingMetrics {
  return {
    timeToFirstByte: extractAuditNumeric(data, "server-response-time"),
    firstContentfulPaint: extractAuditNumeric(data, "first-contentful-paint"),
    speedIndex: extractAuditNumeric(data, "speed-index"),
    totalBlockingTime: extractAuditNumeric(data, "total-blocking-time"),
    largestContentfulPaint: extractAuditNumeric(data, "largest-contentful-paint"),
    cumulativeLayoutShift: extractAuditNumeric(data, "cumulative-layout-shift"),
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function analyzeFullReport(url: string): Promise<FullReport> {
  const data = await callPSI(url, ["performance", "accessibility", "best-practices", "seo"]);

  const loadingExperience = data.loadingExperience;
  const fieldDataAvailable = loadingExperience?.metrics != null &&
    Object.keys(loadingExperience.metrics).length > 0;

  const lcp = extractCrUXMetric(loadingExperience, "LARGEST_CONTENTFUL_PAINT_MS", THRESHOLDS.LCP);
  const cls = extractCrUXMetric(loadingExperience, "CUMULATIVE_LAYOUT_SHIFT_SCORE", THRESHOLDS.CLS);
  const inp = extractCrUXMetric(loadingExperience, "INTERACTION_TO_NEXT_PAINT", THRESHOLDS.INP);

  const lighthouseScores = extractLighthouseScores(data);
  const loadingMetrics = extractLoadingMetrics(data);

  const performanceScore = lighthouseScores.performance;

  return {
    url,
    fetchedUrl: sanitizePsiUrl(data.lighthouseResult?.finalDisplayedUrl ?? data.id ?? url),
    strategy: "mobile",
    coreWebVitals: {
      lcp,
      cls,
      inp,
      fieldDataAvailable,
    },
    lighthouseScores,
    loadingMetrics,
    overallGrade: performanceGrade(performanceScore),
    performanceScore,
    checkedAt: new Date().toISOString(),
  };
}

export async function analyzePreview(url: string): Promise<PreviewReport> {
  const data = await callPSI(url, ["performance"]);

  const lighthouseScores = extractLighthouseScores(data);
  const performanceScore = lighthouseScores.performance;

  return {
    url,
    performanceScore,
    overallGrade: performanceGrade(performanceScore),
    preview: true,
    checkedAt: new Date().toISOString(),
    note: "Preview shows Lighthouse performance score only. Pay via x402 for full Core Web Vitals, all Lighthouse categories, and loading metrics.",
  };
}
