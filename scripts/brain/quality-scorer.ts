/**
 * Quality scorer for generated API code.
 *
 * Evaluates generated code across 4 dimensions (richness, error handling,
 * documentation, performance) and returns a 0-100 overall score.
 * APIs scoring below 60/100 are blocked with actionable feedback.
 */

export interface QualityScore {
  richness: number;       // 0-100
  error_handling: number; // 0-100
  documentation: number;  // 0-100
  performance: number;    // 0-100
  overall: number;        // weighted average
  pass: boolean;          // overall >= 60
  details: string[];      // human-readable dimension breakdown
  feedback: string;       // actionable fix suggestions when pass=false, empty when pass=true
}

interface GeneratedFile {
  path: string;
  content: string;
}

// ---------------------------------------------------------------------------
// Dimension scorers
// ---------------------------------------------------------------------------

function scoreRichness(allContent: string): number {
  let score = 0;

  // Count fields in typed response/result interfaces
  const interfaceBlocks = allContent.matchAll(
    /interface\s+\w*(?:Result|Response)\s*\{([^}]+)\}/gi
  );
  let fieldCount = 0;
  for (const match of interfaceBlocks) {
    const body = match[1];
    const fields = body.split("\n").filter((l) => l.includes(":")).length;
    fieldCount += fields;
  }

  if (fieldCount >= 10) score += 30;
  else if (fieldCount >= 5) score += 20;
  else score += 5;

  // Check for explanation/recommendation keywords
  const explanationPattern =
    /explanation|recommendation|suggestion|fix|remediation/i;
  if (explanationPattern.test(allContent)) score += 25;

  // Check for score/grade/severity keywords
  const scoringPattern = /score|grade|rating|severity/i;
  if (scoringPattern.test(allContent)) score += 25;

  // Check for response envelope pattern status+data+meta
  const envelopePattern = /status.*data.*meta/s;
  if (envelopePattern.test(allContent)) score += 20;

  return Math.min(100, score);
}

function scoreErrorHandling(allContent: string): number {
  let score = 0;

  // Count non-empty catch blocks
  const catchBlocks = allContent.matchAll(/catch\s*\([^)]*\)\s*\{([^}]*)\}/gs);
  let nonEmptyCatchCount = 0;
  let totalCatchCount = 0;
  for (const match of catchBlocks) {
    totalCatchCount++;
    const body = match[1].trim();
    if (body.length > 0 && (body.includes("c.json") || body.includes("return"))) {
      nonEmptyCatchCount++;
    }
  }

  if (nonEmptyCatchCount > 0) {
    score += Math.min(40, nonEmptyCatchCount * 20);
  }

  // Check for AbortSignal.timeout in catch context (timeout error handling)
  if (/TimeoutError|timed?\s*out/i.test(allContent) && /504/.test(allContent)) {
    score += 20;
  }

  // Check for input validation patterns
  if (/if\s*\(\s*!(?:url|query|domain|email|input)/i.test(allContent)) {
    score += 20;
  }

  // Check for 504 timeout status code handling
  if (/504/.test(allContent)) {
    score += 20;
  }

  return Math.min(100, score);
}

function scoreDocumentation(allContent: string): number {
  let score = 0;

  // Check info endpoint for docs/pricing/examples fields
  const hasDocsField = /docs\s*:/i.test(allContent);
  const hasPricingField = /pricing\s*:/i.test(allContent);
  const hasExamplesField = /examples\s*:/i.test(allContent);

  if (hasDocsField) score += 15;
  if (hasPricingField) score += 15;
  if (hasExamplesField) score += 10;

  // Check for JSDoc comment blocks
  const jsdocBlocks = allContent.match(/\/\*\*[\s\S]*?\*\//g);
  if (jsdocBlocks && jsdocBlocks.length > 0) {
    score += Math.min(30, jsdocBlocks.length * 15);
  }

  // Check for example response patterns
  if (/example|sample/i.test(allContent) && /response|result/i.test(allContent)) {
    score += 30;
  }

  return Math.min(100, score);
}

function scorePerformance(allContent: string): number {
  let score = 0;

  // Check for AbortSignal.timeout usage on fetch/safeFetch calls
  if (/AbortSignal\.timeout\s*\(/i.test(allContent)) {
    score += 30;
  }

  // Check for Promise.all or parallel fetch patterns
  if (/Promise\.all/i.test(allContent)) {
    score += 30;
  }

  // Check for readBodyCapped usage
  if (/readBodyCapped/i.test(allContent)) {
    score += 20;
  }

  // Check for streaming/chunked patterns
  if (/stream|chunked|ReadableStream|TransformStream/i.test(allContent)) {
    score += 20;
  }

  return Math.min(100, score);
}

// ---------------------------------------------------------------------------
// Feedback generator
// ---------------------------------------------------------------------------

function generateFeedback(
  richness: number,
  errorHandling: number,
  documentation: number,
  performance: number,
  allContent: string
): string {
  const items: string[] = [];

  if (richness < 20) {
    // Count actual fields
    const interfaceBlocks = allContent.matchAll(
      /interface\s+\w*(?:Result|Response)\s*\{([^}]+)\}/gi
    );
    let fieldCount = 0;
    for (const match of interfaceBlocks) {
      fieldCount += match[1].split("\n").filter((l) => l.includes(":")).length;
    }
    items.push(
      `Response interface has ${fieldCount} fields, need 5+. Add: explanations field, severity_score field, recommendations array`
    );
  }

  if (errorHandling < 20) {
    const catchBlocks = allContent.matchAll(/catch\s*\([^)]*\)\s*\{([^}]*)\}/gs);
    let emptyCount = 0;
    for (const match of catchBlocks) {
      if (match[1].trim().length === 0) emptyCount++;
    }
    items.push(
      `Found ${emptyCount} empty catch blocks. Each catch must contain c.json() error response with detail message`
    );
  }

  if (documentation < 20) {
    items.push(
      "Info endpoint missing docs/examples. Add docs object with endpoint descriptions and example responses"
    );
  }

  if (performance < 20) {
    items.push(
      "No timeout configuration found. Add AbortSignal.timeout(10000) to all fetch/safeFetch calls"
    );
  }

  return items.join("\n");
}

// ---------------------------------------------------------------------------
// Main scorer
// ---------------------------------------------------------------------------

const WEIGHT_RICHNESS = 0.30;
const WEIGHT_ERROR = 0.25;
const WEIGHT_DOCS = 0.20;
const WEIGHT_PERF = 0.25;

export function scoreQuality(files: GeneratedFile[]): QualityScore {
  const allContent = files.map((f) => f.content).join("\n");

  const richness = scoreRichness(allContent);
  const error_handling = scoreErrorHandling(allContent);
  const documentation = scoreDocumentation(allContent);
  const performance = scorePerformance(allContent);

  const overall = Math.round(
    richness * WEIGHT_RICHNESS +
      error_handling * WEIGHT_ERROR +
      documentation * WEIGHT_DOCS +
      performance * WEIGHT_PERF
  );

  const pass = overall >= 60;

  const details = [
    `Richness: ${richness}/100 (weight ${WEIGHT_RICHNESS})`,
    `Error Handling: ${error_handling}/100 (weight ${WEIGHT_ERROR})`,
    `Documentation: ${documentation}/100 (weight ${WEIGHT_DOCS})`,
    `Performance: ${performance}/100 (weight ${WEIGHT_PERF})`,
    `Overall: ${overall}/100 — ${pass ? "PASS" : "FAIL"}`,
  ];

  const feedback = pass
    ? ""
    : generateFeedback(richness, error_handling, documentation, performance, allContent);

  return {
    richness,
    error_handling,
    documentation,
    performance,
    overall,
    pass,
    details,
    feedback,
  };
}
