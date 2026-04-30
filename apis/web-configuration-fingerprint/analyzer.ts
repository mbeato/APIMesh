import { safeFetch, readBodyCapped } from "../../shared/ssrf";

// --- Types ---

export interface Recommendation {
  issue: string;
  severity: number; // 0-100, higher is more critical
  suggestion: string;
}

export interface ConfigFingerprintResult {
  url: string;
  configsFound: string[]; // filenames detected
  framework: string | null;
  deployment: string | null;
  score: number; // 0-100
  grade: string; // A-F
  recommendations: Recommendation[];
  details: string; // human-readable summary of findings
}

export interface ConfigPreviewResult {
  url: string;
  configsDetected: string[];
  frameworkGuess: string | null;
  note: string;
}

// --- Constants & Helpers ---

const COMMON_CONFIG_FILES = [
  "nuxt.config.js",
  "next.config.js",
  "netlify.toml",
  "vercel.json",
  "gatsby-config.js",
  "remix.config.js",
  "svelte.config.js",
  "firebase.json",
  "package.json",
];

// Maps config file to framework or deployment
const CONFIG_FRAMEWORK_MAP: Record<string, string> = {
  "nuxt.config.js": "Nuxt",
  "next.config.js": "Next.js",
  "gatsby-config.js": "Gatsby",
  "remix.config.js": "Remix",
  "svelte.config.js": "SvelteKit",
};

const CONFIG_DEPLOYMENT_MAP: Record<string, string> = {
  "netlify.toml": "Netlify",
  "vercel.json": "Vercel",
  "firebase.json": "Firebase Hosting",
};

// --- Util: Grade from score ---
function gradeFromScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  if (score >= 30) return "E";
  return "F";
}

// --- Util: Fetch config file content if accessible (js or toml/json) ---

async function fetchConfigFile(urlBase: URL, filename: string): Promise<string | null> {
  // Construct the URL to the config file at root or base
  // Normalize url with trailing slash
  let baseHref = urlBase.href;
  if (!baseHref.endsWith("/")) baseHref += "/";

  const targetUrl = baseHref + filename;

  try {
    const resp = await safeFetch(targetUrl, {
      method: "GET",
      signal: AbortSignal.timeout(10000),
      headers: { "User-Agent": "web-configuration-fingerprint/1.0 apimesh.xyz" },
    });

    if (!resp.ok || resp.status >= 400) {
      return null;
    }

    // Limit body size to 64KB
    const text = await readBodyCapped(resp, 64 * 1024);
    return text;
  } catch (e) {
    return null;
  }
}

// --- Parsing helpers ---

// Extract version from package.json content if present
function extractFrameworkVersion(pkgJsonContent: string, frameworkName: string): string | null {
  try {
    const parsed = JSON.parse(pkgJsonContent);

    if (!parsed.dependencies && !parsed.devDependencies) return null;

    const deps = {
      ...(parsed.dependencies || {}),
      ...(parsed.devDependencies || {}),
    };

    switch (frameworkName.toLowerCase()) {
      case "nuxt":
        return deps["nuxt"] || null;
      case "next.js":
      case "next":
        return deps["next"] || null;
      case "gatsby":
        return deps["gatsby"] || null;
      case "remix":
        return deps["@remix-run/react"] || null;
      case "sveltekit":
        return deps["@sveltejs/kit"] || null;
      default:
        return null;
    }
  } catch {
    return null;
  }
}

// For simple toml parsing (only basic key-value), we use a minimal regex approach
function parseTomlToObj(tomlText: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = tomlText.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith("[")) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    let val = trimmed.slice(eqIdx + 1).trim();
    // Remove quotes if present
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    result[key] = val;
  }
  return result;
}

// --- Analysis core ---

export async function analyzeConfigurations(url: URL): Promise<ConfigFingerprintResult> {
  const configsFound: string[] = [];
  const configsContents: Record<string, string | null> = {};

  // Attempt to fetch common config files in parallel
  const fetchPromises = COMMON_CONFIG_FILES.map(async (filename) => {
    const content = await fetchConfigFile(url, filename);
    if (content !== null) {
      configsFound.push(filename);
      configsContents[filename] = content;
    }
  });

  await Promise.all(fetchPromises);

  // Determine framework & deployment guesses
  let framework: string | null = null;
  let deployment: string | null = null;

  for (const fname of configsFound) {
    if (!framework && CONFIG_FRAMEWORK_MAP[fname]) {
      framework = CONFIG_FRAMEWORK_MAP[fname];
    }
    if (!deployment && CONFIG_DEPLOYMENT_MAP[fname]) {
      deployment = CONFIG_DEPLOYMENT_MAP[fname];
    }
  }

  // Attempt to extract versions or more detailed info from package.json or config files
  let versionInfo: string | null = null;

  if (configsFound.includes("package.json") && framework) {
    const pkgContent = configsContents["package.json"] ?? null;
    if (pkgContent) {
      versionInfo = extractFrameworkVersion(pkgContent, framework);
    }
  }

  // Aggregate score and recommendations
  let score = 100;
  const recommendations: Recommendation[] = [];
  const detailsArr: string[] = [];

  if (configsFound.length === 0) {
    score = 20;
    recommendations.push({
      issue: "No config files detected",
      severity: 90,
      suggestion: "Check if config files are named unusually or deployed behind auth. Try absolute URLs or different base URL.",
    });
    detailsArr.push("No recognizable config files found at root.");
  } else {
    detailsArr.push(`Detected config files: ${configsFound.join(", ")}`);

    if (framework) {
      detailsArr.push(`Inferred framework: ${framework}`);
      if (versionInfo) {
        detailsArr.push(`Detected ${framework} version: ${versionInfo}`);
        // Example: penalize outdated versions (very simple check)
        if (/^(0|1|2)\./.test(versionInfo)) {
          score -= 30;
          recommendations.push({
            issue: `Outdated ${framework} version ${versionInfo}`,
            severity: 60,
            suggestion: `Upgrade to a supported ${framework} version for security and performance gains.`,
          });
        }
      } else {
        recommendations.push({
          issue: `No version info detected for ${framework}`,
          severity: 30,
          suggestion: `Include ${framework} version in package.json dependencies explicitly.`,
        });
      }
    } else {
      recommendations.push({
        issue: "No framework detected",
        severity: 50,
        suggestion: "Try to verify framework via other artifacts or deeper analysis.",
      });
      score -= 20;
    }

    if (!deployment) {
      recommendations.push({
        issue: "No deployment platform detected",
        severity: 40,
        suggestion: "Check for deployment config files or configure CI/CD platform annotations.",
      });
      score -= 10;
    } else {
      detailsArr.push(`Detected deployment platform: ${deployment}`);
      // Example recommendation for Netlify
      if (deployment === "Netlify" && !configsFound.includes("_redirects")) {
        recommendations.push({
          issue: "Netlify redirects configuration missing",
          severity: 40,
          suggestion: "Add a _redirects file for routing and rewrite rules.",
        });
        score -= 15;
      }
    }
  }

  // Clamp score
  if (score < 0) score = 0;
  if (score > 100) score = 100;

  const grade = gradeFromScore(score);

  return {
    url: url.toString(),
    configsFound,
    framework,
    deployment,
    score,
    grade,
    recommendations,
    details: detailsArr.join(" "),
  };
}

export async function analyzePreview(url: URL): Promise<ConfigPreviewResult> {
  const configsDetected: string[] = [];

  // Check presence of only key config files concurrently
  const checks = ["nuxt.config.js", "next.config.js", "netlify.toml"].map(
    async (fname) => {
      const content = await fetchConfigFile(url, fname);
      if (content !== null) {
        configsDetected.push(fname);
      }
    }
  );
  await Promise.all(checks);

  let frameworkGuess: string | null = null;
  for (const fname of configsDetected) {
    if (CONFIG_FRAMEWORK_MAP[fname]) {
      frameworkGuess = CONFIG_FRAMEWORK_MAP[fname];
      break;
    }
  }

  return {
    url: url.toString(),
    configsDetected,
    frameworkGuess,
    note: "Preview mode detects only a subset of common config files with minimal analysis.",
  };
}
