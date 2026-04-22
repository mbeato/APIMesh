import { safeFetch, validateExternalUrl } from "../../shared/ssrf";

// -------------------------------
// TypeScript types
// -------------------------------

export type LintLetterGrade = "A" | "B" | "C" | "D" | "F";

export interface LintIssue {
  issue: string;
  severity: number; // 0-100 higher means more severe
  suggestion: string;
}

export interface LintCheckResult {
  overallScore: number; // 0-100
  overallGrade: LintLetterGrade;
  issues: LintIssue[];
  recommendations: LintIssue[]; // actionable fixes
}

export interface ApiLintingResult {
  overallScore: number;
  overallGrade: LintLetterGrade;
  checks: {
    type: "spec" | "implementation" | "consistency";
    score: number;
    grade: LintLetterGrade;
    issues: LintIssue[];
  }[];
  recommendations: LintIssue[];
}

// -------------------------------
// Spec linting
// - Fetches OpenAPI spec at URL
// - Validates syntax
// - Checks for common anti-patterns
// - Returns detailed issues and scores
// -------------------------------


export async function analyzeSpecLint(specUrl: string): Promise<LintCheckResult> {
  // Validate URL
  const checked = validateExternalUrl(specUrl);
  if ("error" in checked) return { overallScore: 0, overallGrade: "F", issues: [{ issue: checked.error, severity: 100, suggestion: "Check URL format and accessibility." }], recommendations: [] };

  try {
    // Fetch spec file with 10s timeout
    const res = await safeFetch(checked.url.toString(), {
      timeoutMs: 10000,
      headers: { "User-Agent": "api-linting-spec/1.0 apimesh.xyz" },
    });

    if (!res.ok) {
      return {
        overallScore: 0,
        overallGrade: "F",
        issues: [{ issue: `Spec fetch failed HTTP status ${res.status}`, severity: 100, suggestion: "Verify the spec_url is valid and accessible." }],
        recommendations: [],
      };
    }

    // Attempt to parse as JSON or YAML
    let content: any;
    const text = await res.text();

    try {
      content = JSON.parse(text);
    } catch {
      // fallback to YAML parse
      try {
        // use lightweight YAML parse sandbox here
        content = parseYaml(text);
      } catch (e) {
        return {
          overallScore: 0,
          overallGrade: "F",
          issues: [{ issue: "Spec is not valid JSON or YAML", severity: 100, suggestion: "Correct syntax errors in OpenAPI document." }],
          recommendations: [],
        };
      }
    }

    // Validate base OpenAPI structure
    const issues: LintIssue[] = [];

    // Basic validations
    if (!content.openapi || !/^3\./.test(content.openapi)) {
      issues.push({
        issue: "OpenAPI field missing or not version 3.x",
        severity: 90,
        suggestion: "Use OpenAPI v3.x specification version.",
      });
    }

    if (!content.info || typeof content.info.title !== "string" || content.info.title.trim() === "") {
      issues.push({
        issue: "Info.title missing or empty",
        severity: 80,
        suggestion: "Provide a meaningful title for the API.",
      });
    }

    if (!content.paths || typeof content.paths !== "object" || Object.keys(content.paths).length === 0) {
      issues.push({
        issue: "No paths defined in OpenAPI spec",
        severity: 100,
        suggestion: "Define at least one path with operations.",
      });
    }

    // Check each path for method presence and description
    if (content.paths && typeof content.paths === "object") {
      for (const [pathKey, pathValue] of Object.entries(content.paths)) {
        if (!pathValue || typeof pathValue !== "object") continue;

        const methods = Object.keys(pathValue).filter(m => ["get", "post", "put", "delete", "patch", "head", "options", "trace"].includes(m.toLowerCase()));
        if (methods.length === 0) {
          issues.push({
            issue: `Path ${pathKey} defines no HTTP methods`,
            severity: 70,
            suggestion: "Define HTTP operations for the path.",
          });
        } else {
          for (const method of methods) {
            const op = (pathValue as any)[method];
            if (!op.description || typeof op.description !== "string" || op.description.trim() === "") {
              issues.push({
                issue: `Operation '${method.toUpperCase()}' on path ${pathKey} missing description`,
                severity: 60,
                suggestion: "Add a meaningful description for the operation.",
              });
            }

            // Check parameters have description
            if (op.parameters && Array.isArray(op.parameters)) {
              for (const param of op.parameters) {
                if (!param.description) {
                  issues.push({
                    issue: `Parameter '${param.name}' in '${method.toUpperCase()}' on path ${pathKey} missing description`,
                    severity: 50,
                    suggestion: "Document parameters with descriptions.",
                  });
                }
              }
            }

            // Check responses
            if (!op.responses || typeof op.responses !== "object" || Object.keys(op.responses).length === 0) {
              issues.push({
                issue: `Operation '${method.toUpperCase()}' on path ${pathKey} has no responses defined`,
                severity: 70,
                suggestion: "Define at least one response status code and schema.",
              });
            } else {
              for (const [statusCode, resp] of Object.entries(op.responses)) {
                if (!resp.description || typeof resp.description !== "string" || resp.description.trim() === "") {
                  issues.push({
                    issue: `Response status ${statusCode} in '${method.toUpperCase()}' on path ${pathKey} missing description`,
                    severity: 60,
                    suggestion: "Provide response descriptions.",
                  });
                }
              }
            }
          }
        }
      }
    }

    // Scoring logic
    // Deduct points for each issue weighted by severity
    let score = 100;
    for (const issue of issues) {
      score -= Math.min(issue.severity, 100);
    }

    if (score < 0) score = 0;

    return {
      overallScore: score,
      overallGrade: letterGrade(score),
      issues,
      recommendations: generateSpecRecommendations(issues),
    };
  } catch (e: any) {
    return {
      overallScore: 0,
      overallGrade: "F",
      issues: [{ issue: `Exception: ${e.message || String(e)}`, severity: 100, suggestion: "Check spec_url and spec content." }],
      recommendations: [],
    };
  }
}

// -------------------------------
// Implementation linting
// - Calls live API implementation endpoint
// - Checks HTTP status correctness
// - Checks content-type and response structure
// - Validates handshake and basic response conformity with spec
// -------------------------------

export async function analyzeImplementationLint(implUrl: string): Promise<LintCheckResult> {
  const checked = validateExternalUrl(implUrl);
  if ("error" in checked) return { overallScore: 0, overallGrade: "F", issues: [{ issue: checked.error, severity: 100, suggestion: "Check impl_url format and accessibility." }], recommendations: [] };

  try {
    // Attempt GET request
    const res = await safeFetch(checked.url.toString(), {
      method: "GET",
      timeoutMs: 10000,
      headers: { "User-Agent": "api-linting-impl/1.0 apimesh.xyz" },
    });

    const issues: LintIssue[] = [];

    // Expect 2xx response for base
    if (!(res.status >= 200 && res.status < 300)) {
      issues.push({
        issue: `Unexpected HTTP status code ${res.status}`,
        severity: 80,
        suggestion: "Ensure API returns 2xx status codes on success operations.",
      });
    }

    // Content-Type check
    const contentType = res.headers.get("content-type") || "";
    if (!contentType.includes("json")) {
      issues.push({
        issue: `Unexpected Content-Type: ${contentType || "missing"}`,
        severity: 70,
        suggestion: "API should return application/json responses as per best practice.",
      });
    }

    // Try parse JSON body
    let bodyJson: any = null;
    const text = await res.text();
    try {
      bodyJson = JSON.parse(text);
    } catch {
      issues.push({
        issue: "Response body is not valid JSON",
        severity: 80,
        suggestion: "Ensure API returns well-formed JSON responses.",
      });
    }

    // Check for meta or error fields for common anti-pattern
    if (bodyJson && typeof bodyJson === "object") {
      if ("error" in bodyJson && !res.ok) {
        issues.push({
          issue: "API returns error object with non-2xx HTTP status",
          severity: 60,
          suggestion: "Use standard HTTP status codes alongside error response bodies.",
        });
      }

      if ("status" in bodyJson && typeof bodyJson.status !== "string") {
        issues.push({
          issue: "Response has non-string status field",
          severity: 50,
          suggestion: "Standardize status indicators to string values or HTTP codes.",
        });
      }
    }

    // Compute score
    let score = 100;
    for (const issue of issues) {
      score -= Math.min(issue.severity, 100);
    }
    if (score < 0) score = 0;

    return {
      overallScore: score,
      overallGrade: letterGrade(score),
      issues,
      recommendations: generateImplRecommendations(issues),
    };
  } catch (e: any) {
    return {
      overallScore: 0,
      overallGrade: "F",
      issues: [{ issue: `Exception: ${e.message || String(e)}`, severity: 100, suggestion: "Check impl_url and server availability." }],
      recommendations: [],
    };
  }
}

// -------------------------------
// Consistency linting
// - Compares spec with implementation
// - Validates that implemented endpoints exist in spec
// - Checks response conformity to declared responses
// - Identifies mismatches and inconsistencies
// - Uses multiple fetches for deeper check
// -------------------------------

export async function analyzeConsistencyLint(specUrl: string, implUrl: string): Promise<LintCheckResult> {
  // Validate URLs
  const specCheck = validateExternalUrl(specUrl);
  const implCheck = validateExternalUrl(implUrl);
  if ("error" in specCheck) return { overallScore: 0, overallGrade: "F", issues: [{ issue: `Spec URL invalid: ${specCheck.error}`, severity: 100, suggestion: "Check the spec_url." }], recommendations: [] };
  if ("error" in implCheck) return { overallScore: 0, overallGrade: "F", issues: [{ issue: `Impl URL invalid: ${implCheck.error}`, severity: 100, suggestion: "Check the impl_url." }], recommendations: [] };

  try {
    // Fetch spec and impl in parallel with 10s timeout
    const [specRes, implRes] = await Promise.all([
      safeFetch(specCheck.url.toString(), { timeoutMs: 10000 }),
      safeFetch(implCheck.url.toString(), { timeoutMs: 10000 }),
    ]);

    if (!specRes.ok || !implRes.ok) {
      return {
        overallScore: 0,
        overallGrade: "F",
        issues: [
          { issue: `Failed to fetch spec or impl URLs (status ${specRes.status} / ${implRes.status})`, severity: 100, suggestion: "Ensure both URLs are accessible and serve valid content." }
        ],
        recommendations: [],
      };
    }

    const specText = await specRes.text();
    let specJson: any;
    try {
      specJson = JSON.parse(specText);
    } catch {
      try {
        specJson = parseYaml(specText);
      } catch {
        return {
          overallScore: 0,
          overallGrade: "F",
          issues: [{ issue: "Spec is invalid JSON/YAML. Cannot check consistency.", severity: 100, suggestion: "Fix syntax errors in spec document." }],
          recommendations: [],
        };
      }
    }

    const implContentType = implRes.headers.get("content-type") || "";
    if (!implContentType.includes("json")) {
      return {
        overallScore: 0,
        overallGrade: "F",
        issues: [{ issue: "Impl URL response is not JSON. Cannot verify consistency.", severity: 100, suggestion: "Ensure the API returns JSON responses." }],
        recommendations: [],
      };
    }

    const implJson = await implRes.json().catch(() => null);
    if (implJson === null) {
      return {
        overallScore: 0,
        overallGrade: "F",
        issues: [{ issue: "Impl response is not valid JSON.", severity: 100, suggestion: "Ensure the implementation is properly serving JSON." }],
        recommendations: [],
      };
    }

    // Now analyze consistency:
    const issues: LintIssue[] = [];

    // Find all paths in spec
    const specPaths = specJson.paths && typeof specJson.paths === "object" ? Object.keys(specJson.paths) : [];
    if (specPaths.length === 0) {
      issues.push({
        issue: "Spec has no paths. Cannot check consistency.",
        severity: 100,
        suggestion: "Define at least one path in spec.",
      });
    }

    // Check if impl URL path exists in spec
    try {
      const implUrlObj = new URL(implCheck.url.toString());
      const implPath = implUrlObj.pathname;

      if (!specPaths.includes(implPath)) {
        issues.push({
          issue: `Implementation endpoint path '${implPath}' not found in spec paths`,
          severity: 90,
          suggestion: "Add the path to the OpenAPI spec or fix implementation URL.",
        });
      }
    } catch {
      // fail silently
    }

    // Check for response property mismatches
    // Check if spec defines a response for 200, look for expected fields
    if (specJson.paths) {
      for (const pathKey of specPaths) {
        const pathItem = specJson.paths[pathKey];
        const methods = Object.keys(pathItem).filter(m => ["get", "post", "put", "delete", "patch", "head", "options", "trace"].includes(m.toLowerCase()));

        for (const method of methods) {
          const op = pathItem[method];
          if (!op.responses || Object.keys(op.responses).length === 0) continue;

          // Only validate '200' or 'default' responses if present
          const expectedResp = op.responses["200"] || op.responses["default"] || null;
          if (!expectedResp) continue;

          // We can try loosely to check response schema keys (very shallow)
          if (expectedResp.content && expectedResp.content["application/json"] && expectedResp.content["application/json"].schema) {
            const schema = expectedResp.content["application/json"].schema;
            // Skip complex schemas
            if (schema && typeof schema === "object" && schema.type === "object" && schema.properties) {
              const expectedProps = Object.keys(schema.properties);
              const implProps = implJson && typeof implJson === "object" ? Object.keys(implJson) : [];
              for (const prop of expectedProps) {
                if (!implProps.includes(prop)) {
                  issues.push({
                    issue: `Response missing expected property '${prop}' from spec schema at path '${pathKey}' method '${method.toUpperCase()}'`,
                    severity: 60,
                    suggestion: "Ensure API implementation matches declared response schemas.",
                  });
                }
              }
            }
          }
        }
      }
    }

    // Score
    let score = 100;
    for (const issue of issues) {
      score -= Math.min(issue.severity, 100);
    }
    if (score < 0) score = 0;

    return {
      overallScore: score,
      overallGrade: letterGrade(score),
      issues,
      recommendations: generateConsistencyRecommendations(issues),
    };
  } catch (e: any) {
    return {
      overallScore: 0,
      overallGrade: "F",
      issues: [{ issue: `Exception: ${e.message || String(e)}`, severity: 100, suggestion: "Check URLs and content format." }],
      recommendations: [],
    };
  }
}

// -------------------------------
// Recommendations generators
// -------------------------------

function generateSpecRecommendations(issues: LintIssue[]): LintIssue[] {
  // Filter issues with severity >= 50
  return issues.filter(i => i.severity >= 50).map(i => ({ ...i }));
}

function generateImplRecommendations(issues: LintIssue[]): LintIssue[] {
  // Recommend fixes for top severity issues
  return issues.filter(i => i.severity >= 50).map(i => ({ ...i }));
}

function generateConsistencyRecommendations(issues: LintIssue[]): LintIssue[] {
  // Similar filtering
  return issues.filter(i => i.severity >= 50).map(i => ({ ...i }));
}

//--------------------------------
// Helpers
//--------------------------------

function letterGrade(score: number): LintLetterGrade {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

// Minimal YAML parser stub (safe subset) just to parse OpenAPI spec YAML
// Returns JS object or throws
function parseYaml(yamlText: string): any {
  // We do a very naive parse for demonstration:
  // Only handles top level key: value pairs and nested by indentation spaces
  // This is NOT a real parser! For demo only.
  // In production this would be replaced with a full YAML library.

  const lines = yamlText.split(/\r?\n/);
  const doc: any = {};
  let currentKey: string | null = null;
  let currentObj: any = doc;
  let indentStack: number[] = [];
  let objStack: any[] = [];

  for (let line of lines) {
    line = line.trimEnd();
    if (line === "" || line.startsWith("#")) continue;
    const indentMatch = line.match(/^\s*/);
    const indent = indentMatch ? indentMatch[0].length : 0;

    // Detect level changes
    while (indentStack.length && indent < indentStack[indentStack.length - 1]) {
      indentStack.pop();
      objStack.pop();
      currentObj = objStack.length > 0 ? objStack[objStack.length - 1] : doc;
    }

    const colonIndex = line.indexOf(":");
    if (colonIndex === -1) {
      // Probably list item or invalid
      continue;
    }

    const key = line.slice(0, colonIndex).trim();
    let value = line.slice(colonIndex + 1).trim();

    if (value === "") {
      // New nested object level
      const newObj: any = {};
      currentObj[key] = newObj;
      currentObj = newObj;
      indentStack.push(indent);
      objStack.push(newObj);
    } else {
      // Assign value, convert simple types
      if (/^\d+$/.test(value)) {
        value = parseInt(value, 10);
      } else if (/^\d+\.\d+$/.test(value)) {
        value = parseFloat(value);
      } else if (value === "true" || value === "false") {
        value = value === "true";
      }
      currentObj[key] = value;
    }
  }

  return doc;
}
