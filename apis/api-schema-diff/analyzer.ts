import {
  safeFetch,
  validateExternalUrl,
} from "../../shared/ssrf";

// TypeScript types
export interface SchemaVersion {
  url: string;
  version: string;
}

export type SchemaType = "REST" | "GraphQL" | "Unknown";

export interface VersionSchemaData {
  raw: any; // Parsed JSON schema
  // Possible extension for typed schema data
}

export interface DifferenceSummary {
  added: number;
  removed: number;
  changed: number;
}

export interface Recommendation {
  issue: string;
  severity: number; // 0-100
  suggestion: string;
}

export interface DiffDetails {
  // Detailed structured difference info between schemas
  [key: string]: any;
}

export interface SchemaDiffResponse {
  comparedVersions: string[]; // List of version labels compared
  type: SchemaType;
  differencesSummary: DifferenceSummary;
  score: number; // 0-100 compatibility score
  grade: string; // A-F
  recommendations: Recommendation[];
  details: DiffDetails;
}

/**
 * API info documentation type
 */
export interface InfoDoc {
  api: string;
  status: string;
  version: string;
  docs: {
    endpoints: Array<{
      method: string;
      path: string;
      description: string;
      parameters: Array<{ name: string; in?: string; schema?: any; description: string }>;
      exampleResponse?: any;
    }>;
    parameters: Array<{ name: string; description: string }>;
    examples: Array<{ description: string; method: string; path: string; body?: any }>;
  };
  pricing: {
    type: string;
    price: string;
  };
}

// --- Internal helpers ---

function getSchemaType(schemaJson: any): SchemaType {
  // Distinguish between REST OpenAPI and GraphQL introspection
  if (!schemaJson || typeof schemaJson !== "object") return "Unknown";
  // Heuristics for OpenAPI
  if (
    (typeof schemaJson.openapi === "string" && schemaJson.openapi.startsWith("3.")) ||
    schemaJson.swagger === "2.0"
  ) {
    return "REST";
  }

  // Heuristics for GraphQL Introspection
  if (schemaJson.__schema && schemaJson.__schema.types) {
    return "GraphQL";
  }

  return "Unknown";
}

interface RESTPathObject {
  [path: string]: {
    [method: string]: any;
  };
}

interface RESTSchema {
  paths: RESTPathObject;
  components?: any;
}

interface GraphQLType {
  kind: string;
  name: string;
  description?: string | null;
  fields?: any[];
  inputFields?: any[];
  interfaces?: any[];
  enumValues?: any[];
  possibleTypes?: any[];
}

interface GraphQLSchema {
  __schema: {
    types: GraphQLType[];
    queryType: { name: string };
    mutationType?: { name: string };
    subscriptionType?: { name: string };
    directives: any[];
  };
}

// ------- Diff utils --------

/**
 * Deep compare two objects with max depth
 */
function deepDiff(
  a: any,
  b: any,
  maxDepth = 5,
  depth = 0
): { added: number; removed: number; changed: number; details: any } {
  if (depth > maxDepth) {
    return { added: 0, removed: 0, changed: 0, details: null };
  }

  if (a === b) {
    return { added: 0, removed: 0, changed: 0, details: null };
  }

  if ((typeof a !== "object" && typeof b !== "object") || a === null || b === null) {
    // Primitive mismatch
    return { added: 0, removed: 0, changed: 1, details: { from: a, to: b } };
  }

  const additions = new Set<string>();
  const removals = new Set<string>();
  const changes: Record<string, any> = {};

  const aKeys = a ? Object.keys(a) : [];
  const bKeys = b ? Object.keys(b) : [];

  for (const key of bKeys) {
    if (!aKeys.includes(key)) {
      additions.add(key);
    }
  }
  for (const key of aKeys) {
    if (!bKeys.includes(key)) {
      removals.add(key);
    }
  }

  let changed = 0;
  for (const key of aKeys) {
    if (bKeys.includes(key)) {
      const diff = deepDiff(a[key], b[key], maxDepth, depth + 1);
      if (diff.changed > 0 || diff.added > 0 || diff.removed > 0) {
        changed++;
        changes[key] = diff.details;
      }
    }
  }

  return {
    added: additions.size,
    removed: removals.size,
    changed,
    details: {
      added: Array.from(additions),
      removed: Array.from(removals),
      changed: changes,
    },
  };
}

// --- REST Schema Analysis ---

function analyzeRestPaths(paths1: RESTPathObject, paths2: RESTPathObject): DifferenceSummary & { details: any } {
  const addedEndpoints: string[] = [];
  const removedEndpoints: string[] = [];
  const changedEndpoints: string[] = [];
  const changesDetails: Record<string, any> = {};

  const allPaths = new Set([...Object.keys(paths1), ...Object.keys(paths2)]);

  for (const path of allPaths) {
    const methods1 = paths1[path] || {};
    const methods2 = paths2[path] || {};

    const allMethods = new Set([...Object.keys(methods1), ...Object.keys(methods2)]);

    for (const method of allMethods) {
      const endpointKey = `${method.toUpperCase()} ${path}`;
      const method1 = methods1[method];
      const method2 = methods2[method];
      if (!method1 && method2) {
        addedEndpoints.push(endpointKey);
        changesDetails[endpointKey] = { changeType: "added" };
      } else if (method1 && !method2) {
        removedEndpoints.push(endpointKey);
        changesDetails[endpointKey] = { changeType: "removed" };
      } else if (method1 && method2) {
        // Compare operation objects deeply with limited depth
        const diff = deepDiff(method1, method2, 6);
        if (diff.added > 0 || diff.removed > 0 || diff.changed > 0) {
          changedEndpoints.push(endpointKey);
          changesDetails[endpointKey] = diff.details;
        }
      }
    }
  }

  return {
    added: addedEndpoints.length,
    removed: removedEndpoints.length,
    changed: changedEndpoints.length,
    details: {
      addedEndpoints,
      removedEndpoints,
      changedEndpoints,
      changesDetails,
    },
  };
}

// --- GraphQL Schema Analysis ---

interface GraphQLTypeMap {
  [name: string]: GraphQLType;
}

function mapGraphQLTypes(types: GraphQLType[]): GraphQLTypeMap {
  const map: GraphQLTypeMap = {};
  for (const t of types) {
    if (t.name) {
      map[t.name] = t;
    }
  }
  return map;
}

function compareGraphQLFields(
  fieldsA: any[] | undefined,
  fieldsB: any[] | undefined
): DifferenceSummary {
  if (!fieldsA && !fieldsB) return { added: 0, removed: 0, changed: 0 };
  if (!fieldsA) return { added: fieldsB!.length, removed: 0, changed: 0 };
  if (!fieldsB) return { added: 0, removed: fieldsA.length, changed: 0 };

  const namesA = new Set(fieldsA.map((f) => f.name));
  const namesB = new Set(fieldsB.map((f) => f.name));

  let added = 0;
  let removed = 0;
  let changed = 0;

  for (const bName of namesB) {
    if (!namesA.has(bName)) added++;
  }

  for (const aName of namesA) {
    if (!namesB.has(aName)) removed++;
  }

  // For fields existing in both, compare types and args
  for (const name of namesA) {
    if (namesB.has(name)) {
      const fA = fieldsA.find((f) => f.name === name)!;
      const fB = fieldsB.find((f) => f.name === name)!;
      if (JSON.stringify(fA.type) !== JSON.stringify(fB.type)) {
        changed++;
      } else {
        // Could compare arguments etc. but keep shallow
        // Could do deeper changes here if needed
      }
    }
  }

  return { added, removed, changed };
}

function analyzeGraphQLSchemas(schemaA: GraphQLSchema, schemaB: GraphQLSchema): DifferenceSummary & { details: any } {
  const typesA = schemaA.__schema.types;
  const typesB = schemaB.__schema.types;
  const mapA = mapGraphQLTypes(typesA);
  const mapB = mapGraphQLTypes(typesB);

  const namesA = new Set(Object.keys(mapA));
  const namesB = new Set(Object.keys(mapB));

  const addedTypes: string[] = [];
  const removedTypes: string[] = [];
  const changedTypes: string[] = [];
  const changeInfos: Record<string, any> = {};

  for (const name of namesB) {
    if (!namesA.has(name)) {
      addedTypes.push(name);
    }
  }

  for (const name of namesA) {
    if (!namesB.has(name)) {
      removedTypes.push(name);
    }
  }

  for (const name of namesA) {
    if (namesB.has(name)) {
      const typeA = mapA[name];
      const typeB = mapB[name];
      if (typeA.kind !== typeB.kind) {
        changedTypes.push(name);
        changeInfos[name] = { issue: "Kind changed", from: typeA.kind, to: typeB.kind };
        continue;
      }

      // Compare fields for OBJECT and INTERFACE
      if (typeA.fields || typeB.fields) {
        const diff = compareGraphQLFields(typeA.fields, typeB.fields);
        if (diff.added > 0 || diff.removed > 0 || diff.changed > 0) {
          changedTypes.push(name);
          changeInfos[name] = { fieldsDiff: diff };
          continue;
        }
      }

      // Could add deeper comparisons for inputs, enums etc.
    }
  }

  return {
    added: addedTypes.length,
    removed: removedTypes.length,
    changed: changedTypes.length,
    details: {
      addedTypes,
      removedTypes,
      changedTypes,
      changesDetail: changeInfos,
    },
  };
}

// --- Scoring/Grading ---

function computeScore(added: number, removed: number, changed: number): number {
  // Weighted scoring logic
  // Removing endpoints/types is more severe (breaking)
  // Adding is less severe
  // Changes moderate
  // Example: start at 100, subtract appropriately

  let score = 100;
  score -= removed * 20; // heavy penalty for removals
  score -= changed * 10; // medium for changes
  score -= added * 5; // small for additions
  if (score < 0) score = 0;
  return score;
}

function letterGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 50) return "D";
  return "F";
}

function generateRecommendations(
  summary: DifferenceSummary,
  type: SchemaType
): Recommendation[] {
  const recs: Recommendation[] = [];

  if (summary.removed > 0) {
    recs.push({
      issue: "Removed endpoints or types",
      severity: 90,
      suggestion: "Review removed items for breaking changes. Deprecate gradually or provide backward compatibility.",
    });
  }
  if (summary.changed > 0) {
    recs.push({
      issue: "Changed schema elements",
      severity: 70,
      suggestion: "Check compatibility of changes; update clients and document changed fields or endpoints.",
    });
  }
  if (summary.added > 0) {
    recs.push({
      issue: "Added endpoints or types",
      severity: 20,
      suggestion: "Communicate new features clearly; maintain versioning semantics.",
    });
  }
  if (type === "Unknown") {
    recs.push({
      issue: "Unrecognized schema type",
      severity: 50,
      suggestion: "Ensure schema is OpenAPI or GraphQL Introspection format.",
    });
  }

  if (recs.length === 0) {
    recs.push({
      issue: "No breaking changes detected",
      severity: 0,
      suggestion: "Ready for smooth upgrade; continue good versioning practice.",
    });
  }

  return recs;
}

// --- Exported analysis function ---

/**
 * schemaDiffAnalysis runs comprehensive comparison of multiple API schemas
 * @param versions - array of schema version descriptors (urls and labels)
 * @param schemasJson - array of parsed JSON schema data matching versions order
 * @returns comprehensive diff structured result
 */
export async function schemaDiffAnalysis(
  versions: SchemaVersion[],
  schemasJson: any[]
): Promise<SchemaDiffResponse> {
  // Determine schema type by the first schema (assume homogeneous set)
  const type = getSchemaType(schemasJson[0]);

  let diffSummary: DifferenceSummary = { added: 0, removed: 0, changed: 0 };
  let diffDetails: any = {};

  if (type === "REST") {
    // Merge all versions pairwise
    let aggregatedSummary: DifferenceSummary = { added: 0, removed: 0, changed: 0 };
    const detailsPerPair: any[] = [];

    for (let i = 0; i < schemasJson.length - 1; i++) {
      const a = schemasJson[i];
      const b = schemasJson[i + 1];
      // Defensive: verify paths
      if (!a.paths || !b.paths) {
        return {
          comparedVersions: versions.map((v) => v.version),
          type,
          differencesSummary: { added: 0, removed: 0, changed: 0 },
          score: 0,
          grade: "F",
          recommendations: [
            {
              issue: "Invalid schema structure",
              severity: 100,
              suggestion: "Ensure each schema has valid OpenAPI 'paths' property.",
            },
          ],
          details: {},
        };
      }
      const diff = analyzeRestPaths(a.paths, b.paths);
      aggregatedSummary.added += diff.added;
      aggregatedSummary.removed += diff.removed;
      aggregatedSummary.changed += diff.changed;
      detailsPerPair.push({ from: versions[i].version, to: versions[i + 1].version, diff });
    }

    diffSummary = aggregatedSummary;
    diffDetails = { pairwiseDiffs: detailsPerPair };
  } else if (type === "GraphQL") {
    // Analyze pairwise differences
    let aggregatedSummary: DifferenceSummary = { added: 0, removed: 0, changed: 0 };
    const detailsPerPair: any[] = [];

    for (let i = 0; i < schemasJson.length - 1; i++) {
      const a = schemasJson[i] as GraphQLSchema;
      const b = schemasJson[i + 1] as GraphQLSchema;
      if (!a.__schema || !b.__schema) {
        return {
          comparedVersions: versions.map((v) => v.version),
          type,
          differencesSummary: { added: 0, removed: 0, changed: 0 },
          score: 0,
          grade: "F",
          recommendations: [
            {
              issue: "Invalid schema structure",
              severity: 100,
              suggestion:
                "Ensure each schema conforms to GraphQL Introspection Query result format.",
            },
          ],
          details: {},
        };
      }
      const diff = analyzeGraphQLSchemas(a, b);
      aggregatedSummary.added += diff.added;
      aggregatedSummary.removed += diff.removed;
      aggregatedSummary.changed += diff.changed;
      detailsPerPair.push({ from: versions[i].version, to: versions[i + 1].version, diff });
    }

    diffSummary = aggregatedSummary;
    diffDetails = { pairwiseDiffs: detailsPerPair };
  } else {
    // Unknown schema type: cannot compare
    return {
      comparedVersions: versions.map((v) => v.version),
      type,
      differencesSummary: { added: 0, removed: 0, changed: 0 },
      score: 0,
      grade: "F",
      recommendations: [
        {
          issue: "Unrecognized schema",
          severity: 100,
          suggestion: "Schema is neither OpenAPI 3.x Swagger nor GraphQL introspection. Provide valid schema.",
        },
      ],
      details: {},
    };
  }

  const score = computeScore(diffSummary.added, diffSummary.removed, diffSummary.changed);
  const grade = letterGrade(score);
  const recommendations = generateRecommendations(diffSummary, type);

  return {
    comparedVersions: versions.map((v) => v.version),
    type,
    differencesSummary: diffSummary,
    score,
    grade,
    recommendations,
    details: diffDetails,
  };
}
