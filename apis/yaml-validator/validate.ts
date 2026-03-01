// validate.ts: Safe YAML parse+validate using js-yaml (Bun built-in)
// No schema enforcement (user gets AST JSON or errors)

// Types for return output
type Output = {
  valid: true;
  parsed: unknown;
  errors?: undefined;
  warning?: string;
} | {
  valid: false;
  errors: { line?: number; column?: number; message: string }[];
  parsed?: undefined;
};

// Defensive max length for YAML strings (protect crash/payload)
const MAX_YAML_LENGTH = 64 * 1024; // 64KB

// Use Bun's js-yaml (see https://bun.sh/docs/runtime/yaml)
export function validateYaml(yamlSource: string): Output {
  if (typeof yamlSource !== "string" || yamlSource.length === 0) {
    return { valid: false, errors: [{ message: "Blank YAML input" }] };
  }
  if (yamlSource.length > MAX_YAML_LENGTH) {
    return {
      valid: false,
      errors: [{ message: `YAML input exceeds max allowed size (${MAX_YAML_LENGTH} bytes)` }],
    };
  }

  try {
    // Bun's YAML.parse throws on error
    // It supports single doc (no YAML.loadAll). We'll expose only parse.
    // Parse and return AST JSON
    const parsed = YAML.parse(yamlSource);
    // Sometimes parse returns undefined/null for blank input
    if (parsed === undefined || parsed === null) {
      return { valid: false, errors: [{ message: "YAML parsed as null/undefined (empty)" }] };
    }
    // Accept all objects/arrays/scalars
    return { valid: true, parsed };
  } catch (err: any) {
    // js-yaml/Bun error messages often have mark (line/col)
    const errors: { line?: number; column?: number; message: string }[] = [];
    if (err && typeof err === "object" && "mark" in err) {
      const mark = (err as any).mark;
      errors.push({
        line: mark?.line !== undefined ? mark.line + 1 : undefined,
        column: mark?.column !== undefined ? mark.column + 1 : undefined,
        message: String(err.message) || "YAML parse error"
      });
    } else {
      errors.push({ message: String(err?.message || err || "Parse error") });
    }
    return { valid: false, errors };
  }
}
