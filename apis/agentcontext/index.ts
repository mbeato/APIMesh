import { Hono } from "hono";
import { cors } from "hono/cors";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { rateLimit } from "../../shared/rate-limit";
import { apiLogger } from "../../shared/logger";

import {
  parseAgentsMd,
  parseClaudeMd,
  parseGeminiMd,
  parseCursorMdc,
  parseCursorLegacy,
  parseWindsurfMdc,
  parseWindsurfLegacy,
  parseClineFile,
  parseConventionsMd,
  renderAgentsMd,
  renderClaudeMd,
  renderGeminiMd,
  renderCursorMdc,
  renderWindsurfMdc,
  renderClineDir,
  renderConventionsMd,
  type Bundle,
  type SourceFormat,
  type TargetFormat,
  emptyBundle,
} from "@mbeato/agentcontext";

const app = new Hono();
const API_NAME = "agentcontext";

// Cache the landing page once.
const LANDING_HTML = readFileSync(resolve(import.meta.dir, "landing.html"), "utf8");

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET", "POST", "OPTIONS"],
  allowHeaders: ["Content-Type"],
}));

app.get("/health", (c) => c.json({ status: "ok" }));

// Subdomain canonicalization: agentcontext.apimesh.xyz → 301 → agentsmd.apimesh.xyz
app.use("*", async (c, next) => {
  const host = c.req.header("host") ?? "";
  const hostname = host.split(":")[0]!;
  if (hostname === "agentcontext.apimesh.xyz") {
    const url = new URL(c.req.url);
    url.host = "agentsmd.apimesh.xyz";
    return c.redirect(url.toString(), 301);
  }
  return next();
});

app.use("*", rateLimit("agentcontext", 60, 60_000));
app.use("/normalize", rateLimit("agentcontext-normalize", 30, 60_000));
app.use("*", apiLogger(API_NAME, 0));

// Landing page (single HTML, embedded inline form for /normalize).
app.get("/", (c) => c.html(LANDING_HTML));

// Free conversion endpoint. Accepts source content + format, returns rendered file map.
// No auth — rate-limited only. Cap input size to prevent abuse.
const MAX_INPUT_CHARS = 100_000;

app.post("/normalize", async (c) => {
  let body: {
    source_format?: SourceFormat;
    content?: string;
    targets?: TargetFormat[];
    options?: { split_nested?: boolean };
  };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "invalid JSON body" }, 400);
  }
  if (!body.source_format) return c.json({ error: "source_format required" }, 400);
  if (typeof body.content !== "string") return c.json({ error: "content (string) required" }, 400);
  if (body.content.length > MAX_INPUT_CHARS) {
    return c.json({ error: `content exceeds ${MAX_INPUT_CHARS} chars` }, 413);
  }
  const targets = Array.isArray(body.targets) && body.targets.length > 0
    ? body.targets
    : (["agents-md"] as TargetFormat[]);

  const bundle = emptyBundle();
  try {
    const sub = await parseByFormat(body.source_format, body.content);
    bundle.rules.push(...sub.rules);
    for (const w of sub.warnings) bundle.warnings.push(w);
    if (sub.config_extras.aider_conf) bundle.config_extras.aider_conf = sub.config_extras.aider_conf;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return c.json({ error: `parse failed: ${msg}` }, 400);
  }

  const files: Record<string, string> = {};
  const warnings: string[] = [...bundle.warnings];
  for (const t of targets) {
    try {
      const out = renderByTarget(bundle, t);
      Object.assign(files, out.files);
      for (const w of out.warnings) warnings.push(w);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return c.json({ error: `render(${t}) failed: ${msg}` }, 400);
    }
  }
  return c.json({ files, warnings, detected_formats: bundle.detected_formats });
});

async function parseByFormat(format: SourceFormat, content: string): Promise<Bundle> {
  switch (format) {
    case "agents-md":
      return parseAgentsMd({ path: "AGENTS.md", content });
    case "claude-md":
      return parseClaudeMd({ path: "CLAUDE.md", content });
    case "gemini-md":
      return parseGeminiMd({ path: "GEMINI.md", content });
    case "cursor-mdc":
      return parseCursorMdc({ path: ".cursor/rules/x.mdc", content });
    case "cursor-legacy":
      return parseCursorLegacy({ path: ".cursorrules", content });
    case "windsurf-mdc":
      return parseWindsurfMdc({ path: ".windsurf/rules/x.md", content });
    case "windsurf-legacy":
      return parseWindsurfLegacy({ path: ".windsurfrules", content });
    case "cline-file":
      return parseClineFile({ path: ".clinerules", content });
    case "cline-dir":
      throw new Error("cline-dir requires a directory; use the CLI 'sync' verb locally");
    case "conventions-md":
      return parseConventionsMd({ path: "CONVENTIONS.md", content });
  }
}

function renderByTarget(bundle: Bundle, target: TargetFormat) {
  switch (target) {
    case "agents-md":
      return renderAgentsMd(bundle);
    case "claude-md":
      return renderClaudeMd(bundle);
    case "gemini-md":
      return renderGeminiMd(bundle);
    case "cursor-mdc":
      return renderCursorMdc(bundle);
    case "windsurf-mdc":
      return renderWindsurfMdc(bundle);
    case "cline-dir":
      return renderClineDir(bundle);
    case "conventions-md": {
      const r = renderConventionsMd(bundle);
      return { files: r.files, warnings: r.warnings };
    }
  }
}

export { app };
