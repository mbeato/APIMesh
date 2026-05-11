import type { Hono } from "hono";
import { app as agentcontext } from "./agentcontext/index";
import { app as sigdebug } from "./sigdebug/index";

// Post-pivot registry (2026-05). 100 marketplace-era APIs retired here.
// See apis/RETIRED.md for what was built + the archive branch
// archive/marketplace-2026-04-pre-prune for the full pre-prune snapshot.
// Each surviving entry maps a subdomain to a Hono sub-app. Aliases let a
// single app respond to multiple subdomains (e.g. agentsmd + agentcontext).
export const registry: Record<string, Hono> = {
  "agentsmd":     agentcontext,
  "agentcontext": agentcontext,
  "stripesig":    sigdebug,
  "sigdebug":     sigdebug,
};
