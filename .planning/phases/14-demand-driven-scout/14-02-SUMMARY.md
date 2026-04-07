---
phase: 14-demand-driven-scout
plan: 02
subsystem: brain, scoring
tags: [demand-scoring, theme-week, model-escalation, scout-integration]

# Dependency graph
requires:
  - phase: 14-demand-driven-scout
    plan: 01
    provides: demand data source modules and backlog schema extensions
provides:
  - Weighted scoring formula preferring measured demand over LLM estimates
  - Theme week configuration system with date-bounded category focus
  - Model escalation for high-scoring backlog items (gpt-4.1)
  - Full demand source integration in scout pipeline
affects: [brain daily cron, API quality via model escalation]

# Tech tracking
tech-stack:
  added: []
  patterns: [weighted scoring with fallback weights, async config loading via Bun.file, model escalation with daily cap]

key-files:
  created:
    - scripts/brain/demand/scoring.ts
    - scripts/brain/demand/scoring.test.ts
    - scripts/brain/scout-config.ts
    - scripts/brain/scout-config.test.ts
    - scripts/brain/build.test.ts
    - data/scout-config.json
  modified:
    - scripts/brain/scout.ts
    - scripts/brain/build.ts

key-decisions:
  - "Measured demand weight 0.25 vs LLM demand 0.10 when both available; LLM rises to 0.20 when no measured data"
  - "Daily escalation cap of 1 gpt-4.1 build per day to control costs"
  - "Theme week config requires end_date to prevent permanent category lock-in"
  - "Autocomplete fallback scales suggestion count by 100x for normalization compatibility"

patterns-established:
  - "async loadScoutConfig using Bun.file (not readFileSync) per CLAUDE.md conventions"
  - "Model escalation via env var override (SCOUT_ESCALATION_MODEL)"

requirements-completed: [DEMAND-04, DEMAND-05, DEMAND-07]

# Metrics
duration: 5min
completed: 2026-04-07
---

# Phase 14 Plan 02: Demand-Aware Scoring and Integration Summary

**Weighted scoring formula with measured demand preference, theme week configuration, and gpt-4.1 model escalation for high-scoring API builds**

## Performance

- **Duration:** 5 min
- **Started:** 2026-04-07T23:12:50Z
- **Completed:** 2026-04-07T23:17:38Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments
- Created scoring module with weighted formula that gives measured demand (0.25) higher weight than LLM estimates (0.10)
- Built theme week configuration system with JSON config, async Bun.file loader, and date validation
- Integrated all 5 demand data sources into scout.ts signal gathering (RapidAPI, Dev.to, competitors) and scoring (DataForSEO, autocomplete)
- Added model escalation in build.ts: items scoring above 7.5 get gpt-4.1 instead of gpt-4.1-mini
- Daily escalation cap prevents cost overruns (max 1 gpt-4.1 build/day)
- 20 tests passing across scoring, config, and build escalation

## Task Commits

Each task was committed atomically:

1. **Task 1: Create scoring module and theme week config** - `a3e599e` (test RED), `9e6d20c` (feat GREEN)
2. **Task 2: Integrate demand sources into scout.ts and model escalation in build.ts** - `a926284` (feat)

## Files Created/Modified
- `scripts/brain/demand/scoring.ts` - computeOverallScore and normalizeDemandSignal with weighted formula
- `scripts/brain/demand/scoring.test.ts` - 10 tests for scoring weights and normalization
- `scripts/brain/scout-config.ts` - async loadScoutConfig and isThemeWeekActive with date validation
- `scripts/brain/scout-config.test.ts` - 6 tests for config loading and theme week logic
- `scripts/brain/build.test.ts` - 4 tests for model escalation threshold and env override
- `data/scout-config.json` - Theme week and demand source configuration
- `scripts/brain/scout.ts` - Added 7 imports, gatherDemandData, signals 5-7, theme week prompt, demand re-scoring
- `scripts/brain/build.ts` - ESCALATION_MODEL/THRESHOLD constants, model escalation with daily cap, db import

## Decisions Made
- Measured demand weight 0.25 vs LLM demand 0.10; LLM fallback to 0.20 when no measured data
- Daily escalation cap of 1 gpt-4.1 build/day to control OpenAI costs
- Theme week config requires end_date to prevent permanent category lock-in
- Autocomplete fallback multiplies suggestion count by 100 for normalization compatibility

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed CONFIG_PATH in scout-config.ts**
- **Found during:** Task 1
- **Issue:** Plan template had `join(import.meta.dir, "..", "data", ...)` which resolves to `scripts/data/` instead of project root `data/`
- **Fix:** Changed to `join(import.meta.dir, "..", "..", "data", "scout-config.json")` for correct path resolution
- **Files modified:** scripts/brain/scout-config.ts

**2. [Rule 2 - Critical] Made loadScoutConfig async per CLAUDE.md**
- **Found during:** Task 1
- **Issue:** Plan template used `require("fs").readFileSync` which violates CLAUDE.md directive to use Bun.file over node:fs
- **Fix:** Used async `Bun.file(CONFIG_PATH).text()` and made loadScoutConfig return `Promise<ScoutConfig>`
- **Files modified:** scripts/brain/scout-config.ts, scripts/brain/scout.ts (await calls)

## Known Stubs

None - all data sources are wired end-to-end.

## Self-Check: PASSED

All 9 files verified on disk. All 3 task commits (a3e599e, 9e6d20c, a926284) verified in git log.

---
*Phase: 14-demand-driven-scout*
*Completed: 2026-04-07*
