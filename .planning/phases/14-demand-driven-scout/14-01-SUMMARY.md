---
phase: 14-demand-driven-scout
plan: 01
subsystem: database, api
tags: [dataforseo, google-autocomplete, rapidapi, devto, sqlite, demand-signals]

# Dependency graph
requires:
  - phase: 13-legal-compliance
    provides: stable backlog schema with saturation_score
provides:
  - DataForSEO keyword volume client
  - Google Autocomplete fallback for search suggestions
  - RapidAPI marketplace demand signal scraper
  - Competitor gap analysis registry (5 competitors)
  - Dev.to engagement signal collector with category interest aggregation
  - Backlog schema extended with 5 demand columns
affects: [14-02 scoring integration, scout.ts demand-aware scoring]

# Tech tracking
tech-stack:
  added: []
  patterns: [demand data source modules with graceful fallback, env-gated API clients]

key-files:
  created:
    - scripts/brain/demand/dataforseo.ts
    - scripts/brain/demand/autocomplete.ts
    - scripts/brain/demand/rapidapi.ts
    - scripts/brain/demand/competitors.ts
    - scripts/brain/demand/devto-feedback.ts
    - scripts/brain/demand/dataforseo.test.ts
    - scripts/brain/demand/autocomplete.test.ts
    - scripts/brain/demand/rapidapi.test.ts
    - scripts/brain/demand/competitors.test.ts
    - scripts/brain/demand/devto-feedback.test.ts
    - data/migrations/008_demand_columns.sql
    - shared/db-demand.test.ts
  modified:
    - shared/db.ts

key-decisions:
  - "Env-gated API clients: DataForSEO and Dev.to modules return empty arrays when credentials are absent rather than throwing"
  - "RapidAPI HTML scraping with /hub/ link fallback: primary card markers may be JS-rendered, so we count hub links as fallback"
  - "Static competitor registry: no API calls, manually maintained, returns defensive copy"

patterns-established:
  - "Demand source pattern: each module exports typed interface + async getter, returns empty/null on failure"
  - "insertBacklogItem backward compatibility: new demandData param is optional, existing 7-arg callers unaffected"

requirements-completed: [DEMAND-01, DEMAND-02, DEMAND-03, DEMAND-06]

# Metrics
duration: 5min
completed: 2026-04-07
---

# Phase 14 Plan 01: Demand Data Sources Summary

**Five demand signal modules (DataForSEO, Google Autocomplete, RapidAPI, competitor gaps, Dev.to engagement) with backlog schema extended for measured demand storage**

## Performance

- **Duration:** 5 min
- **Started:** 2026-04-07T23:02:14Z
- **Completed:** 2026-04-07T23:06:55Z
- **Tasks:** 2
- **Files modified:** 13

## Accomplishments
- Created 5 demand data source modules with typed exports and graceful error handling
- Extended backlog schema with 5 new demand columns (search_volume, marketplace_listings, measured_demand_score, demand_source, category)
- 24 tests passing covering all modules including mock fetch, env var checks, and round-trip DB operations
- Backward-compatible insertBacklogItem -- existing scout.ts callers unaffected

## Task Commits

Each task was committed atomically:

1. **Task 1: Create demand data source modules with tests** - `80f734d` (feat)
2. **Task 2: Extend backlog DB schema and update shared/db.ts** - `2eadbb2` (feat)

## Files Created/Modified
- `scripts/brain/demand/dataforseo.ts` - DataForSEO keyword volume client with Basic auth
- `scripts/brain/demand/autocomplete.ts` - Google Autocomplete fallback for search suggestions
- `scripts/brain/demand/rapidapi.ts` - RapidAPI marketplace demand signal scraper
- `scripts/brain/demand/competitors.ts` - Static competitor gap analysis registry (5 competitors)
- `scripts/brain/demand/devto-feedback.ts` - Dev.to engagement signal collector with category interest
- `scripts/brain/demand/dataforseo.test.ts` - 5 tests for DataForSEO client
- `scripts/brain/demand/autocomplete.test.ts` - 4 tests for autocomplete
- `scripts/brain/demand/rapidapi.test.ts` - 3 tests for RapidAPI scraper
- `scripts/brain/demand/competitors.test.ts` - 4 tests for competitor registry
- `scripts/brain/demand/devto-feedback.test.ts` - 4 tests for Dev.to engagement
- `data/migrations/008_demand_columns.sql` - 5 ALTER TABLE statements for demand columns
- `shared/db-demand.test.ts` - 4 tests for demand column round-trip
- `shared/db.ts` - Extended BacklogItem interface and insertBacklogItem with demandData param

## Decisions Made
- Env-gated API clients return empty results when credentials are missing (not errors)
- RapidAPI uses HTML scraping with /hub/ link fallback since search results may be JS-rendered
- Static competitor registry maintained manually (no external API dependency)
- insertBacklogItem uses optional trailing demandData parameter for backward compatibility

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- In-memory SQLite test databases don't have `saturation_score` column because migration 006 is a no-op and the pre-migration hook in migrate.ts only adds it to pre-existing tables. Worked around in db-demand.test.ts by conditionally adding the column after migrations run. This is a pre-existing issue in the test infrastructure, not caused by this plan.

## User Setup Required

None - no external service configuration required. DataForSEO and Dev.to modules gracefully skip when credentials are absent.

## Next Phase Readiness
- All 5 demand data source modules ready for Plan 02 scoring integration
- Backlog schema extended and tested for demand data storage
- Plan 02 can wire these modules into the scout scoring pipeline

---
*Phase: 14-demand-driven-scout*
*Completed: 2026-04-07*
