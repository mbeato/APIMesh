# Roadmap: APIMesh

## Milestones

- **v1.0 Stripe Billing & User Accounts** — Phases 1-12 (shipped 2026-03-26) | [Archive](milestones/v1.0-ROADMAP.md)
- **v1.1 Compliance & Smarter Brain** — Phases 13-15 (in progress)

## Phases

<details>
<summary>v1.0 Stripe Billing & User Accounts (Phases 1-12) — SHIPPED 2026-03-26</summary>

- [x] Phase 1: Foundation (3/3 plans) — completed 2026-03-16
- [x] Phase 2: Signup & Login (3/3 plans) — completed 2026-03-17
- [x] Phase 3: Auth Hardening & Sessions (3/3 plans) — completed 2026-03-17
- [x] Phase 4: API Keys (2/2 plans) — completed 2026-03-18
- [x] Phase 5: Stripe Billing (3/3 plans) — completed 2026-03-18
- [x] Phase 6: Credits & Account Dashboard (2/2 plans) — completed 2026-03-18
- [x] Phase 7: API Key Auth Middleware (3/3 plans) — completed 2026-03-18
- [x] Phase 8: MCP & Landing Page (2/2 plans) — completed 2026-03-18
- [x] Phase 9: Bug Fixes & Code Gaps (1/1 plan) — completed 2026-03-23
- [x] Phase 10: Verification & Traceability (3/3 plans) — completed 2026-03-24
- [x] Phase 11: Platform Analytics & Security Hardening (3/3 plans) — completed 2026-03-26
- [x] Phase 12: Documentation Backfill (1/1 plan) — completed 2026-03-26

</details>

- [x] **Phase 13: Legal Compliance** - Ship compliance pages, signup consent, and abuse process so APIMesh operates with full legal cover (completed 2026-04-07)
- [ ] **Phase 14: Demand-Driven Scout** - Upgrade scout to select API targets based on real search volume and market signals instead of LLM guessing
- [ ] **Phase 15: Higher Quality Builder** - Upgrade brain-built APIs to produce rich, well-documented output that justifies paid usage over DIY

## Phase Details

### Phase 13: Legal Compliance
**Goal**: Users and operators have full legal coverage -- every required policy is published, discoverable, and wired into signup and payment flows
**Depends on**: Nothing (independent of other v1.1 phases)
**Requirements**: LEGAL-01, LEGAL-02, LEGAL-03, LEGAL-04, LEGAL-05, LEGAL-06, LEGAL-07, LEGAL-08, LEGAL-09
**Success Criteria** (what must be TRUE):
  1. User can navigate to each of the six legal pages (ToS, Privacy Policy, AUP, Refund Policy, Cookie Disclosure, DMCA/Abuse) from the site footer on any page
  2. Each legal page includes a plain-language TL;DR summary box at the top with 3-5 bullet points
  3. New users must check a ToS/Privacy Policy agreement checkbox before account creation succeeds
  4. Stripe Checkout flow displays refund policy acknowledgment before payment completes
  5. User can report abuse by following the documented DMCA/abuse process (abuse@apimesh.xyz with stated 48h response commitment)
**Plans**: 2 plans
**UI hint**: yes

Plans:
- [x] 13-01-PLAN.md — Legal pages, routes, and footer (LEGAL-01 through LEGAL-07)
- [ ] 13-02-PLAN.md — Signup consent, Stripe refund text, and tests (LEGAL-08, LEGAL-09)

### Phase 14: Demand-Driven Scout
**Goal**: Scout selects API build targets using real market demand data, producing a backlog where high-scoring items reflect actual developer search interest and competitive gaps
**Depends on**: Phase 13
**Requirements**: DEMAND-01, DEMAND-02, DEMAND-03, DEMAND-04, DEMAND-05, DEMAND-06, DEMAND-07
**Success Criteria** (what must be TRUE):
  1. Scout queries external data sources (DataForSEO or Google Autocomplete fallback) for keyword search volume on candidate API categories during each run
  2. Backlog items include real demand data (search volume, marketplace listings, competitor gaps) in their scoring rather than relying solely on LLM opinion
  3. Scoring model demonstrably weights measured demand signals higher than LLM-estimated demand when both are available
  4. Brain supports themed expansion weeks where scout focuses on a configured category instead of scattershot gap-filling
  5. High-scoring backlog items (overall_score > 7.5) trigger gpt-4.1 model escalation for the build step
**Plans**: 2 plans

Plans:
- [x] 14-01-PLAN.md — Demand data sources, tests, and DB schema extension (DEMAND-01, DEMAND-02, DEMAND-03, DEMAND-06)
- [ ] 14-02-PLAN.md — Scoring integration, theme weeks, and model escalation (DEMAND-04, DEMAND-05, DEMAND-07)

### Phase 15: Higher Quality Builder
**Goal**: Brain-built APIs produce rich, structured, well-documented output with automated quality gates -- every deployed API justifies its price over free alternatives
**Depends on**: Phase 14
**Requirements**: QUAL-01, QUAL-02, QUAL-03, QUAL-04, QUAL-05, QUAL-06, QUAL-07, QUAL-08, QUAL-09
**Success Criteria** (what must be TRUE):
  1. Brain-built APIs return structured JSON with 5+ distinct data fields, explanations, severity scores, and actionable fix suggestions where applicable
  2. Brain-built APIs handle invalid URLs, unreachable hosts, malformed input, and timeouts gracefully with informative error responses
  3. All brain-built APIs follow the consistent response envelope schema ({ status, data, meta: { timestamp, duration_ms, api_version } })
  4. Post-build automated quality scoring runs before deployment and blocks any API scoring below 60/100 across richness, error handling, docs, and performance
  5. Builder uses category-appropriate reference APIs (rotating, not hardcoded) and runs pre-generation competitive research to differentiate output
**Plans**: TBD

Plans:
- [ ] 15-01: TBD
- [ ] 15-02: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 13 -> 14 -> 15

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Foundation | v1.0 | 3/3 | Complete | 2026-03-16 |
| 2. Signup & Login | v1.0 | 3/3 | Complete | 2026-03-17 |
| 3. Auth Hardening & Sessions | v1.0 | 3/3 | Complete | 2026-03-17 |
| 4. API Keys | v1.0 | 2/2 | Complete | 2026-03-18 |
| 5. Stripe Billing | v1.0 | 3/3 | Complete | 2026-03-18 |
| 6. Credits & Account Dashboard | v1.0 | 2/2 | Complete | 2026-03-18 |
| 7. API Key Auth Middleware | v1.0 | 3/3 | Complete | 2026-03-18 |
| 8. MCP & Landing Page | v1.0 | 2/2 | Complete | 2026-03-18 |
| 9. Bug Fixes & Code Gaps | v1.0 | 1/1 | Complete | 2026-03-23 |
| 10. Verification & Traceability | v1.0 | 3/3 | Complete | 2026-03-24 |
| 11. Platform Analytics & Security | v1.0 | 3/3 | Complete | 2026-03-26 |
| 12. Documentation Backfill | v1.0 | 1/1 | Complete | 2026-03-26 |
| 13. Legal Compliance | v1.1 | 1/2 | Complete    | 2026-04-07 |
| 14. Demand-Driven Scout | v1.1 | 1/2 | In progress | - |
| 15. Higher Quality Builder | v1.1 | 0/? | Not started | - |
