# Requirements: APIMesh

**Defined:** 2026-04-07
**Core Value:** Developers and AI agents can access a unified suite of web analysis APIs through a single account with one credit pool, paying with either credit card or crypto.

## v1.1 Requirements

Requirements for Compliance & Smarter Brain milestone. Each maps to roadmap phases.

### Legal Compliance

- [x] **LEGAL-01**: User can read Terms of Service covering API usage rights, payment terms, liability limitations, data usage, termination, and x402 crypto payment terms
- [x] **LEGAL-02**: User can read Privacy Policy disclosing data collected, purposes, retention periods, third-party sharing (Stripe, Resend), and user rights (GDPR + CCPA)
- [x] **LEGAL-03**: User can read Acceptable Use Policy prohibiting unauthorized scanning, DDoS via API, and abuse of security/vulnerability APIs
- [x] **LEGAL-04**: User can read Refund/Credit Policy with non-refundable prepaid credits, billing error exceptions, and EU digital goods disclosure
- [x] **LEGAL-05**: User can read Cookie Disclosure confirming essential-only session cookies with no tracking
- [x] **LEGAL-06**: User can report abuse via documented DMCA/abuse process (abuse@apimesh.xyz, 48h response)
- [x] **LEGAL-07**: Each legal page has a plain-language TL;DR summary box (3-5 bullet points)
- [x] **LEGAL-08**: Signup page requires agreement to ToS and Privacy Policy before account creation
- [x] **LEGAL-09**: Stripe Checkout flow includes refund policy acknowledgment

### Demand-Driven Selection

- [x] **DEMAND-01**: Scout queries DataForSEO for keyword search volume on candidate API categories
- [x] **DEMAND-02**: Scout checks RapidAPI/marketplace listings for demand signals in adjacent categories
- [x] **DEMAND-03**: Scout performs competitor gap analysis against SecurityTrails, BuiltWith, Qualys equivalents
- [x] **DEMAND-04**: Scoring model weights real search volume data higher than LLM-guessed demand
- [x] **DEMAND-05**: Scout supports themed expansion weeks with configurable category focus
- [x] **DEMAND-06**: Dev.to article engagement feeds back into scout as demand signal
- [x] **DEMAND-07**: High-scoring backlog items (overall_score > 7.5) trigger gpt-4.1 model escalation for builds

### API Quality

- [x] **QUAL-01**: Brain-built APIs return rich structured JSON with 5+ distinct data fields, explanations, and severity scores
- [x] **QUAL-02**: Brain-built APIs handle edge cases gracefully (invalid URL, unreachable host, malformed input, timeout)
- [x] **QUAL-03**: Brain-built APIs include actionable recommendations with severity levels and fix suggestions
- [x] **QUAL-04**: All APIs follow consistent response envelope schema (`{ status, data, meta: { timestamp, duration_ms, api_version } }`)
- [x] **QUAL-05**: Brain generates comprehensive API documentation (description, parameters, examples, error codes, rate limits)
- [x] **QUAL-06**: Brain-built APIs include comparative scoring (0-100 score with letter grade) where applicable
- [x] **QUAL-07**: Builder uses rotating reference APIs by category (not just web-checker and email-verify)
- [x] **QUAL-08**: Post-build automated quality scoring gates deployment (minimum 60/100 across response richness, error handling, docs, performance)
- [x] **QUAL-09**: Builder runs pre-generation competitive research to differentiate from existing tools

## Future Requirements

Deferred to future milestones. Tracked but not in current roadmap.

### Advanced Demand Signals

- **DEMAND-F01**: GitHub issue/discussion mining for unmet API demand
- **DEMAND-F02**: Stack Overflow question volume correlation with API categories

### Enterprise Features

- **ENT-F01**: Data Processing Agreement (DPA) for enterprise customers
- **ENT-F02**: SOC2/HIPAA compliance documentation

### Advanced Quality

- **QUAL-F01**: Multi-source aggregation APIs (single call combines multiple data sources)
- **QUAL-F02**: Human review queue for brain-built APIs above quality threshold

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Cookie consent banner/CMP | Essential-only cookies — banner implies tracking that doesn't exist |
| Auto-generated legal pages from template services | Generic boilerplate doesn't match APIMesh-specific practices (x402, URL scanning, non-expiring credits) |
| CMS for legal pages | Over-engineering for content that changes 1-2x/year — static HTML with git versioning |
| Real-time keyword tracking subscription | $100+/mo overkill — batch DataForSEO lookups at ~$5/mo sufficient |
| User feature voting board | Not enough active users to generate meaningful signal |
| LLM-powered runtime API responses | Inconsistent results, high latency, per-call LLM costs eating margins |
| Wrapper-only APIs (single free source proxied) | Zero value over DIY — each API must combine sources or add analysis |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| LEGAL-01 | Phase 13 | Complete |
| LEGAL-02 | Phase 13 | Complete |
| LEGAL-03 | Phase 13 | Complete |
| LEGAL-04 | Phase 13 | Complete |
| LEGAL-05 | Phase 13 | Complete |
| LEGAL-06 | Phase 13 | Complete |
| LEGAL-07 | Phase 13 | Complete |
| LEGAL-08 | Phase 13 | Complete |
| LEGAL-09 | Phase 13 | Complete |
| DEMAND-01 | Phase 14 | Complete |
| DEMAND-02 | Phase 14 | Complete |
| DEMAND-03 | Phase 14 | Complete |
| DEMAND-04 | Phase 14 | Complete |
| DEMAND-05 | Phase 14 | Complete |
| DEMAND-06 | Phase 14 | Complete |
| DEMAND-07 | Phase 14 | Complete |
| QUAL-01 | Phase 15 | Complete |
| QUAL-02 | Phase 15 | Complete |
| QUAL-03 | Phase 15 | Complete |
| QUAL-04 | Phase 15 | Complete |
| QUAL-05 | Phase 15 | Complete |
| QUAL-06 | Phase 15 | Complete |
| QUAL-07 | Phase 15 | Complete |
| QUAL-08 | Phase 15 | Complete |
| QUAL-09 | Phase 15 | Complete |

**Coverage:**
- v1.1 requirements: 25 total
- Mapped to phases: 25
- Unmapped: 0

---
*Requirements defined: 2026-04-07*
*Last updated: 2026-04-07 after roadmap creation*
