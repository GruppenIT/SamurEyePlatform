# Milestones

## v1.1 Close Known Gaps (Shipped: 2026-03-23)

**Phases:** 3 | **Plans:** 5
**Timeline:** 2026-03-17 to 2026-03-23 (7 days)
**Files changed:** 46 | **Lines:** +6,981

### Key Accomplishments

1. EDR timestamp extraction from timeline events — deploymentTimestamp/detectionTimestamp per host finding
2. Queryable edr_deployments table with idempotent migration guard and storage functions
3. Scoring calibration regression tests encoding THRT-06/08/09 hierarchy invariants
4. Reusable calibration CLI (scripts/calibrate.ts) for live DB validation of scoring constants
5. Full-stack EDR deployment read path: LEFT JOIN API endpoint + Sheet UI with per-host results
6. Zero-failure test baseline established: 298 tests across 17 files, 25/25 threat rule snapshots

### Tech Debt Carried Forward

- `getEdrDeploymentsByJourney` dormant (superseded by `getEdrDeploymentsByJourneyWithHost`)
- Direct import pattern in journeyExecutor bypasses storage facade (intentional)
- Nyquist validation incomplete for Phases 5-7
- THRT-06 live validation skipped (no critical threats in DB)
- PARS-09 missing from 05-01-SUMMARY.md frontmatter (metadata only)

**Archive:** `.planning/milestones/v1.1-ROADMAP.md`, `.planning/milestones/v1.1-REQUIREMENTS.md`

---

## v1.0 — SamurEye Product Revision

**Shipped:** 2026-03-17
**Phases:** 4 | **Plans:** 12
**Timeline:** 2026-03-16 to 2026-03-17
**Files changed:** 553 | **Lines:** ~110K

### Key Accomplishments

1. Rewrote nmap/nuclei parsers with XML output and Zod validation, capturing full OS detection, service versions, NSE scripts, and nuclei evidence
2. Built threat grouping engine consolidating related findings into parent/child clusters with journey-specific grouping keys
3. Implemented contextual scoring engine with weighted formula, score breakdown persistence, and projected posture delta per threat
4. Created 25 remediation templates generating host-specific fix instructions with effort tags and role requirements
5. Redesigned threats page with expandable parent/child grouping, structured detail dialog (Problema/Impacto/Correcao), and human-readable evidence
6. Built action plan page with prioritized remediation cards, filter by effort/role/journey, and score delta visualization
7. Rewrote postura dashboard with score hero + sparkline, journey coverage grid, top 3 actions, WebSocket auto-refresh, and journey comparison delta

### Known Gaps

- PARS-07/08/09: AD/EDR parser depth improvements deferred
- PARS-11: Snapshot test coverage partial
- THRT-06/08/09: Scoring weight calibration not finalized

### UAT Results

- 12 tests: 10 passed, 1 cosmetic issue (fixed), 1 skipped (WebSocket — no live job)

**Archive:** `.planning/milestones/v1.0-ROADMAP.md`, `.planning/milestones/v1.0-REQUIREMENTS.md`
