# Roadmap: SamurEye Platform

## Milestones

- **v1.0 Product Revision** — Phases 1-4 (shipped 2026-03-17)
- **v1.1 Close Known Gaps** — Phases 5-6 (in progress)

## Phases

<details>
<summary>v1.0 Product Revision (Phases 1-4) — SHIPPED 2026-03-17</summary>

- [x] Phase 1: Parser Foundation (3/3 plans) — completed 2026-03-16
- [x] Phase 2: Threat Engine Intelligence (3/3 plans) — completed 2026-03-16
- [x] Phase 3: Remediation Engine (2/2 plans) — completed 2026-03-16
- [x] Phase 4: User-Facing Surfaces (4/4 plans) — completed 2026-03-16

See: `.planning/milestones/v1.0-ROADMAP.md` for full details.

</details>

### v1.1 Close Known Gaps (In Progress)

**Milestone Goal:** Close all known gaps from v1.0 — EDR timestamps, scoring calibration, snapshot coverage, test suite health

- [x] **Phase 5: EDR Timestamps** - Add deployment/detection timestamps to EDR parser and expose them in a queryable database table (completed 2026-03-17)
- [x] **Phase 6: Calibration and Quality** - Validate scoring weights against real scan data, complete snapshot coverage, and achieve zero-failure test baseline (completed 2026-03-17)

## Phase Details

### Phase 5: EDR Timestamps
**Goal**: EDR findings surface per-host deployment and detection timestamps in structured, queryable form
**Depends on**: Phase 4 (v1.0 complete)
**Requirements**: PARS-09, PARS-10
**Success Criteria** (what must be TRUE):
  1. Each EDR finding includes a deploymentTimestamp and detectionTimestamp field with a real value (not null) when the scanner reports them
  2. A dedicated database table stores per-host EDR deployment metadata, queryable by host identifier and journey ID
  3. Existing EDR scan results continue to load without errors after the schema migration
**Plans**: 1 plan

Plans:
- [ ] 05-01-PLAN.md — EDR parser timestamp fields, edr_deployments table, migration guard, storage functions, and scanner/executor wiring

### Phase 6: Calibration and Quality
**Goal**: Scoring weights are validated against real data, all 25 threat rules have snapshot coverage, and the test suite runs with zero failures
**Depends on**: Phase 5
**Requirements**: THRT-06, THRT-08, THRT-09, PARS-11, QUAL-01, QUAL-02
**Success Criteria** (what must be TRUE):
  1. Running the full test suite produces zero failures (npx vitest run exits 0)
  2. All 25 threat rule test files have committed .snap files with current output
  3. Scoring component weights, host criticality multipliers, and exploitability multiplier are reviewed against real scan data with any inversions corrected and findings documented
**Plans**: 2 plans

Plans:
- [ ] 06-01-PLAN.md — Test suite health verification (QUAL-01, PARS-11) and calibration regression tests (THRT-06, THRT-08, THRT-09 hierarchy invariants)
- [ ] 06-02-PLAN.md — Calibration CLI script, live DB validation, auto-patch, and calibration report (THRT-06, THRT-08, THRT-09)

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Parser Foundation | v1.0 | 3/3 | Complete | 2026-03-16 |
| 2. Threat Engine Intelligence | v1.0 | 3/3 | Complete | 2026-03-16 |
| 3. Remediation Engine | v1.0 | 2/2 | Complete | 2026-03-16 |
| 4. User-Facing Surfaces | v1.0 | 4/4 | Complete | 2026-03-16 |
| 5. EDR Timestamps | 1/1 | Complete   | 2026-03-17 | - |
| 6. Calibration and Quality | 2/2 | Complete   | 2026-03-17 | - |
