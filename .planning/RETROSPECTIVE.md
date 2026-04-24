# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v1.1 — Close Known Gaps

**Shipped:** 2026-03-23
**Phases:** 3 | **Plans:** 5

### What Was Built
- EDR per-host deployment/detection timestamps with queryable storage table
- Full-stack EDR deployment read path (API + Sheet UI)
- Scoring calibration regression tests and reusable CLI
- Zero-failure test baseline (298 tests, 25/25 snapshots)

### What Worked
- Gap-driven milestone scope kept work tightly focused — every phase traced to a specific audit finding
- Reuse of existing patterns (storage ops module, route registration, Sheet side-panel) made new features fast
- Calibration script as reusable CLI means future scoring changes can be re-validated quickly
- "Pre-resolved" findings (QUAL-01 already passing, PARS-11 snapshots already committed) saved execution time

### What Was Inefficient
- Nyquist validation was configured but never signed off for any phase — the workflow step exists but wasn't enforced
- STATE.md progress tracking fell out of sync during rapid execution — manual updates needed
- The original `getEdrDeploymentsByJourney` was created in Phase 5 but immediately superseded in Phase 7 — could have been designed once if phases were planned together

### Patterns Established
- Idempotent migration guard pattern (pg_tables check + CREATE TABLE IF NOT EXISTS) for additive schema changes
- Calibration regression tests as hierarchy invariants — express scoring rules as assertions, not documentation
- Sheet side-panel pattern for row-level detail views (journey → EDR deployment results)

### Key Lessons
1. Gap audits before milestone closure catch real issues — PARS-10 partial gap would have shipped incomplete without the audit
2. "Pre-resolved" status should be verified early — two of the Phase 6 items were already done, saving a full plan's worth of work
3. Fire-and-forget storage inserts (non-blocking try/catch) are the right pattern for metadata that doesn't block the primary flow

### Cost Observations
- Sessions: ~6 across 2 days (Mar 17, Mar 23)
- Notable: v1.1 was compact — 5 plans across 3 phases, 46 files changed, completed in 7 calendar days

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Phases | Plans | Key Change |
|-----------|--------|-------|------------|
| v1.0 | 4 | 12 | Full product revision with GSD workflow |
| v1.1 | 3 | 5 | Gap-driven scope, audit-before-close pattern |

### Cumulative Quality

| Milestone | Tests | Snapshots | Test Files |
|-----------|-------|-----------|------------|
| v1.0 | ~280 | 25 | 17 |
| v1.1 | 298 | 25 | 17 |

### Top Lessons (Verified Across Milestones)

1. Additive schema changes prevent data loss and allow safe rollback — validated across both milestones
2. Audit before closing milestones catches real gaps — v1.0 known gaps became v1.1 scope, v1.1 audit caught PARS-10 partial
