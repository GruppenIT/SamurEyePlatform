# Phase 6: Calibration and Quality - Context

**Gathered:** 2026-03-17
**Status:** Ready for planning

<domain>
## Phase Boundary

Validate scoring weights against real scan data from the live database, complete snapshot coverage for all 25 threat rules, and achieve a zero-failure test baseline. Produces a reusable calibration CLI script and calibration regression tests. No new scoring capabilities, no new threat rules, no UI changes.

</domain>

<decisions>
## Implementation Decisions

### Scoring calibration method
- Calibration runs against the live production database using the same `DATABASE_URL` from `.env`
- Reusable CLI script at `scripts/calibrate.ts` — can be re-run anytime against any DB
- Single script run validates all three components together: weights (THRT-06), criticality multipliers (THRT-08), exploitability (THRT-09)
- Read-write auto-patch: script queries DB, detects inversions, patches `scoringEngine.ts` constants directly, then re-runs to verify
- Outputs results to both stdout and a report file

### Inversion detection and auto-fix
- Strict ordering: any case where a lower-severity finding scores higher than a higher-severity finding of the same type is an inversion
- No adjustment limits — script adjusts weights/multipliers to whatever value eliminates the inversion
- THRT-08 validation: strict hierarchy must hold — domain (1.5) > server/firewall/router (1.2) > desktop/switch/other (1.0). Same finding on a DC must always score higher than on a desktop
- THRT-09 validation: both ordering check (confirmed > unconfirmed) AND exact 1.3x ratio verification for exploitability multiplier

### Test suite health
- QUAL-01 (edrAvScanner failures): verify current state — if 0 failures, mark resolved. No investigation of root cause needed
- PARS-11 (25 rule snapshots): verify completeness of existing `.snap` file entries — if all 25 present and current, mark done
- QUAL-02 (zero failures): ensure `npx vitest run` exits 0 with existing tests, PLUS add calibration regression tests that encode scoring hierarchy as permanent test cases
- Calibration regression tests go in `scoringEngine.test.ts` to prevent future inversions

### Calibration documentation
- Report stored in `.planning/phases/06-calibration-and-quality/CALIBRATION-REPORT.md`
- Summary format: pass/fail per component, inversions found, changes made
- Script outputs to both stdout during execution and writes the report file

### Claude's Discretion
- Calibration script implementation details (how to query, how to detect inversions algorithmically)
- Exact format of regression test assertions
- How to patch scoringEngine.ts constants programmatically
- Error handling for DB connection failures in the script

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Scoring system
- `server/services/scoringEngine.ts` — Scoring formula, weight constants (40/25/20/15), criticality multipliers, exploitability multiplier, score breakdown record
- `server/__tests__/scoringEngine.test.ts` — Existing scoring tests, patterns for adding calibration regression tests

### Threat rules and snapshots
- `server/__tests__/threatRuleSnapshots.test.ts` — Consolidated test covering all 25 threat rules
- `server/__tests__/__snapshots__/threatRuleSnapshots.test.ts.snap` — Committed snapshot file for all 25 rules
- `server/services/threatEngine.ts` — Threat engine with all 25 rule implementations

### EDR scanner tests
- `server/__tests__/edrAvScanner.test.ts` — Test file referenced by QUAL-01 (verify 0 failures)

### Requirements
- `.planning/REQUIREMENTS.md` — THRT-06, THRT-08, THRT-09, PARS-11, QUAL-01, QUAL-02 definitions

### Database schema
- `shared/schema.ts` — Database tables and schemas for querying scored findings

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `scoringEngine.ts`: Complete scoring implementation with `SEVERITY_WEIGHTS`, `CRITICALITY_MULTIPLIERS`, `EXPOSURE_FACTORS`, `calculateThreatScore()` — calibration script wraps this
- `threatRuleSnapshots.test.ts`: All 25 rules tested in one file — PARS-11 may already be satisfied
- Drizzle ORM query patterns: Existing `storage/*.ts` files show how to query the DB

### Established Patterns
- Server uses `DATABASE_URL` from `.env` for Drizzle connection — calibration script reuses this
- Vitest for all testing — calibration regression tests follow same patterns
- Score breakdown record: 7-field object documenting each scoring component — useful for calibration analysis

### Integration Points
- `scoringEngine.ts` constants: Where weight/multiplier values live — auto-patch target
- `scoringEngine.test.ts`: Where calibration regression tests will be added
- `.env` DATABASE_URL: Connection config shared between server and calibration script

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 06-calibration-and-quality*
*Context gathered: 2026-03-17*
