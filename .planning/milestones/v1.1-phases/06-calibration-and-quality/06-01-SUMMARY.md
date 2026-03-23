---
phase: 06-calibration-and-quality
plan: "01"
subsystem: testing
tags: [vitest, scoring, calibration, regression-tests]

# Dependency graph
requires:
  - phase: 05-edr-timestamps
    provides: passing test suite baseline (QUAL-01 edrAvScanner resolved)
provides:
  - Calibration regression tests encoding scoring hierarchy invariants (THRT-06, THRT-08, THRT-09)
  - QUAL-02 zero-failure baseline with 298 tests across 17 files
affects: [any future scoring changes — tests will catch inversions]

# Tech tracking
tech-stack:
  added: []
  patterns: [regression-test-first for scoring invariants — hierarchy ordering expressed as assertions not documentation]

key-files:
  created: []
  modified:
    - server/__tests__/scoringEngine.test.ts

key-decisions:
  - "QUAL-01 pre-resolved: edrAvScanner.test.ts (9 tests) passed without any C:\\tmp\\ failures — blocker from STATE.md did not manifest on Linux"
  - "PARS-11 pre-resolved: threatRuleSnapshots.test.ts.snap contained exactly 25 entries"
  - "Calibration regression tests appended to existing scoringEngine.test.ts as new describe block, not a separate file"

patterns-established:
  - "Scoring hierarchy invariants encoded as direct rawScore comparisons (not just multiplier checks), ensuring end-to-end correctness"
  - "Exploitability ratio tested as division (confirmed/base) with toBeCloseTo(1.3, 5) for floating-point safety"

requirements-completed: [QUAL-01, QUAL-02, PARS-11, THRT-06, THRT-08, THRT-09]

# Metrics
duration: 2min
completed: 2026-03-17
---

# Phase 6 Plan 01: Calibration and Quality — Test Health and Regression Tests Summary

**5 calibration regression tests added to scoringEngine.test.ts permanently encoding severity, host criticality, and exploitability hierarchy invariants; full suite at 298 tests with 0 failures**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-17T20:20:22Z
- **Completed:** 2026-03-17T20:21:39Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments

- QUAL-01 confirmed resolved: edrAvScanner.test.ts passes with 9/9 tests, zero failures
- PARS-11 confirmed resolved: threatRuleSnapshots.test.ts.snap contains exactly 25 snapshot entries
- THRT-06: severity rawScore strict ordering test (critical > high > medium > low) added and passing
- THRT-08: host criticality ordering test (domain > server > desktop, firewall/router parity) added and passing
- THRT-09: exploitability ratio tests (1.3x nmap_vuln exact ratio + nuclei confirmation parity) added and passing
- QUAL-02 baseline: full suite 298 tests / 17 files / 0 failures

## Task Commits

Each task was committed atomically:

1. **Task 1: Verify existing test health (QUAL-01, PARS-11, QUAL-02 baseline)** - verification only, no file changes
2. **Task 2: Add calibration regression tests** - `76f7bec` (test)

**Plan metadata:** (docs commit — see below)

## Files Created/Modified

- `server/__tests__/scoringEngine.test.ts` — appended `describe('Calibration regression: hierarchy invariants (THRT-06, THRT-08, THRT-09)')` block with 5 tests

## Decisions Made

- QUAL-01 blocker in STATE.md (C:\tmp\ directory dependency) did not manifest on Linux — the edrAvScanner tests use /dev/shm or /tmp which are available. No fix was needed.
- Regression tests appended to existing scoringEngine.test.ts rather than creating a new file, keeping all scoring tests co-located.
- THRT-09 ratio test uses `toBeCloseTo(1.3, 5)` for floating-point safety, while the nuclei parity test uses `toBe` (exact equality since both code paths produce same multiply).

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None. All pre-existing test failures documented in STATE.md were already resolved before this plan ran.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Calibration regression tests are in place; future scoring changes that invert the hierarchy will be caught immediately
- Phase 6 Plan 02 (UI calibration or remaining quality work) can proceed with clean baseline
- QUAL-02 zero-failure requirement is satisfied

---
*Phase: 06-calibration-and-quality*
*Completed: 2026-03-17*

## Self-Check: PASSED

- `server/__tests__/scoringEngine.test.ts` — FOUND
- `.planning/phases/06-calibration-and-quality/06-01-SUMMARY.md` — FOUND
- Commit `76f7bec` (test(06-01): add calibration regression tests) — FOUND
- All 5 acceptance criteria strings confirmed present in test file
