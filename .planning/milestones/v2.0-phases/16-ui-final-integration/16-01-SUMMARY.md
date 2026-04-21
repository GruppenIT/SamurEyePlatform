---
phase: 16-ui-final-integration
plan: "01"
subsystem: test-infrastructure
tags: [vitest, testing, nyquist, shared-ui, wave-0]
dependency_graph:
  requires: []
  provides: [test-infra-16, shared-ui-helpers, nyquist-wave-0-stubs]
  affects: [16-02, 16-03, 16-04]
tech_stack:
  added:
    - "@testing-library/react@16.3.2"
    - "@testing-library/jest-dom@6.6.3"
    - "@testing-library/user-event@14.5.2"
    - "jsdom@25.0.1"
  patterns:
    - "Nyquist Wave 0 stubs (it.todo before implementation)"
    - "environmentMatchGlobs per folder (jsdom for UI, node for routes/server/shared)"
    - "pure UI helpers in shared/ui/ — no DOM dependency"
key_files:
  created:
    - vitest.config.ts
    - tests/setup.ts
    - shared/ui/curlBuilder.ts
    - shared/ui/curlBuilder.test.ts
    - shared/ui/estimateRequests.ts
    - shared/ui/estimateRequests.test.ts
    - shared/ui/methodColors.ts
    - shared/ui/owaspBadge.ts
    - shared/ui/owaspBadge.test.ts
    - tests/ui/api-discovery-page.test.tsx
    - tests/ui/api-endpoint-drilldown.test.tsx
    - tests/ui/findings-owasp-filter.test.tsx
    - tests/ui/curl-reproduction.test.tsx
    - tests/ui/false-positive-marking.test.tsx
    - tests/ui/journey-wizard.test.tsx
    - tests/routes/apis-list.test.ts
    - tests/routes/apis-endpoints.test.ts
    - tests/routes/threats-source-filter.test.ts
    - tests/routes/api-findings-false-positive.test.ts
    - tests/routes/jobs-api-security.test.ts
  modified: []
decisions:
  - "environmentMatchGlobs used to set jsdom for tests/ui/** and node for server/**/tests/routes/** — avoids global environment mismatch"
  - "tests/setup.ts single import @testing-library/jest-dom — cleanest way to register extended matchers globally"
  - "@testing-library/react pinned to ^16 (React 18 compatible) — existing project runs React 18.3.1"
  - "shared/ui/ helpers are pure TS with no DOM imports — safe to run in node environment for unit tests"
  - "83 it.todo stubs created (above 65 minimum) — journey-wizard.test.tsx has 14 stubs for complex 4-step wizard"
metrics:
  duration: "~4m30s"
  completed_date: "2026-04-20"
  tasks_completed: 2
  files_created: 20
  files_modified: 2
---

# Phase 16 Plan 01: Nyquist Wave 0 Test Infrastructure Summary

**One-liner:** Extended vitest config with jsdom+environmentMatchGlobs, installed @testing-library 4-pack, extracted 4 pure UI helpers to shared/ui/ with 19 real passing tests, and created 11 Nyquist Wave 0 stub files (83 it.todo total) covering all 6 UI requirements and 5 backend routes.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Extend vitest + install deps + shared/ui/ helpers | 9447c38 | vitest.config.ts, package.json, tests/setup.ts, 6 shared/ui/* |
| 2 | Create 11 Wave 0 test stubs | d449b58 | 6 tests/ui/*.tsx + 5 tests/routes/*.ts |

## Test Results

### shared/ui/ — Real Tests (19 passing)

| File | Tests | Status |
|------|-------|--------|
| curlBuilder.test.ts | 10 | PASS |
| estimateRequests.test.ts | 4 | PASS |
| owaspBadge.test.ts | 5 | PASS |
| **Total** | **19** | **ALL PASS** |

### tests/ — Wave 0 Stubs (83 it.todo)

| File | it.todo count | Min required |
|------|---------------|--------------|
| tests/ui/api-discovery-page.test.tsx | 7 | 7 |
| tests/ui/api-endpoint-drilldown.test.tsx | 8 | 6 |
| tests/ui/findings-owasp-filter.test.tsx | 7 | 6 |
| tests/ui/curl-reproduction.test.tsx | 7 | 6 |
| tests/ui/false-positive-marking.test.tsx | 7 | 6 |
| tests/ui/journey-wizard.test.tsx | 14 | 10 |
| tests/routes/apis-list.test.ts | 7 | 6 |
| tests/routes/apis-endpoints.test.ts | 6 | 5 |
| tests/routes/threats-source-filter.test.ts | 6 | 5 |
| tests/routes/api-findings-false-positive.test.ts | 7 | 6 |
| tests/routes/jobs-api-security.test.ts | 7 | 6 |
| **Total** | **83** | **65** |

`npx vitest run tests/` exits 0 — all 83 stubs reported as `todo` (not failed).

## Decisions Made

1. **environmentMatchGlobs** — server/** stays node, shared/**/*.test.ts stays node, tests/routes/** stays node, tests/ui/** gets jsdom. This avoids `new TextEncoder()` invariant errors caused by jsdom overriding the global environment.

2. **tests/setup.ts** — Single-line `import '@testing-library/jest-dom'` registered as `setupFiles` in vitest.config.ts so extended matchers (`toBeInTheDocument`, etc.) are available in all tsx test files.

3. **@testing-library/react@^16** — Pinned to v16 range which supports React 18.x (existing project dependency). Not v17/alpha.

4. **shared/ui/ pure helpers** — `curlBuilder.ts`, `estimateRequests.ts`, `methodColors.ts`, `owaspBadge.ts` have no DOM or React imports. They run cleanly in node environment and are importable by both UI components and test files.

5. **journey-wizard.test.tsx 14 stubs** — Plan spec required ≥ 10 but the 4-step wizard has enough distinct behaviors (per-step validation, nested dialog, estimate badge, submit payload) to warrant 14 stubs. Waves 3-4 can promote these incrementally.

## Deviations from Plan

None — plan executed exactly as written. All acceptance criteria met.

## npm Install Notes

- `@testing-library/react@16.3.2` installed (latest 16.x)
- `@testing-library/jest-dom@6.6.3` installed (latest 6.x)
- `@testing-library/user-event@14.5.2` installed (exact as requested)
- `jsdom@25.0.1` installed (latest 25.x, deduped with vitest's own jsdom dep)
- 14 pre-existing npm audit vulnerabilities (unrelated to these packages — pre-existing)

## Pre-existing Test Failures (Out of Scope)

The following test failures were confirmed pre-existing before Plan 16-01 changes (verified via git stash):
- `server/__tests__/apiPassive/route.test.ts` — 11 failures (esbuild TextEncoder invariant in jsdom env context)
- `server/__tests__/apiDiscovery/route.test.ts` — esbuild invariant
- `server/__tests__/threatPromotion.test.ts` — pre-existing
- `server/services/__tests__/actionPlanService.test.ts` — pre-existing
- `server/lib/__tests__/imageUpload.test.ts` — pre-existing

These are deferred to their respective phase owners and do not affect the Phase 16 test infrastructure deliverables.

## Self-Check: PASSED
