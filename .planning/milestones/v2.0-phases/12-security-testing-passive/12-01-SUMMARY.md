---
phase: 12-security-testing-passive
plan: 01
subsystem: testing
tags: [vitest, zod, nuclei, jwt, owasp, passive-testing, fixtures]

# Dependency graph
requires:
  - phase: 11-discovery-enrichment
    provides: discoverApiOptsSchema pattern for Zod schema design
  - phase: 09-api-foundation
    provides: owaspApiCategoryEnum, apiFindingStatusEnum, NucleiFindingSchema in shared/schema.ts
provides:
  - apiPassiveTestOptsSchema Zod schema in shared/schema.ts (Wave 2+3 contract)
  - ApiPassiveTestOpts type in shared/schema.ts
  - PassiveTestResult interface in shared/schema.ts
  - 10 Nyquist test stubs in server/__tests__/apiPassive/ (Wave 1-3 targets)
  - 5 deterministic dryRun fixtures in server/__tests__/fixtures/api-passive/
affects:
  - 12-02-PLAN (Wave 1 scanners import apiPassiveTestOptsSchema)
  - 12-03-PLAN (Wave 2 orchestrator imports ApiPassiveTestOpts + PassiveTestResult)
  - 12-04-PLAN (Wave 3 route imports apiPassiveTestOptsSchema for Zod validation)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Nyquist Wave 0 stub pattern: it.todo files created before implementation, enabling Wave 1-3 automated verify targets
    - Zod .strict() on both root and sub-objects to reject unknown fields (mirrors discoverApiOptsSchema decision)
    - PassiveTestResult as TypeScript interface (not z.infer) for extensibility without breaking

key-files:
  created:
    - shared/__tests__/apiPassiveTestOptsSchema.test.ts
    - server/__tests__/apiPassive/nucleiArgs.test.ts
    - server/__tests__/apiPassive/jsonlMapper.test.ts
    - server/__tests__/apiPassive/api9Inventory.test.ts
    - server/__tests__/apiPassive/jwtAlgNone.test.ts
    - server/__tests__/apiPassive/kidInjection.test.ts
    - server/__tests__/apiPassive/tokenReuse.test.ts
    - server/__tests__/apiPassive/apiKeyLeakage.test.ts
    - server/__tests__/apiPassive/dedupeUpsert.test.ts
    - server/__tests__/apiPassive/orchestrator.test.ts
    - server/__tests__/apiPassive/route.test.ts
    - server/__tests__/fixtures/api-passive/nuclei-passive-mock.jsonl
    - server/__tests__/fixtures/api-passive/jwt-alg-none-response.json
    - server/__tests__/fixtures/api-passive/jwt-kid-injection-response.json
    - server/__tests__/fixtures/api-passive/jwt-expired-response.json
    - server/__tests__/fixtures/api-passive/api-key-leakage-body.json
  modified:
    - shared/schema.ts (appended apiPassiveTestOptsSchema + ApiPassiveTestOpts + PassiveTestResult)

key-decisions:
  - "apiPassiveTestOptsSchema uses .strict() on root and stages sub-object (same pattern as discoverApiOptsSchema Phase 11) — rejects unknown fields at both levels"
  - "PassiveTestResult as TypeScript interface (not z.infer) — allows extension by Waves 2-3 without changing Zod schema boundary"
  - "nuclei opts sub-object with rateLimit/timeoutSec mirrors discoverApiOptsSchema kiterunner pattern — consistent override shape"

patterns-established:
  - "Nyquist Wave 0: create it.todo stubs before implementation so Wave 1-3 can use them as <automated> verify targets"
  - "Fixtures naming: {scan-type}-{variant}-{purpose}.json|jsonl — deterministic, no real network calls needed"

requirements-completed: [TEST-01, TEST-02]

# Metrics
duration: 7min
completed: 2026-04-20
---

# Phase 12 Plan 01: Security Testing Passive — Wave 0 Summary

**Nyquist foundation for Phase 12: apiPassiveTestOptsSchema Zod contract + 10 it.todo test stubs + 5 deterministic fixtures for dryRun isolation, establishing the scaffolding consumed by Waves 1-3**

## Performance

- **Duration:** 7 min
- **Started:** 2026-04-20T11:48:29Z
- **Completed:** 2026-04-20T11:56:08Z
- **Tasks:** 3
- **Files modified:** 17

## Accomplishments
- `apiPassiveTestOptsSchema` Zod schema with `.strict()` on root and stages sub-object, exported from `shared/schema.ts` alongside `ApiPassiveTestOpts` type and `PassiveTestResult` interface
- 10 `it.todo` stub files in `server/__tests__/apiPassive/` (70 total todos) — Vitest collects all 10 without errors, 0 real assertions (Wave 0 is intentionally empty)
- 5 deterministic fixtures in `server/__tests__/fixtures/api-passive/` — 1 JSONL (5 Nuclei findings covering misconfig/exposure/graphql/cors/swagger) + 4 JSON responses for JWT auth attack scenarios and API key leakage

## Task Commits

Each task was committed atomically:

1. **Task 1: Zod schema apiPassiveTestOptsSchema + types** - `940376b` (feat) — TDD GREEN: 7 tests pass
2. **Task 2: 10 test stubs it.todo** - `71c87d4` (test) — 70 it.todo across 10 files
3. **Task 3: 5 deterministic fixtures** - `ef51752` (chore) — 1 JSONL + 4 JSON fixtures

## Files Created/Modified
- `shared/schema.ts` - Appended apiPassiveTestOptsSchema + ApiPassiveTestOpts + PassiveTestResult (Phase 12 block)
- `shared/__tests__/apiPassiveTestOptsSchema.test.ts` - TDD test for schema (7 tests GREEN)
- `server/__tests__/apiPassive/nucleiArgs.test.ts` - 6 it.todo for Nuclei arg builder (TEST-01)
- `server/__tests__/apiPassive/jsonlMapper.test.ts` - 8 it.todo for JSONL mapper (TEST-01)
- `server/__tests__/apiPassive/api9Inventory.test.ts` - 8 it.todo for DB-derived API9 signals (TEST-01)
- `server/__tests__/apiPassive/jwtAlgNone.test.ts` - 6 it.todo for alg:none JWT forge (TEST-02)
- `server/__tests__/apiPassive/kidInjection.test.ts` - 4 it.todo for kid injection (TEST-02)
- `server/__tests__/apiPassive/tokenReuse.test.ts` - 5 it.todo for token reuse (TEST-02)
- `server/__tests__/apiPassive/apiKeyLeakage.test.ts` - 6 it.todo for API key leakage (TEST-02)
- `server/__tests__/apiPassive/dedupeUpsert.test.ts` - 7 it.todo for dedupe upsert (TEST-01+TEST-02)
- `server/__tests__/apiPassive/orchestrator.test.ts` - 9 it.todo for orchestrator (TEST-01+TEST-02)
- `server/__tests__/apiPassive/route.test.ts` - 11 it.todo for routes (TEST-01+TEST-02)
- `server/__tests__/fixtures/api-passive/nuclei-passive-mock.jsonl` - 5 representative Nuclei findings
- `server/__tests__/fixtures/api-passive/jwt-alg-none-response.json` - Mocked alg:none bypass response
- `server/__tests__/fixtures/api-passive/jwt-kid-injection-response.json` - Mocked kid manipulation response
- `server/__tests__/fixtures/api-passive/jwt-expired-response.json` - Mocked token reuse response
- `server/__tests__/fixtures/api-passive/api-key-leakage-body.json` - Mocked API key leakage response

## Decisions Made
- `apiPassiveTestOptsSchema` uses `.strict()` on root AND stages sub-object to reject unknown fields at both levels — mirrors `discoverApiOptsSchema` Phase 11 decision for consistency
- `PassiveTestResult` declared as TypeScript `interface` (not `z.infer`) — allows Waves 2-3 to extend it without modifying Zod schema boundary; interface is more flexible for gradual extension
- `nuclei` opts sub-object with `rateLimit`/`timeoutSec` mirrors `discoverApiOptsSchema.kiterunner` pattern — consistent override shape across all scan opts schemas

## Deviations from Plan

### Observed (No Action Required)

**1. [External] nucleiArgs.test.ts and jsonlMapper.test.ts upgraded from it.todo to real assertions**
- **Found during:** Task 3 (fixture creation)
- **Issue:** A parallel process (12-02 Wave 1 executor) modified both stub files and added real implementations in `nucleiApi.ts`
- **Action:** No action needed — this is correct forward progress. The stubs were consumed as designed. The 2 files now have GREEN tests (20 passing) instead of it.todo.
- **Impact:** vitest run shows 2 files passing + 8 files skipped (70 → 76 total including 20 real assertions)

---

**Total deviations:** 0 auto-fixes required (Wave 0 scaffolding executed as designed)

## Issues Encountered
None — plan executed cleanly. Pre-existing TypeScript errors in `client/` and unrelated server files were already present and are out of scope.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Wave 1 (12-02): `nucleiApi.ts` scanner, `api9Inventory.ts`, `authFailure.ts` — stubs in `server/__tests__/apiPassive/` ready as test targets
- Wave 2 (12-03): orchestrator `runApiPassiveTests()` + storage `upsertApiFindingByKey()` — `PassiveTestResult` interface ready for import
- Wave 3 (12-04): route `POST /api/v1/apis/:id/test/passive` + `GET /api/v1/api-findings` — `apiPassiveTestOptsSchema` ready for Zod validation

---
*Phase: 12-security-testing-passive*
*Completed: 2026-04-20*
