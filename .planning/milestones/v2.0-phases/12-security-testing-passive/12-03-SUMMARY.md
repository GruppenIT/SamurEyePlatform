---
phase: 12-security-testing-passive
plan: "03"
subsystem: api
tags: [security, passive-testing, storage, upsert, deduplication, orchestrator, drizzle, jwt, nuclei]

requires:
  - phase: 12-security-testing-passive/12-01
    provides: Schema types (ApiPassiveTestOpts, PassiveTestResult, InsertApiFinding) + 10 Nyquist stubs + 5 fixtures
  - phase: 12-security-testing-passive/12-02
    provides: 3 scanner files (nucleiApi, authFailure, api9Inventory) + NucleiFindingSchema camelCase + decodeJwtExp returns Date|null

provides:
  - upsertApiFindingByKey in server/storage/apiFindings.ts (db.transaction dedupe with closed-row reopen)
  - listApiFindings in server/storage/apiFindings.ts (filtered query with apiId/endpointId/jobId guard)
  - IStorage interface signatures for both new storage methods
  - DatabaseStorage wiring in server/storage/index.ts
  - runApiPassiveTests orchestrator composing all 3 Wave 1 scanners with dryRun + cancel support

affects:
  - 12-04 (Wave 3 route + CLI consumes runApiPassiveTests + storage.listApiFindings)
  - Phase 15 journey executor (uses runApiPassiveTests directly)
  - Any code calling storage.upsertApiFindingByKey or storage.listApiFindings

tech-stack:
  added: []
  patterns:
    - "upsert with composite key (endpointId, owaspCategory, title) + db.transaction for race safety"
    - "findalize() inner closure captures all mutable state — single exit path for cancel/normal paths"
    - "dryRun fixture loading from server/__tests__/fixtures/api-passive/ with title prefixing"
    - "encryptionService.decryptCredential(secretEncrypted, dekEncrypted) for credential access"
    - "checkCancel() helper wrapping jobQueue.isJobCancelled — reused at each stage boundary"

key-files:
  created:
    - server/services/journeys/apiPassiveTests.ts
  modified:
    - server/storage/apiFindings.ts
    - server/storage/interface.ts
    - server/storage/index.ts

key-decisions:
  - "upsertApiFindingByKey uses db.transaction (not ON CONFLICT) — enables row-level status check and closed-row reopen in a single serialized unit"
  - "listApiFindings requires at least one of apiId/endpointId/jobId — prevents accidental full-table scans from callers"
  - "encryptionService.decryptCredential used in real path (not credWithSecret.secret) — ApiCredentialWithSecret only has secretEncrypted/dekEncrypted fields per schema"
  - "auth_failure stage scoped to bearer_jwt + api_key_header + api_key_query only (Phase 12 scope per CONTEXT.md)"
  - "stagesRun includes stage name only if it actually ran (auth_failure removed from stagesRun if no eligible endpoints)"

patterns-established:
  - "finalize() inner closure: same pattern as apiDiscovery.ts Phase 11"
  - "Cooperative cancel: checkCancel() called at each stage boundary and between endpoint iterations"
  - "Partial persistence on cancel: no rollback, findings already upserted remain"

requirements-completed:
  - TEST-01
  - TEST-02

duration: 18min
completed: "2026-04-20"
---

# Phase 12 Plan 03: Security Testing Passive Wave 2 Summary

**Storage facade extended with transaction-safe `upsertApiFindingByKey` + `listApiFindings`, and `runApiPassiveTests` orchestrator composing all 3 Wave 1 scanners with dryRun fixture loading and cooperative cancellation**

## Performance

- **Duration:** 18 min
- **Started:** 2026-04-20T12:00:00Z
- **Completed:** 2026-04-20T12:18:00Z
- **Tasks:** 2
- **Files modified:** 4 (3 storage + 1 new orchestrator)

## Accomplishments

- Storage facade: `upsertApiFindingByKey` uses `db.transaction` to serialize SELECT+INSERT/UPDATE; non-closed match → UPDATE (preserve status); closed match or no match → INSERT new row
- Storage facade: `listApiFindings` with dynamic WHERE conditions, join via `apiEndpoints` for `apiId` filter, guard requiring at least one scoping key
- IStorage interface and DatabaseStorage updated with 2 new method signatures
- Orchestrator `runApiPassiveTests`: 3 stages in order (api9_inventory → nuclei_passive → auth_failure), dryRun loads fixtures and prefixes `[DRY-RUN]`, cooperative cancel via `jobQueue.isJobCancelled`, findings persisted via `upsertApiFindingByKey` with counters

## Task Commits

1. **Task 1: storage facade (upsertApiFindingByKey + listApiFindings)** - `7d40fc5` (feat)
2. **Task 2: runApiPassiveTests orchestrator** - `44a0d83` (feat)

## Files Created/Modified

- `server/storage/apiFindings.ts` — Added `upsertApiFindingByKey` (db.transaction dedupe) + `listApiFindings` (filtered query) + `ListApiFindingsFilter` interface
- `server/storage/interface.ts` — Added 2 new IStorage signatures for Phase 12 storage methods
- `server/storage/index.ts` — Wired `upsertApiFindingByKey` and `listApiFindings` in DatabaseStorage
- `server/services/journeys/apiPassiveTests.ts` — New 481-line orchestrator with all 3 scanner stages, dryRun fixture loading, cancel, JWT vectors, API key leakage, finalize() inner closure

## Decisions Made

- `upsertApiFindingByKey` uses `db.transaction` rather than SQL `ON CONFLICT` because the dedupe rule requires checking `status != 'closed'` before deciding to update vs insert — this logic cannot be expressed as a single ON CONFLICT clause
- `listApiFindings` guard (requires apiId/endpointId/jobId) throws at the function level to prevent callers from accidentally querying all findings
- Plan code used `credWithSecret.secret` which doesn't exist on `ApiCredentialWithSecret` (type is `ApiCredential = {secretEncrypted, dekEncrypted}`). Fixed to use `encryptionService.decryptCredential(secretEncrypted, dekEncrypted)` matching the Phase 11 pattern
- `auth_failure` stage entry in `stagesRun` is removed post-loop if no endpoints were eligible, preventing misleading "stage ran" signals in `PassiveTestResult`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed credential secret access in orchestrator**
- **Found during:** Task 2 (runApiPassiveTests orchestrator)
- **Issue:** Plan code example used `credWithSecret.secret` which does not exist — `ApiCredentialWithSecret = ApiCredential` only has `secretEncrypted`/`dekEncrypted` per schema
- **Fix:** Used `encryptionService.decryptCredential(credWithSecret.secretEncrypted, credWithSecret.dekEncrypted)` matching Phase 11 `apiDiscovery.ts` pattern
- **Files modified:** server/services/journeys/apiPassiveTests.ts
- **Verification:** `npx tsc --noEmit` reports 0 new errors in apiPassiveTests.ts
- **Committed in:** 44a0d83 (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - bug in plan code example)
**Impact on plan:** Essential correctness fix — wrong field access would cause runtime crash on real credential decryption. No scope creep.

## Issues Encountered

None — TypeScript caught the credential field issue at compile time (0 new errors after fix).

## Self-Check: PASSED

- `server/storage/apiFindings.ts` exists ✓
- `server/storage/interface.ts` contains `upsertApiFindingByKey` ✓
- `server/storage/index.ts` wires both new methods ✓
- `server/services/journeys/apiPassiveTests.ts` exists (481 lines) ✓
- Commits `7d40fc5` and `44a0d83` present in git log ✓
- `npx tsc --noEmit` — 89 errors (all pre-existing, 0 new) ✓
- `npx vitest run server/__tests__/apiPassive` — 58 passing, 27 todo ✓
- Phase 10/11 regression: 231 tests passing ✓

## Next Phase Readiness

- Wave 3 (Plan 12-04): Route `POST /api/v1/apis/:id/passive-test` + CLI `runApiPassiveTests.ts` can now `import { runApiPassiveTests } from '../services/journeys/apiPassiveTests'` and call `storage.listApiFindings({ apiId })`
- Phase 15 journey executor: can call `runApiPassiveTests(apiId, opts, jobId)` directly
- No blockers

---
*Phase: 12-security-testing-passive*
*Completed: 2026-04-20*
