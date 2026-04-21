# Phase 10 Deferred Items

Issues discovered during Phase 10 execution that are out-of-scope for Wave 0
(test stub infrastructure). Tracked here per GSD scope boundary rule — these
are pre-existing, not caused by Phase 10 changes.

## Pre-existing test failures (not Phase 10)

### actionPlanService.test.ts requires DATABASE_URL

- **File**: `server/services/__tests__/actionPlanService.test.ts`
- **Observed during**: Plan 10-01 full-suite regression check.
- **Symptom**: `Error: DATABASE_URL must be set. Did you forget to provision a database?`
- **Root cause**: `server/db.ts` throws at import time if `DATABASE_URL` is unset; this test imports production `db.ts` transitively.
- **Last modified in commit**: `5a0e05e test(action-plan): opt-in guard for destructive DB tests` — predates Phase 10.
- **Status**: Not caused by Phase 10 Wave 0 stubs. Phase 10 stubs are `it.todo` only and do not import production `db.ts`. Deferred.
