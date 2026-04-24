---
phase: 15-journey-orchestration-safety
plan: "04"
subsystem: journey-executor
tags:
  - journey
  - api-security
  - executor
  - abort-route
  - audit-log
  - safe-03
  - safe-04
  - safe-06
  - jrny-01
  - jrny-02
  - jrny-03
  - jrny-05
dependency_graph:
  requires:
    - 15-02  # schema: authorizationAck column + journeyTypeEnum 'api_security'
    - 15-03  # rateLimiter: TokenBucketRateLimiter + MAX_API_RATE_LIMIT
    - 11-*   # discoverApi
    - 12-*   # runApiPassiveTests
    - 13-*   # runApiActiveTests
  provides:
    - executeApiSecurity() method in JourneyExecutorService
    - POST /api/v1/jobs/:id/abort route
  affects:
    - server/services/journeyExecutor.ts
    - server/routes/jobs.ts
tech_stack:
  added: []
  patterns:
    - TDD Red-Green (tests written before implementation)
    - Guard-first pattern (authorizationAck before any scan)
    - Audit log pair (start + complete/failed)
    - Destructive gate (SAFE-03 force-false unless explicit true)
    - Cooperative cancellation (isJobCancelled between stages)
key_files:
  created: []
  modified:
    - server/services/journeyExecutor.ts
    - server/routes/jobs.ts
    - server/__tests__/journeyOrchestration.test.ts
    - server/__tests__/abortRoute.test.ts
decisions:
  - "executeApiSecurity does NOT call threatEngine.processJobResults — already called by executeJourney wrapper after switch returns"
  - "TokenBucketRateLimiter instantiated in executeApiSecurity but not yet passed to sub-orchestrators — Phase 11/12/13 have their own rateLimit opts fields; global ceiling via MAX_API_RATE_LIMIT"
  - "beforeEach mockReset for runApiActiveTests.mock.calls needed in SAFE-03 describe block — vitest module cache retains mock call history across tests in the same file"
  - "abortRoute test mocks '../routes/middleware' (not './middleware') — from test file perspective the path is relative to __tests__/"
  - "Pre-existing TS2769 errors in journeyExecutor.ts (lines 249-1579) are pre-existing log.error calls — new code at line 1612+ introduces zero new TS errors"
metrics:
  duration_seconds: 298
  completed_date: "2026-04-20"
  tasks_completed: 2
  files_modified: 4
  tests_added: 22
  tests_total_phase15: 43
---

# Phase 15 Plan 04: Journey Executor Wire-up + Abort Route Summary

Wire final de tudo — executeApiSecurity() orchestrating Phase 11/12/13 outputs with authorizationAck guard, SAFE-03 destructive gate, SAFE-04 audit log start/complete/failed, SAFE-06 log discipline; plus POST /api/v1/jobs/:id/abort route with cooperative cancel + killAll + audit(action='abort').

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | executeApiSecurity() + switch case 'api_security' (JRNY-01/02/03, SAFE-03/04/06) | 07fa03a | server/services/journeyExecutor.ts, server/__tests__/journeyOrchestration.test.ts |
| 2 | POST /api/v1/jobs/:id/abort route (JRNY-05) | a0e9342 | server/routes/jobs.ts, server/__tests__/abortRoute.test.ts |

## Switch Statement Diff

Before:
```typescript
      case 'web_application':
        await this.executeWebApplication(journey, jobId, onProgress);
        break;
      default:
        throw new Error(`Tipo de jornada não suportado: ${journey.type}`);
```

After:
```typescript
      case 'web_application':
        await this.executeWebApplication(journey, jobId, onProgress);
        break;
      case 'api_security':
        // Phase 15 JRNY-01 — wire api_security journey type
        await this.executeApiSecurity(journey, jobId, onProgress);
        break;
      default:
        throw new Error(`Tipo de jornada não suportado: ${journey.type}`);
```

## executeApiSecurity() Method (new, ~150 lines)

Key structure:
1. JRNY-02 guard: `if (journey.authorizationAck !== true) throw new Error('Jornada api_security requer acknowledgment...')`
2. SAFE-04 audit start: `logAudit({ action: 'start', objectType: 'api_security_journey', after: { apiId, targets, credentialIds (UUIDs only), authorizationAck, stages, dryRun } })`
3. TokenBucketRateLimiter instantiation
4. Stage 1: `discoverApi(apiId, discoveryOpts, jobId)` → progress 20%
5. Stage 2: `runApiPassiveTests(apiId, passiveOpts, jobId)` → progress 50%
6. SAFE-03 gate: `activeOpts.destructiveEnabled = rawActiveOpts.destructiveEnabled === true`
7. Stage 3: `runApiActiveTests(apiId, activeOpts, jobId)` → progress 75%
8. Progress 90% + SAFE-04 audit complete: `logAudit({ action: 'complete', after: { outcome, findingsCount, durationMs } })`
9. Catch: `logAudit({ action: 'failed', ... })` + re-throw

## Abort Route Diff (new handler, ~70 lines)

New route: `app.post('/api/v1/jobs/:id/abort', isAuthenticatedWithPasswordCheck, requireOperator, ...)`

Flow: getJob(404) → validate status='running'(400) → markJobAsCancelled → killAll → updateJob(status:'failed') → emit jobUpdate → logAudit(action:'abort') → res.json({ message: 'Jornada abortada', killedProcesses })

Original `POST /api/jobs/:id/cancel-process` preserved unchanged.

## Test Results

### Phase 15 Full Suite: 43 tests passed (4 files)

| File | Tests | Requirements |
|------|-------|--------------|
| journeyOrchestration.test.ts | 15 passed | JRNY-01, JRNY-02, JRNY-03, SAFE-03, SAFE-04, SAFE-06 |
| rateLimiter.test.ts | 12 passed | SAFE-01, SAFE-02 |
| abortRoute.test.ts | 9 passed | JRNY-05 |
| healthzTarget.test.ts | 7 passed | infrastructure |

## Requirements Coverage

| Requirement | Description | Status |
|-------------|-------------|--------|
| JRNY-01 | api_security in journey_type enum + switch routing | Satisfied (Plan 02 + 04) |
| JRNY-02 | authorizationAck guard before scan | Satisfied (Plan 02 schema + Plan 04 executor) |
| JRNY-03 | discoveryOpts/passiveOpts/activeOpts flow to sub-orchestrators | Satisfied (Plan 04) |
| JRNY-04 | Scheduler accepts api_security (via enum extension) | Satisfied implicitly (Plan 02 enum) |
| JRNY-05 | POST /api/v1/jobs/:id/abort route | Satisfied (Plan 04) |
| SAFE-01 | MAX_API_RATE_LIMIT=50 ceiling | Satisfied (Plan 03 rateLimiter) |
| SAFE-02 | Retry-After + exponential backoff | Satisfied (Plan 03 rateLimiter) |
| SAFE-03 | Destructive gate before active tests | Satisfied (Plan 04) |
| SAFE-04 | Audit log start/complete/failed | Satisfied (Plan 04) |
| SAFE-05 | healthz probe for test target reachability | Satisfied (Plan 03 healthzTarget) |
| SAFE-06 | No secrets/credentials in logs | Satisfied (Plan 04 — static analysis test) |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] mockReset needed in SAFE-03 beforeEach for runApiActiveTests**
- **Found during:** Task 1 GREEN phase (1 test failing after 14 passing)
- **Issue:** Test "quando opts.destructiveEnabled=true" was picking up the first call from a prior test because vitest module cache shares mock state across describe blocks. `.mock.calls.find(c => c[0] === 'api-1')` returned the first-ever call (destructiveEnabled=false from JRNY-03 tests)
- **Fix:** Added `mocks.runApiActiveTests.mockReset()` in SAFE-03 `beforeEach()` 
- **Files modified:** server/__tests__/journeyOrchestration.test.ts
- **Commit:** 07fa03a

**2. [Rule 1 - Bug] abortRoute test mock path correction**
- **Found during:** Task 2 RED phase
- **Issue:** Mock path `'./middleware'` in test file was wrong — from `server/__tests__/` the path to `server/routes/middleware.ts` is `'../routes/middleware'`; also missing `'../db'` mock causing DATABASE_URL error
- **Fix:** Changed mock path to `'../routes/middleware'`; added `vi.mock('../db', () => ({ db: {} }))`
- **Files modified:** server/__tests__/abortRoute.test.ts
- **Commit:** a0e9342

### Pre-existing Issues (Out of Scope)

- TS2769 errors in server/services/journeyExecutor.ts lines 249-1579: pre-existing `log.error()` type errors from before this plan's changes. Not introduced by Plan 04. Deferred per scope boundary rule.

## Self-Check

All files verified on disk and commits exist.
