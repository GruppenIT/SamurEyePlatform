---
phase: 11-discovery-enrichment
plan: 06
subsystem: api-discovery
tags: [vitest, typescript, orchestrator, tdd, abort-signal, drift-detection, oauth2, httpx, arjun, katana, kiterunner, openapi, graphql]

# Dependency graph
requires:
  - phase: 11-01
    provides: Nyquist stubs (orchestrator.test.ts + drift.test.ts), httpx_* columns on apiEndpoints, fixtures
  - phase: 11-02
    provides: preflightApiBinary(), storage extensions (upsertApiEndpoints/mergeHttpxEnrichment/appendQueryParams/markEndpointsStale/updateApiSpecMetadata)
  - phase: 11-03
    provides: fetchAndParseSpec + specToEndpoints + probeGraphQL + schemaToEndpoints
  - phase: 11-04
    provides: runKatana (KatanaCredential auth matrix) + runKiterunner
  - phase: 11-05
    provides: runHttpx (tri-valor requiresAuth) + mapRequiresAuth + runArjun (dict-keyed Zod validation)

provides:
  - "discoverApi(apiId, opts, jobId?): Promise<DiscoveryResult> — end-to-end API discovery orchestrator (~310 lines)"
  - "DiscoveryResult interface — public contract consumed by Plan 11-07 route + CLI, then Phase 15/16"
  - "Stage state machine: spec → crawler → kiterunner → httpx (2-pass) → arjun, each independent catch+skip"
  - "Drift detection: log.warn({apiId,oldHash,newHash},'spec drift detected') + specFetched.driftDetected (DISC-06)"
  - "httpx 2-pass: unauth probe fills requiresAuth; compatible creds trigger 2nd auth probe"
  - "Arjun validation: arjunEndpointIds all exist + apiId match + method=GET (fail-fast)"
  - "dryRun=true forces crawler/kiterunner/arjun off (spec + httpx only)"
  - "AbortSignal cancellation: pipeline stops at stage boundary; already-upserted endpoints persist"
  - "Stale endpoint detection: diff listEndpointsByApi vs run-start timestamp → markEndpointsStale"
  - "OAuth2 in-memory token cache per-process (expires_in - 30s buffer per Phase 10 CONTEXT.md)"
  - "11 tests GREEN: orchestrator.test.ts (7) + drift.test.ts (4)"

affects: [11-07-PLAN]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Stage state machine with independent try/catch per stage — log.error + stagesSkipped + continue (never abort pipeline on stage failure)"
    - "dryRun override pattern: effectiveStages computed at start, all scanner calls use effectiveStages"
    - "httpx 2-pass grouping by authHeader: Map<string, string[]> groups endpoints with same cred"
    - "OAuth2 mint cache: Map<credId, {token,expiresAt}> scoped to process — never persisted"
    - "Stale endpoint detection via updatedAt < runStart heuristic (lastSeenAt column deferred)"
    - "finalize() closure captures startedAt + all stage results — single return path for all scenarios including cancel"
    - "KatanaCredential built from ApiCredentialWithSecret — switch on authType covers all 7 Phase 10 auth types"

key-files:
  created:
    - server/services/journeys/apiDiscovery.ts
  modified:
    - server/__tests__/apiDiscovery/orchestrator.test.ts
    - server/__tests__/apiDiscovery/drift.test.ts

key-decisions:
  - "httpx stage runs even with 0 endpoints (urls=[]): runHttpx([]) returns {results:[]} without preflight skip, so stagesRun includes 'httpx' to signal stage was active"
  - "resolveCompatibleAuthHeader uses getApiCredential(credIdOverride) when override present — avoids URL pattern matching for explicit creds"
  - "KatanaCredential from buildKatanaCredential covers all 7 auth types including hmac (signals skip inside katana.ts) and mtls (tempfile path inside katana.ts)"
  - "Stale detection uses updatedAt < runStart — approximate but correct for Phase 11; lastSeenAt column deferred to Phase 12+"
  - "finalize() as inner closure captures all mutable state by reference — clean single exit path"

requirements-completed: [DISC-01, DISC-02, DISC-03, DISC-04, DISC-05, DISC-06, ENRH-01, ENRH-02, ENRH-03]

# Metrics
duration: 6min
completed: 2026-04-20
---

# Phase 11 Plan 06: API Discovery Orchestrator Summary

**discoverApi() state machine (spec → crawler → kiterunner → httpx 2-pass → arjun) with drift detection (DISC-06), dryRun, cancellation, stale endpoints, OAuth2 cache, and 11 tests GREEN (orchestrator.test.ts 7 + drift.test.ts 4)**

## Performance

- **Duration:** ~6 min
- **Started:** 2026-04-20T01:09:03Z
- **Completed:** 2026-04-20T01:14:00Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- `server/services/journeys/apiDiscovery.ts` (527 lines) — `discoverApi(apiId, opts, jobId?)` sequential stage state machine; each stage wrapped in independent try/catch; `DiscoveryResult` interface with all 9 fields per CONTEXT.md
- Drift detection: `log.warn({apiId, oldHash, newHash}, 'spec drift detected')` + `specFetched.driftDetected=true`; pipeline continues (no abort)
- httpx 2-pass: pass 1 unauth → fills requiresAuth; pass 2 groups endpoints by authHeader → re-probes auth-required endpoints with compatible creds
- Arjun validation: all `arjunEndpointIds` must exist in `listEndpointsByApi`, belong to `apiId`, have `method=GET` — fail-fast with descriptive error
- dryRun=true: forces `effectiveStages.crawler/kiterunner/arjun = false` at orchestrator entry regardless of opts
- AbortSignal: checks `signal.aborted` at each stage boundary; `cancelled=true` propagated to result; already-upserted endpoints not rolled back
- Stale detection: `listEndpointsByApi → filter updatedAt < runStart → markEndpointsStale`; IDs returned in `endpointsStale`
- OAuth2 in-memory cache: `Map<credId, {token,expiresAt}>` per-process; `expires_in - 30s` buffer per Phase 10 decision
- `orchestrator.test.ts`: 7 it.todo → 7 real tests covering all 7 orchestrator behaviors
- `drift.test.ts`: 4 it.todo → 4 real tests covering all 4 DISC-06 drift scenarios
- Full suite: 575 tests passing (11 new from this plan; pre-existing actionPlanService DATABASE_URL failure unchanged)

## Task Commits

1. **Task 1: Create apiDiscovery.ts orchestrator + 7 orchestrator tests** — `76afc55` (feat)
2. **Task 2: Convert drift.test.ts to 4 real tests (DISC-06)** — `d9fa32b` (feat)

## Decisions Made

- httpx stage always "ran" even with 0 endpoints — `runHttpx([])` returns `{results:[]}` (no skipped), so stagesRun includes `'httpx'` to signal stage was active (not skipped by configuration)
- `resolveCompatibleAuthHeader` delegates to `getApiCredential(credIdOverride)` when override present — avoids URL pattern matching for explicitly specified cred IDs
- `finalize()` as inner closure captures state by reference — single exit path for all cancel/normal paths

## Deviations from Plan

None — plan executed exactly as written. The code template in the `<action>` block was used as the structural blueprint with adjustments for the URL=0 edge case discovered during test iteration.

### Auto-fixed Issues

**1. [Rule 1 - Bug] httpx skipped when 0 endpoints instead of stagesRun**
- **Found during:** Task 1 (orchestrator tests)
- **Issue:** Initial implementation had `if (urls.length === 0) stagesSkipped.push(...)` — tests expected httpx in stagesRun even with 0 URLs
- **Fix:** Removed early-exit on empty URLs; `runHttpx([])` called always when httpx stage enabled; mock returns `{results:[]}` which triggers `stagesRun.push('httpx')`
- **Files modified:** server/services/journeys/apiDiscovery.ts
- **Verification:** 7 orchestrator tests GREEN including "dryRun=true skips crawler/kiterunner/arjun" and "skips stage + logs error + continues pipeline"
- **Committed in:** 76afc55

---

**Total deviations:** 1 auto-fixed (Rule 1 bug)
**Impact on plan:** Essential for correct httpx stage reporting. No scope creep.

## Issues Encountered

None.

## User Setup Required

None.

## Next Phase Readiness

- Plan 11-07 (route + CLI) can call `discoverApi(apiId, opts, jobId?)` directly — full pipeline end-to-end
- `DiscoveryResult` interface exported for route handler to return as JSON response body
- All 9 phase requirements (DISC-01..06, ENRH-01..03) have end-to-end pipeline coverage via orchestrator
- Developer can manually invoke `discoverApi` from a REPL and see endpoints materialize in `api_endpoints` with httpx enrichment and Arjun params

## Self-Check: PASSED

- server/services/journeys/apiDiscovery.ts — FOUND (527 lines, > 250 minimum)
- server/__tests__/apiDiscovery/orchestrator.test.ts — FOUND (0 it.todo, 7 real tests)
- server/__tests__/apiDiscovery/drift.test.ts — FOUND (0 it.todo, 4 real tests)
- Commit 76afc55 (Task 1) — FOUND
- Commit d9fa32b (Task 2) — FOUND
- `grep "export async function discoverApi" apiDiscovery.ts` — FOUND
- `grep "export interface DiscoveryResult" apiDiscovery.ts` — FOUND
- `grep "spec drift detected" apiDiscovery.ts` — FOUND
- `grep "method !== 'GET'" apiDiscovery.ts` — FOUND
- `grep "pertence a apiId diferente" apiDiscovery.ts` — FOUND

---
*Phase: 11-discovery-enrichment*
*Completed: 2026-04-20*
