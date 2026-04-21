---
phase: 13-security-testing-active
plan: 03
subsystem: api
tags: [security, owasp, bola, bfla, bopla, rate-limit, ssrf, nuclei, typescript, orchestrator]

# Dependency graph
requires:
  - phase: 13-security-testing-active/13-01
    provides: ApiActiveTestOpts, ActiveTestResult, BOPLA_SENSITIVE_KEYS in shared/schema.ts; fixtures in server/__tests__/fixtures/api-active/
  - phase: 13-security-testing-active/13-02
    provides: 5 scanners (bola.ts, bfla.ts, bopla.ts, rateLimit.ts, ssrfNuclei.ts) with actual interfaces
  - phase: 12-security-testing-passive
    provides: upsertApiFindingByKey dedupe transaction; apiPassiveTests.ts orchestrator pattern
  - phase: 10-api-credentials
    provides: listApiCredentials, getApiCredentialWithSecret, encryptionService.decryptCredential
  - phase: 11-discovery-enrichment
    provides: jobQueue.isJobCancelled cooperative cancellation pattern; storage.getApi, listEndpointsByApi
provides:
  - "runApiActiveTests(apiId, opts, jobId?): Promise<ActiveTestResult> — 5-stage active testing pipeline"
  - "server/services/journeys/apiActiveTests.ts — Wave 2 orchestrator for Phase 13"
affects: [13-04, 13-security-testing-active, phase-15-journey-executor, phase-16-ui]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "5-scanner compose pattern: bola → bfla → bopla → rate_limit → ssrf with independent failure isolation"
    - "Credential resolution at orchestrator entry: listApiCredentials + getApiCredentialWithSecret + decryptCredential"
    - "pairCredentials returns {id}-only typed pairs; orchestrator resolves full CredWithSecret by id after pairings"
    - "BFLA identifyLowPrivCreds returns BflaCredentialSignal (no secret); orchestrator resolves full cred before buildAuthHeaders"
    - "dryRun: each stage reads its own fixture file and builds synthetic hits inline (not delegating to scanner dryRun param)"

key-files:
  created:
    - server/services/journeys/apiActiveTests.ts
  modified: []

key-decisions:
  - "pairCredentials generic type {id} requires orchestrator to re-resolve full CredWithSecret from credsWithSecrets array after pairing — plan template assumed full objects were carried through pairs"
  - "identifyLowPrivCreds returns BflaCredentialSignal (has signal field, no secret) — orchestrator resolves full cred via .find() before calling buildAuthHeaders"
  - "Actual bola.ts testCrossAccess signature differs from plan template: takes {endpointId, endpointPath, objectId, credentialAId, credentialBId, credentialBHeaders, credentialBQueryParam?} — no dryRunFixturePath in scanner; dryRun handled inline in orchestrator"
  - "Actual bopla.ts fetchSeedBody signature: fetchSeedBody(resourceUrl, authHeaders) — plan template had {endpoint, baseUrl, credential} object; orchestrator constructs resourceUrl + extracts headers before calling"
  - "Actual rateLimit.ts detectThrottling signature: detectThrottling({endpointId, endpointPath, endpointUrl, responses, burstSize, windowMs}) returns RateLimitHit | null — plan template showed boolean return"
  - "ssrfNuclei.ts runSsrfNuclei expects targetUrls as Array<{url, endpointId, paramName}> and identifyUrlParams takes SsrfParam[] flat array — orchestrator maps endpoints to flat SsrfParam list before calling"
  - "SSRF dryRun handled inline in orchestrator (reads JSONL fixture, builds SsrfHit directly) rather than delegating to scanner; scanner dryRunFixturePath interface from plan was not implemented in Wave 1"

patterns-established:
  - "Pattern: Orchestrator resolves credential pairs by id lookup — pairCredentials is generic, callers must retain full object arrays"
  - "Pattern: dryRun fixture loading is orchestrator responsibility for all stages except Phase 12 nuclei_passive (which has loadNucleiFixtureHits helper)"
  - "Pattern: buildAuthHeaders(cred) throws for unsupported auth types (hmac/oauth2/mtls); orchestrator catches and skips pair/stage"

requirements-completed:
  - TEST-03
  - TEST-04
  - TEST-05
  - TEST-06
  - TEST-07

# Metrics
duration: 4min
completed: 2026-04-20
---

# Phase 13 Plan 03: API Active Tests Orchestrator Summary

**`runApiActiveTests` orchestrator composing 5 stateful OWASP scanners (BOLA/BFLA/BOPLA/RateLimit/SSRF) into a sequential pipeline with cooperative cancellation, dryRun fixtures, and destructive gate enforcement**

## Performance

- **Duration:** 4 min
- **Started:** 2026-04-20T17:01:22Z
- **Completed:** 2026-04-20T17:05:34Z
- **Tasks:** 1
- **Files modified:** 1 (created)

## Accomplishments

- Created `server/services/journeys/apiActiveTests.ts` (844 lines) exporting `runApiActiveTests`
- 5 stages in fixed order: bola → bfla → bopla → rate_limit → ssrf; each fails independently
- BOPLA gate enforced: stage always skips unless `opts.destructiveEnabled=true`
- rateLimit gate enforced: stage always skips unless `opts.stages.rateLimit=true` (explicit opt-in)
- Cooperative cancellation via `jobQueue.isJobCancelled` between every stage and inside BOLA pair loop
- dryRun reads fixtures from `server/__tests__/fixtures/api-active/`, prefixes titles with `[DRY-RUN]`
- SSRF stage calls `preflightNuclei` before spawn; pipeline continues on preflight failure (stage skipped)
- `credentialsUsed` count tracks distinct credentials that participated across all stages
- All findings persisted via `storage.upsertApiFindingByKey` with created/updated aggregation
- SAFE-06: credential IDs masked as prefix-3+`***` in all log entries; secrets never logged

## Task Commits

1. **Task 1: runApiActiveTests orchestrator** - `b92d542` (feat)

## Files Created/Modified

- `server/services/journeys/apiActiveTests.ts` - Wave 2 orchestrator; composes 5 Wave 1 scanners; exports `runApiActiveTests`

## Decisions Made

- **Scanner interface adaptation:** The plan's template interfaces (from plan frontmatter) did not match the actual Wave 1 scanner signatures. Key differences resolved:
  - `pairCredentials` returns generic `{id}` pairs — orchestrator re-resolves full `CredWithSecret` by id lookup after pairing
  - `identifyLowPrivCreds` returns `BflaCredentialSignal[]` (has `signal` field, no `secret`) — full cred resolved before `buildAuthHeaders`
  - `testCrossAccess` takes flat params (endpointId, objectId, credentialBHeaders) not nested objects
  - `fetchSeedBody(resourceUrl, authHeaders)` flat signature vs plan template's object form
  - `detectThrottling` returns `RateLimitHit | null` (not boolean) — no separate `buildRateLimitHit` needed
  - `identifyUrlParams` takes flat `SsrfParam[]`, not `{query_params, request_params, request_schema}` object

- **dryRun inline handling:** Wave 1 scanners do not accept `dryRun`/`dryRunFixturePath` params (plan template showed these). dryRun logic is handled inline in the orchestrator for each stage, reading fixtures directly.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Scanner interface mismatch between plan template and actual Wave 1 implementations**
- **Found during:** Task 1 (writing orchestrator)
- **Issue:** Plan's `<interfaces>` block showed scanner signatures as designed (e.g., `testCrossAccess(params: {endpoint, baseUrl, credentialA, credentialB, harvestedIds, dryRun})`) but the actual Wave 1 implementations had different signatures that don't carry full credential objects or dryRun flags
- **Fix:** Used actual Wave 1 scanner signatures throughout; implemented dryRun logic inline in orchestrator for each stage; added id-based lookup to resolve full credentials after `pairCredentials` and `identifyLowPrivCreds`
- **Files modified:** server/services/journeys/apiActiveTests.ts
- **Verification:** `npx tsc --noEmit` — zero new errors in apiActiveTests.ts; all 157 prior tests still pass
- **Committed in:** b92d542 (task commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — interface mismatch corrected without user input)
**Impact on plan:** Necessary correctness fix. All scanner calls use actual exported function signatures. No scope creep.

## Issues Encountered

None — TypeScript type checker caught all interface mismatches on first pass; 3 type errors fixed before commit.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `runApiActiveTests` ready for Wave 3 (route + CLI) consumption: `import { runApiActiveTests } from '.../journeys/apiActiveTests'`
- Wave 3 (13-04): add `POST /api/v1/apis/:id/test/active` route + `server/scripts/runApiActiveTests.ts` CLI + runbook
- Phase 15 journey executor can wire `runApiActiveTests` as a journey leg after Wave 3 is complete
- 15 orchestrator test stubs in `server/__tests__/apiActive/orchestrator.test.ts` await real implementation in Wave 3

---
*Phase: 13-security-testing-active*
*Completed: 2026-04-20*
