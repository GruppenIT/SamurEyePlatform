---
phase: 12-security-testing-passive
plan: 02
subsystem: api
tags: [nuclei, jwt, api-security, owasp-api-top-10, passive-scanning, drizzle]

# Dependency graph
requires:
  - phase: 12-security-testing-passive/12-01
    provides: Wave 0 Nyquist stubs + schema types (ApiPassiveTestOpts, PassiveTestResult, NucleiFindingSchema)
  - phase: 10-api-credentials
    provides: decodeJwtExp helper for JWT exp claim parsing
  - phase: 11-discovery-enrichment
    provides: apis/apiEndpoints DB rows with specUrl/specHash/apiType/discoverySources/httpxStatus fields
provides:
  - shared/apiRemediationTemplates.ts with 9 pt-BR remediation string variants (api2/api8/api9)
  - server/services/scanners/api/nucleiApi.ts with runNucleiPassive + mapNucleiJsonlToEvidence + buildNucleiArgs
  - server/services/scanners/api/authFailure.ts with 4 JWT/API2 vectors + mask-at-source pattern
  - server/services/scanners/api/api9Inventory.ts with 3 DB-derived API9 signals
affects: [12-03-PLAN, 12-04-PLAN, 14-risk-scoring]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "mask-at-source: API keys/tokens truncated to 3-char prefix + *** at point of capture"
    - "NucleiFinding uses camelCase fields (matchedAt, templateId, matcherName) not kebab-case"
    - "DB mock path from server/__tests__/apiPassive/ → ../../db (not ../../../db)"
    - "vi.hoisted() for mock state to avoid TDZ issues with db module that throws at load time"

key-files:
  created:
    - shared/apiRemediationTemplates.ts
    - server/services/scanners/api/nucleiApi.ts
    - server/services/scanners/api/authFailure.ts
    - server/services/scanners/api/api9Inventory.ts
    - server/__tests__/apiPassive/nucleiArgs.test.ts
    - server/__tests__/apiPassive/jsonlMapper.test.ts
    - server/__tests__/apiPassive/jwtAlgNone.test.ts
    - server/__tests__/apiPassive/kidInjection.test.ts
    - server/__tests__/apiPassive/tokenReuse.test.ts
    - server/__tests__/apiPassive/apiKeyLeakage.test.ts
  modified:
    - server/__tests__/apiPassive/api9Inventory.test.ts (upgraded from stubs to real tests)

key-decisions:
  - "NucleiFinding actual schema uses camelCase (matchedAt, templateId, matcherName, extractedResults) not kebab-case as the plan docs showed — adapted implementation accordingly"
  - "decodeJwtExp returns Date | null (not number | undefined as plan stated) — checkTokenReuse adapted to use .getTime() comparison"
  - "api9Inventory DB mock path from test file is ../../db not ../../../db — path resolution is relative to test file location"
  - "NucleiFinding.info.severity is z.string() (allows info) not enum — severity normalization required explicit validSeverities allowlist"
  - "request/response fields not in NucleiFindingSchema — used type assertion (NucleiFinding & {request?: string; response?: string}) for body truncation"

patterns-established:
  - "Scanner hit interfaces: endpointId + owaspCategory + severity + title + description + remediation + evidence"
  - "authFailure uses probeFn injection for testability (no HTTP coupling in unit tests)"
  - "api9Inventory: 3 independent queries each wrapped in try/catch — aggregate returns partial results on failure"

requirements-completed: [TEST-01, TEST-02]

# Metrics
duration: 13min
completed: 2026-04-20
---

# Phase 12 Plan 02: Wave 1 Scanner Implementation Summary

**4 scanner modules providing Nuclei passive wrapper, 4 JWT/auth-failure vectors with mask-at-source, and 3 DB-derived API9 inventory signals, plus 9 pt-BR remediation templates**

## Performance

- **Duration:** 13 min
- **Started:** 2026-04-20T11:48:35Z
- **Completed:** 2026-04-20T12:01:00Z
- **Tasks:** 4
- **Files modified:** 11 (4 created scanners + 7 test files updated/created)

## Accomplishments

- `shared/apiRemediationTemplates.ts`: 9 pt-BR remediation strings for api2/api8/api9 OWASP categories, typed `as const`
- `server/services/scanners/api/nucleiApi.ts`: Nuclei passive wrapper with `-tags misconfig,exposure,graphql,cors`, stdin batching, JSONL stream parse, severity info→low normalization, graphql→api9/other→api8 routing
- `server/services/scanners/api/authFailure.ts`: 4 JWT/API2 vectors (alg:none forge, kid injection with 4 canonical payloads, token reuse via decodeJwtExp, API key leakage scan) all with mask-at-source (3-char prefix + ***)
- `server/services/scanners/api/api9Inventory.ts`: 3 DB-derived API9 signals using drizzle queries (spec exposure, graphql introspection, exclusive kiterunner endpoints)
- 58 total tests GREEN across all apiPassive test files

## Task Commits

1. **Task 1: shared/apiRemediationTemplates.ts** - `a1d884e` (feat)
2. **Task 2: server/services/scanners/api/nucleiApi.ts** - `3ff41be` (feat, 20 tests)
3. **Task 3: server/services/scanners/api/authFailure.ts** - `248477d` (feat, 27 tests)
4. **Task 4: server/services/scanners/api/api9Inventory.ts** - `f29ab40` (feat, 11 tests)

## Files Created/Modified

- `shared/apiRemediationTemplates.ts` — pt-BR remediation constants for api2/api8/api9 (9 variants, as const)
- `server/services/scanners/api/nucleiApi.ts` — Nuclei passive scanner wrapper (262 lines)
- `server/services/scanners/api/authFailure.ts` — 4 JWT/auth-failure vectors with mask-at-source (267 lines)
- `server/services/scanners/api/api9Inventory.ts` — 3 DB-derived API9 inventory signals (209 lines)
- `server/__tests__/apiPassive/nucleiArgs.test.ts` — 10 tests for buildNucleiArgs
- `server/__tests__/apiPassive/jsonlMapper.test.ts` — 10 tests for mapNucleiJsonlToEvidence
- `server/__tests__/apiPassive/jwtAlgNone.test.ts` — 5 tests for forgeJwtAlgNone
- `server/__tests__/apiPassive/kidInjection.test.ts` — 8 tests for injectKid + KID_INJECTION_PAYLOADS
- `server/__tests__/apiPassive/tokenReuse.test.ts` — 5 tests for checkTokenReuse
- `server/__tests__/apiPassive/apiKeyLeakage.test.ts` — 9 tests for detectApiKeyLeakage + maskApiKey
- `server/__tests__/apiPassive/api9Inventory.test.ts` — 11 tests (upgraded from stubs)

## Decisions Made

- **NucleiFinding camelCase**: Actual schema uses `matchedAt`/`templateId`/`matcherName`/`extractedResults` (camelCase) not kebab-case as plan docs indicated. Adapted implementation.
- **decodeJwtExp returns Date | null**: Phase 10 helper returns `Date | null`, not `number | undefined`. `checkTokenReuse` adapted to use `expDate.getTime()` comparison.
- **DB mock path**: From `server/__tests__/apiPassive/`, the correct mock path is `../../db` (not `../../../db`) since the file is 2 levels from `server/`.
- **request/response fields**: Not in NucleiFindingSchema (schema uses camelCase and omits raw HTTP). Used `(finding as NucleiFinding & {request?: string; response?: string})` type assertion for body truncation.
- **NucleiFinding.info.severity is z.string()**: Allows 'info' which is outside threat_severity_enum. Added explicit allowlist-based normalization.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] NucleiFinding schema uses camelCase, not kebab-case**
- **Found during:** Task 2 (nucleiApi.ts TypeScript check)
- **Issue:** Plan code examples used `finding['matched-at']`, `finding['template-id']`, etc. Actual type has `finding.matchedAt`, `finding.templateId`, `finding.matcherName`, `finding.extractedResults`
- **Fix:** Updated all field accesses to camelCase; added type assertion for raw request/response fields not in schema
- **Files modified:** server/services/scanners/api/nucleiApi.ts
- **Verification:** `npx tsc --noEmit` clean; 20 tests GREEN

**2. [Rule 1 - Bug] decodeJwtExp returns Date | null, not number | undefined**
- **Found during:** Task 3 (authFailure.ts implementation)
- **Issue:** Plan interface showed `decodeJwtExp(jwt): number | undefined`; actual Phase 10 implementation returns `Date | null`
- **Fix:** `checkTokenReuse` uses `decodeJwtExp()` null check + `.getTime() > Date.now()` comparison; skip reasons remain identical
- **Files modified:** server/services/scanners/api/authFailure.ts
- **Verification:** 5 tokenReuse tests GREEN including expired/not-expired/opaque scenarios

---

**Total deviations:** 2 auto-fixed (both Rule 1 — bugs in plan's type documentation)
**Impact on plan:** Fixes essential for TypeScript correctness. Behavior identical to plan intent.

## Issues Encountered

None beyond the auto-fixed deviations above.

## Next Phase Readiness

- Wave 1 scanners fully built and tested: `runNucleiPassive`, `checkTokenReuse`, `detectApiKeyLeakage`, `runApi9Inventory` ready for Wave 2 orchestrator
- Wave 2 (12-03): orchestrator journey `apiPassiveTests.ts` + dedupe upsert storage
- Wave 3 (12-04): route + CLI + documentation
- Pre-existing 27 `it.todo` stubs for orchestrator/route/dedupe remain as Wave 2/3 targets

---
*Phase: 12-security-testing-passive*
*Completed: 2026-04-20*
