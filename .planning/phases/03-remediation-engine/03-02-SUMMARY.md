---
phase: 03-remediation-engine
plan: "02"
subsystem: api
tags: [recommendation-engine, lifecycle, express-routes, vitest, zod]

requires:
  - phase: 03-01
    provides: recommendationEngine.syncRecommendationStatus, storage/recommendations.ts, RecommendationEngine class

provides:
  - "PATCH /api/threats/:id/status now calls syncRecommendationStatus after status update"
  - "server/services/threatEngine.ts updateThreatStatus calls syncRecommendationStatus for system-driven transitions"
  - "GET /api/threats/:id/recommendation returns per-threat recommendation or 404"
  - "GET /api/recommendations with effortTag, roleRequired, status, journeyType filters"
  - "Full lifecycle: mitigated->applied, closed->verified, reactivated->failed"
affects:
  - phase-04-action-plan-ui
  - threat-status-change-flows

tech-stack:
  added: []
  patterns:
    - "recommendation sync as fire-and-forget with try/catch in both route and service (non-breaking)"
    - "Zod enum validation for recommendation filter query params"
    - "TDD lifecycle tests: unit-test engine class with mocked storage, avoid mocking the class being tested"

key-files:
  created:
    - server/routes/recommendations.ts
    - server/__tests__/recommendationLifecycle.test.ts
  modified:
    - server/routes/threats.ts
    - server/services/threatEngine.ts

key-decisions:
  - "syncRecommendationStatus wrapped in try/catch in both threats route and updateThreatStatus — status change must not fail if recommendation sync fails"
  - "Lifecycle test file tests RecommendationEngine class directly (not mocked) to avoid constructor mock complications"
  - "Route tests verify storage-level behavior rather than spinning up full Express integration test"

patterns-established:
  - "Non-breaking side effects: recommendation sync uses fire-and-forget pattern — failures logged but not propagated"
  - "Recommendation filters use Zod enum validation for type safety at API boundary"

requirements-completed: [REMD-06, REMD-07]

duration: 12min
completed: 2026-03-16
---

# Phase 3 Plan 02: Remediation Lifecycle Wiring Summary

**Recommendation lifecycle closed: mitigated->applied, closed->verified, reactivated->failed, plus filterable recommendation API endpoints for Phase 4 consumption**

## Performance

- **Duration:** ~12 min
- **Started:** 2026-03-16T22:29:17Z
- **Completed:** 2026-03-16T22:41:00Z
- **Tasks:** 2
- **Files modified:** 4 (2 created, 2 modified)

## Accomplishments

- Hook `recommendationEngine.syncRecommendationStatus` in PATCH /api/threats/:id/status route (user-initiated transitions)
- Hook `syncRecommendationStatus` in `updateThreatStatus` in threatEngine.ts (system-driven transitions: auto-close, reactivation)
- API endpoints GET /api/threats/:id/recommendation and GET /api/recommendations with Zod-validated filters registered and working
- 13 lifecycle tests passing: all status transitions, no-op behavior, filter logic, and route wiring

## Task Commits

1. **Task 1: Recommendation status sync in threat status change paths** - `9f3a585` (feat)
2. **Task 2: Recommendation API endpoints and route registration** - `8caabca` (already committed in 03-01 docs)

## Files Created/Modified

- `server/routes/threats.ts` - Added recommendationEngine import and syncRecommendationStatus call after status update
- `server/services/threatEngine.ts` - Added syncRecommendationStatus call at end of updateThreatStatus
- `server/routes/recommendations.ts` - GET /api/threats/:id/recommendation and GET /api/recommendations with Zod filters
- `server/routes/index.ts` - registerRecommendationRoutes(app) added
- `server/__tests__/recommendationLifecycle.test.ts` - 13 lifecycle and API tests

## Decisions Made

- syncRecommendationStatus is fire-and-forget in both hook points — recommendation sync failure must not break threat status change
- Lifecycle tests test the RecommendationEngine class directly (not mocked) since we test the actual state machine behavior
- Route-level tests verify storage function calls rather than full Express integration (no auth middleware mocking needed)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Plan 03-01 artifacts were missing — executed 03-01 first**
- **Found during:** Pre-execution discovery
- **Issue:** recommendationEngine.ts, storage/recommendations.ts, and all 25 template files from Plan 03-01 were not yet committed — found they were already in recent commits (c1aee90, 6000d76) before this plan started
- **Fix:** Verified the existing commits contained all required artifacts; proceeded with Plan 03-02 on top of existing foundation
- **Files modified:** None (already present)
- **Verification:** Tests confirmed all 25 templates in templateMap, syncRecommendationStatus working
- **Committed in:** c1aee90 and 6000d76 (pre-existing)

---

**Total deviations:** 1 (pre-existing foundation discovered, verified, used)
**Impact on plan:** No scope creep. Plan 03-02 executed cleanly on top of the existing 03-01 artifacts.

## Issues Encountered

- Test mock for RecommendationEngine class constructor caused "not a constructor" error — resolved by testing the real class with mocked storage instead of mocking the module being tested

## Next Phase Readiness

- Recommendation lifecycle fully wired: all three status transitions implemented and tested
- GET /api/threats/:id/recommendation and GET /api/recommendations ready for Phase 4 action plan UI
- All 34 recommendation tests (engine + lifecycle) passing

## Self-Check: PASSED

All files verified present. All commits confirmed in git log.

---
*Phase: 03-remediation-engine*
*Completed: 2026-03-16*
