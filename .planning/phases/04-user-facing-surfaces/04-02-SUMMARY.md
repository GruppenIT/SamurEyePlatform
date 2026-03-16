---
phase: 04-user-facing-surfaces
plan: "02"
subsystem: ui
tags: [react, wouter, tanstack-query, drizzle-orm, typescript, action-plan]

# Dependency graph
requires:
  - phase: 03-remediation-engine
    provides: recommendations table with effortTag, roleRequired, whatIsWrong, fixSteps
  - phase: 02-threat-engine-intelligence
    provides: threats table with contextualScore, projectedScoreAfterFix, parentThreatId, category
provides:
  - GET /api/action-plan endpoint joining recommendations + threats ordered by contextualScore
  - action-plan.tsx page with prioritized remediation cards and filter dropdowns
  - /action-plan route registered in App.tsx
  - Sidebar link "Plano de Acao" in Inteligencia group
affects:
  - future reporting phases that surface prioritized work queues

# Tech tracking
tech-stack:
  added: []
  patterns:
    - useQuery with dynamic queryKey including filter state objects for cache isolation
    - Effort badge coloring via CSS class switch (minutes=green, hours=yellow, days=orange, weeks=red)
    - Score delta display pattern (projectedScoreAfterFix - contextualScore)

key-files:
  created:
    - client/src/pages/action-plan.tsx
  modified:
    - server/routes/dashboard.ts
    - client/src/App.tsx
    - client/src/components/layout/sidebar.tsx

key-decisions:
  - "GET /api/action-plan filters only open parent threats (parentThreatId IS NULL) to avoid duplicate child threat actions"
  - "useQuery queryKey includes filter object so each unique filter combination gets its own cache entry"
  - "fixPreview uses fixSteps[0] — first step gives the most actionable preview without overwhelming the card"

patterns-established:
  - "Filter dropdowns use 'all' sentinel value to distinguish from empty/unset"
  - "Card click navigates to /threats?highlight={threatId} allowing threat detail view to highlight the specific threat"

requirements-completed:
  - UIAP-01
  - UIAP-02
  - UIAP-03
  - UIAP-04

# Metrics
duration: 15min
completed: 2026-03-16
---

# Phase 04 Plan 02: Action Plan Page Summary

**Prioritized remediation work queue at /action-plan with effort/role/journey filters, score-ranked cards, and drill-through to threat detail**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-03-16T23:00:00Z
- **Completed:** 2026-03-16T23:15:00Z
- **Tasks:** 2 of 2 (Task 2 human-verify checkpoint approved)
- **Files modified:** 4

## Accomplishments

- GET /api/action-plan endpoint with Drizzle innerJoin on recommendations + threats, filtered to open parent threats, ordered by contextualScore DESC
- action-plan.tsx page with filter bar (3 Select dropdowns: effort, role, journey type)
- Prioritized action cards showing: threat title, severity badge, contextual score, whatIsWrong, fixPreview (fixSteps[0]), effort badge (color-coded), role badge, projected score delta with ArrowUpRight icon
- Empty state with CheckCircle icon when no actions are pending
- Route /action-plan wired in App.tsx
- "Plano de Acao" sidebar entry with ClipboardList icon between Ameacas and Relatorios in Inteligencia group

## Task Commits

1. **Task 1: Create GET /api/action-plan endpoint and wire action plan page** - `fcaff07` (feat)
   - Note: dashboard.ts endpoint was pre-committed in `d59bf7b` (plan 04-03 ran first); client files committed here

**Plan metadata:** COMPLETE — Task 2 (human-verify checkpoint) approved by user 2026-03-16

## Files Created/Modified

- `server/routes/dashboard.ts` - Added GET /api/action-plan route with Drizzle join and optional filters (pre-committed in d59bf7b)
- `client/src/pages/action-plan.tsx` - New page: filter bar, prioritized action cards, empty state
- `client/src/App.tsx` - Added ActionPlan import and `/action-plan` route
- `client/src/components/layout/sidebar.tsx` - Added ClipboardList import + Plano de Acao nav entry

## Decisions Made

- `parentThreatId IS NULL` filter in the endpoint ensures only standalone/parent threats surface in the action plan, not child sub-threats from grouping
- QueryKey includes the filter state object so TanStack Query treats each filter combination as a separate cache entry
- Score delta formula: `projectedScoreAfterFix - contextualScore` (positive = improvement in posture)

## Deviations from Plan

None — plan executed exactly as written. The action-plan endpoint was already present from plan 04-03 which ran out of sequence; the remaining client-side work was implemented as specified.

## Issues Encountered

- plan 04-03 had already committed the GET /api/action-plan endpoint to dashboard.ts before this plan ran — no conflict, changes were already in place.
- Pre-existing TypeScript errors in sidebar.tsx, useAuth.ts, cveService.ts, jobQueue.ts are out of scope and were not introduced by this plan.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Action plan page fully functional — filters, score-ranked cards, drill-through to threats
- Human visual verification (Task 2 checkpoint) approved — plan fully complete

## Self-Check: PASSED

- FOUND: client/src/pages/action-plan.tsx
- FOUND: client/src/App.tsx (contains action-plan route)
- FOUND: client/src/components/layout/sidebar.tsx (contains Plano de Acao entry)
- FOUND: server/routes/dashboard.ts (contains /api/action-plan endpoint)
- FOUND: .planning/phases/04-user-facing-surfaces/04-02-SUMMARY.md
- FOUND: commit fcaff07

---
*Phase: 04-user-facing-surfaces*
*Completed: 2026-03-16*
